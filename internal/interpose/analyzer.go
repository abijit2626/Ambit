package interpose

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/abijit2626/ambit/internal/baseline"
	"github.com/abijit2626/ambit/internal/mcp"
	"github.com/abijit2626/ambit/internal/toolscan"
)

// Direction says which way a frame was travelling.
type Direction int

const (
	// FromClient is agent to server: requests and notifications.
	FromClient Direction = iota
	// FromServer is server to agent: responses and notifications. This is the
	// untrusted direction, and the one D4 and D5 read.
	FromServer
)

// queueDepth bounds the analysis backlog. Frames beyond it are dropped and
// counted: the relay must never block, and a backlog this deep already means the
// analyzer cannot keep up, at which point dropping visibly beats stalling a
// developer's tool call.
const queueDepth = 256

// reportQueueDepth bounds undelivered reports. Reports are rare — one per listing
// — so a backlog here means ambitd is wedged or gone, which the shutdown report
// and D7 both surface.
const reportQueueDepth = 32

// pendingCap bounds tracked request ids. A client with this many outstanding
// tools/list requests is pathological; the cap keeps a hostile or buggy peer from
// growing this map without limit.
const pendingCap = 64

// Sender delivers reports. The interposer takes it as an interface so a test can
// assert on what would have been sent without a listener, and so a broken
// transport is visibly a transport problem rather than an analysis one.
type Sender interface {
	Send(ctx context.Context, rep *Report) error
}

// Options configure an Analyzer.
type Options struct {
	// Server is the logical name from .mcp.json. Required: without it the report
	// cannot reconstruct mcp__<server>__<tool>, which is the identity everything
	// downstream keys on.
	Server string
	// Siblings are other configured server names, used only for D5's cross-server
	// reference rule.
	Siblings []string
	// Store may be nil, which is the degraded mode: D5 still runs, D4 cannot, and
	// every report says so rather than implying a clean comparison.
	Store *baseline.Store
	// StoreErr explains a nil Store.
	StoreErr error
	Sender   Sender
	Logger   *slog.Logger
	Version  string
	// SessionID is best-effort; see Report.SessionID.
	SessionID string
	// Now is injected for tests.
	Now func() time.Time
}

// Analyzer watches frames and produces reports.
//
// All state lives on a single worker goroutine, so there are no locks on the
// analysis path and the causal order of the stream is preserved: a request is
// always enqueued before the response it provokes.
type Analyzer struct {
	opts    Options
	scanner *toolscan.Scanner
	log     *slog.Logger
	now     func() time.Time

	frames    chan queued
	reports   chan *Report
	done      chan struct{}
	delivered chan struct{}
	closeOnce sync.Once

	// pending maps a request id to the method it asked for, so a response can be
	// recognized. MCP responses carry no method name.
	pending map[string]string
	// accumulated collects tools across the pages of a paginated tools/list.
	accumulated []mcp.Tool
	// paging is true while a cursor is outstanding.
	paging bool
	// listChanged records that the server announced a change, so the listing that
	// follows is tagged as a re-list rather than a routine one.
	listChanged bool

	clientInfo mcp.ClientInfo
	serverInfo mcp.ServerInfo

	dropped        atomic.Int64
	unparsed       atomic.Int64
	calls          atomic.Int64
	listings       atomic.Int64
	reportsDropped atomic.Int64
}

type queued struct {
	dir Direction
	raw []byte
}

// NewAnalyzer starts the analyzer's goroutines. Close stops them.
func NewAnalyzer(opts Options) *Analyzer {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	a := &Analyzer{
		opts:      opts,
		scanner:   toolscan.New(opts.Server, opts.Siblings),
		log:       opts.Logger,
		now:       opts.Now,
		frames:    make(chan queued, queueDepth),
		reports:   make(chan *Report, reportQueueDepth),
		done:      make(chan struct{}),
		delivered: make(chan struct{}),
		pending:   map[string]string{},
	}
	go a.work()
	go a.deliver()
	return a
}

// Observe hands a forwarded frame to the analyzer. It never blocks and never
// fails: the frame has already reached its destination by the time this is called.
func (a *Analyzer) Observe(dir Direction, f mcp.Frame) {
	// Copied because the caller's buffer belongs to the relay. The copy is cheap
	// next to the analysis, and aliasing a relay buffer would be the kind of bug
	// that shows up as corrupted evidence months later.
	raw := make([]byte, len(f.Raw))
	copy(raw, f.Raw)
	select {
	case a.frames <- queued{dir: dir, raw: raw}:
	default:
		a.dropped.Add(1)
	}
}

// Close drains the analyzer, sends the shutdown report, and stops its goroutines.
//
// It is bounded by ctx because the interposer shuts down on the critical path of
// the agent's own exit: a wedged ambitd must not hold a developer's session open.
// Safe to call more than once, which matters because both the relay error path and
// the normal path reach for it.
func (a *Analyzer) Close(ctx context.Context) {
	a.closeOnce.Do(func() {
		close(a.frames)
		select {
		case <-a.done:
		case <-ctx.Done():
		}

		a.enqueueReport(a.shutdownReport())
		close(a.reports)
		select {
		case <-a.delivered:
		case <-ctx.Done():
		}
	})
}

func (a *Analyzer) work() {
	defer close(a.done)
	for q := range a.frames {
		a.handle(q)
	}
}

// deliver posts reports off the analysis path, so a slow or absent ambitd costs
// delivery latency rather than analysis throughput.
func (a *Analyzer) deliver() {
	defer close(a.delivered)
	for rep := range a.reports {
		if a.opts.Sender == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
		err := a.opts.Sender.Send(ctx, rep)
		cancel()
		if err != nil {
			// Losing a report is a reportable condition, never a reason to
			// disturb the MCP stream. The shutdown log line carries the count,
			// and a silent collection path is what D7 exists to catch.
			a.reportsDropped.Add(1)
			a.log.Warn("interpose report not delivered",
				"server", a.opts.Server, "trigger", rep.Trigger, "err", err)
		}
	}
}

func (a *Analyzer) handle(q queued) {
	m, err := mcp.Parse(q.raw)
	if err != nil {
		// Unparsed frames are counted, not investigated. They were forwarded
		// already; the counter is what tells us whether this matters in practice.
		a.unparsed.Add(1)
		if errors.Is(err, mcp.ErrBatch) {
			a.log.Debug("JSON-RPC batch frame forwarded without analysis", "server", a.opts.Server)
		}
		return
	}

	switch q.dir {
	case FromClient:
		a.fromClient(m)
	case FromServer:
		a.fromServer(m)
	}
}

func (a *Analyzer) fromClient(m *mcp.Message) {
	switch {
	case m.Method == mcp.MethodToolsCall:
		a.calls.Add(1)
	case m.Method == mcp.MethodInitialize:
		if info, err := mcp.ParseInitializeParams(m.Params); err == nil {
			a.clientInfo = info
		}
		a.track(m)
	case m.Method == mcp.MethodToolsList:
		a.track(m)
	}
}

func (a *Analyzer) track(m *mcp.Message) {
	key := m.IDKey()
	if key == "" {
		return
	}
	if len(a.pending) >= pendingCap {
		// Drop an arbitrary entry rather than growing without bound. Losing a
		// correlation costs one listing's analysis; unbounded growth costs the
		// process.
		for k := range a.pending {
			delete(a.pending, k)
			break
		}
	}
	a.pending[key] = m.Method
}

func (a *Analyzer) fromServer(m *mcp.Message) {
	if m.IsNotification() {
		if m.Method == mcp.NotifToolsListChanged {
			a.listChanged = true
			a.enqueueReport(a.notificationReport())
		}
		return
	}
	if !m.IsResponse() {
		return
	}
	key := m.IDKey()
	method, ok := a.pending[key]
	if !ok {
		return
	}
	delete(a.pending, key)

	if len(m.Error) > 0 {
		// An error response to tools/list is not a listing. Resetting the
		// accumulator matters: a failed page must not leave half a listing behind
		// to be compared as if it were complete.
		if method == mcp.MethodToolsList {
			a.accumulated, a.paging = nil, false
		}
		return
	}

	switch method {
	case mcp.MethodInitialize:
		if info, err := mcp.ParseInitializeResult(m.Result); err == nil {
			a.serverInfo = info
		}
	case mcp.MethodToolsList:
		a.toolsList(m)
	}
}

func (a *Analyzer) toolsList(m *mcp.Message) {
	listing, err := mcp.ParseToolsList(m.Result)
	if err != nil {
		a.unparsed.Add(1)
		a.accumulated, a.paging = nil, false
		return
	}

	a.accumulated = append(a.accumulated, listing.Tools...)
	if listing.NextCursor != "" {
		// Partial page. Waiting is the only correct move: comparing now would
		// report every tool on a later page as removed.
		a.paging = true
		return
	}
	tools := a.accumulated
	a.accumulated, a.paging = nil, false
	a.listings.Add(1)

	trigger := TriggerToolsList
	if a.listChanged {
		trigger = TriggerListChanged
		a.listChanged = false
	}
	a.enqueueReport(a.listingReport(tools, trigger, true))
}

// listingReport builds the report for a complete listing: D4 against the store,
// D5 over every advertised field.
func (a *Analyzer) listingReport(tools []mcp.Tool, trigger string, complete bool) *Report {
	rep := a.baseReport(trigger)
	rep.Complete = complete

	findings := map[string][]toolscan.Finding{}
	truncated := map[string]bool{}
	for _, t := range tools {
		inputText, inTrunc := mcp.SchemaText(t.InputSchema)
		outputText, outTrunc := mcp.SchemaText(t.OutputSchema)
		findings[t.Name] = a.scanner.ScanFields(map[string]string{
			mcp.FieldDescription:  t.Description,
			mcp.FieldTitle:        t.Title,
			mcp.FieldName:         t.Name,
			mcp.FieldInputSchema:  inputText,
			mcp.FieldOutputSchema: outputText,
		})
		truncated[t.Name] = inTrunc || outTrunc
	}

	annotations := map[string]mcp.Tool{}
	for _, t := range tools {
		annotations[t.Name] = t
	}

	if a.opts.Store == nil {
		// Degraded: D5 findings are real, D4 is not available, and the report says
		// so per tool rather than reporting approval it never checked.
		rep.Degraded = true
		rep.DegradedReason = "baseline store unavailable"
		if a.opts.StoreErr != nil {
			rep.DegradedReason = "baseline store unavailable: " + a.opts.StoreErr.Error()
		}
		rep.Worst = string(baseline.StateUnavailable)
		rep.Counts.Tools = len(tools)
		for _, t := range tools {
			rep.Tools = append(rep.Tools, ToolReport{
				Tool:            t.Name,
				State:           string(baseline.StateUnavailable),
				MetadataHash:    mcp.MetadataHash(t),
				ScanClasses:     toolscan.Classes(findings[t.Name]),
				ScanRules:       toolscan.RuleIDs(findings[t.Name]),
				Annotations:     t.EventAnnotations(),
				SchemaTruncated: truncated[t.Name],
			})
		}
		return rep
	}

	res, err := a.opts.Store.Observe(a.opts.Server, a.serverInfo, tools, complete, a.now())
	if err != nil {
		// A store that failed mid-write still produced verdicts; report both the
		// verdicts and the failure, because a silent write failure would mean the
		// next session compares against a stale baseline without anyone knowing.
		rep.Degraded = true
		rep.DegradedReason = "baseline store write failed: " + err.Error()
		a.log.Error("baseline store write failed", "server", a.opts.Server, "err", err)
	}
	rep.Approved = res.Approved
	rep.Worst = string(res.Worst)
	rep.Counts = res.Counts
	for _, v := range res.Verdicts {
		tr := ToolReport{
			Tool:            v.Tool,
			State:           string(v.State),
			MetadataHash:    v.MetadataHash,
			PrevHash:        v.PrevHash,
			ChangedFields:   v.ChangedFields,
			ScanClasses:     toolscan.Classes(findings[v.Tool]),
			ScanRules:       toolscan.RuleIDs(findings[v.Tool]),
			SchemaTruncated: truncated[v.Tool],
		}
		if t, ok := annotations[v.Tool]; ok {
			tr.Annotations = t.EventAnnotations()
		}
		rep.Tools = append(rep.Tools, tr)
	}
	return rep
}

func (a *Analyzer) notificationReport() *Report {
	rep := a.baseReport(TriggerNotification)
	// No hashes: nothing has been re-advertised yet. The value here is the
	// warning, which exists even if the client never re-lists.
	rep.Worst = ""
	return rep
}

func (a *Analyzer) shutdownReport() *Report {
	rep := a.baseReport(TriggerShutdown)
	return rep
}

func (a *Analyzer) baseReport(trigger string) *Report {
	return &Report{
		SchemaV:          ReportSchemaVersion,
		InterposeVersion: a.opts.Version,
		TS:               a.now().UTC().Format(time.RFC3339Nano),
		Server:           a.opts.Server,
		Trigger:          trigger,
		SessionID:        a.opts.SessionID,
		PID:              os.Getpid(),
		PPID:             os.Getppid(),
		ClientName:       a.clientInfo.Name,
		ClientVersion:    a.clientInfo.Version,
		ServerInfo:       a.serverInfo,
		CallsObserved:    a.calls.Load(),
		FramesUnparsed:   a.unparsed.Load(),
	}
}

func (a *Analyzer) enqueueReport(rep *Report) {
	select {
	case a.reports <- rep:
	default:
		a.reportsDropped.Add(1)
	}
}

// Stats reports the analyzer's counters, for the shutdown log line.
type Stats struct {
	Listings       int64
	Calls          int64
	FramesDropped  int64
	FramesUnparsed int64
	ReportsDropped int64
}

func (a *Analyzer) Stats() Stats {
	return Stats{
		Listings:       a.listings.Load(),
		Calls:          a.calls.Load(),
		FramesDropped:  a.dropped.Load(),
		FramesUnparsed: a.unparsed.Load(),
		ReportsDropped: a.reportsDropped.Load(),
	}
}
