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

type Direction int

const (
	FromClient Direction = iota

	FromServer
)

const queueDepth = 256

const reportQueueDepth = 32

const pendingCap = 64

type Sender interface {
	Send(ctx context.Context, rep *Report) error
}

type Options struct {
	Server string

	Siblings []string

	Store *baseline.Store

	StoreErr error
	Sender   Sender
	Logger   *slog.Logger
	Version  string

	SessionID string

	Now func() time.Time
}

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

	pending map[string]string

	accumulated []mcp.Tool

	paging bool

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

func (a *Analyzer) Observe(dir Direction, f mcp.Frame) {

	raw := make([]byte, len(f.Raw))
	copy(raw, f.Raw)
	select {
	case a.frames <- queued{dir: dir, raw: raw}:
	default:
		a.dropped.Add(1)
	}
}

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

			a.reportsDropped.Add(1)
			a.log.Warn("interpose report not delivered",
				"server", a.opts.Server, "trigger", rep.Trigger, "err", err)
		}
	}
}

func (a *Analyzer) handle(q queued) {
	m, err := mcp.Parse(q.raw)
	if err != nil {

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
