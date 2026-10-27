package interpose

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/abijit2626/ambit/internal/mcp"
	"github.com/abijit2626/ambit/internal/sse"
)

type Transport string

const (
	// TransportHTTP is MCP's Streamable HTTP transport (2025-03-26 and later).
	TransportHTTP Transport = "http"
	// TransportSSE is the 2024-11-05 HTTP+SSE transport, which Claude Code calls "sse".
	TransportSSE Transport = "sse"
)

func ParseTransport(s string) (Transport, error) {
	switch Transport(strings.ToLower(strings.TrimSpace(s))) {
	case TransportHTTP, "streamable-http", "streamable_http":
		return TransportHTTP, nil
	case TransportSSE:
		return TransportSSE, nil
	}
	return "", fmt.Errorf("unknown transport %q; want http or sse", s)
}

const (
	headerSession  = "Mcp-Session-Id"
	headerProtocol = "MCP-Protocol-Version"
	headerLastID   = "Last-Event-ID"

	maxBodyBytes = sse.MaxEventBytes

	// A notification or a response to the server has nothing to wait for, so a server that
	// sits on one must not stall every message the client sends after it.
	shortPostTimeout = 30 * time.Second
	deleteTimeout    = 2 * time.Second
	defaultGrace     = 3 * time.Second
	maxBackoff       = 30 * time.Second
	maxResumes       = 5
)

var (
	ErrSessionExpired = errors.New("interpose: the upstream server ended the MCP session")
	errNoStream       = errors.New("server does not offer a GET stream")
)

// Bridge speaks newline-delimited JSON-RPC to the client on one side, as a stdio MCP server
// does, and one of MCP's HTTP transports to the real server on the other. Claude Code starts
// it as a stdio server, so the server keeps its key in .mcp.json, and with it the
// mcp__<server>__<tool> identity, and the bridge lives exactly as long as the session.
// The Analyzer sees the same frames it would see from a stdio server.
type Bridge struct {
	URL       *url.URL
	Transport Transport
	Header    http.Header
	HTTP      *http.Client

	FromClient io.Reader
	ToClient   io.Writer

	Analyzer *Analyzer
	Logger   *slog.Logger

	// Grace is how long Run waits for in-flight requests once the client has gone.
	Grace time.Duration

	out lineWriter
	log *slog.Logger

	mu       sync.Mutex
	session  string
	protocol string

	// inflight counts requests awaiting their answer; workers counts every goroutine that can
	// still write to the client or the Analyzer, which Run waits out before it returns.
	inflight sync.WaitGroup
	workers  sync.WaitGroup
	fatal    chan error
	endpoint chan *url.URL

	// owed holds the ids of requests posted over the legacy transport whose answers have not
	// come back on the stream yet; settled is signalled each time one does.
	owed    map[string]struct{}
	settled chan struct{}
}

func (b *Bridge) Run(ctx context.Context) error {
	if b.URL == nil {
		return errors.New("interpose: bridge has no upstream URL")
	}
	b.log = b.Logger
	if b.log == nil {
		b.log = slog.Default()
	}
	if b.HTTP == nil {
		b.HTTP = &http.Client{}
	}
	if b.Grace == 0 {
		b.Grace = defaultGrace
	}
	if b.Transport == "" {
		b.Transport = TransportHTTP
	}
	b.out = lineWriter{w: b.ToClient}
	b.fatal = make(chan error, 1)
	b.endpoint = make(chan *url.URL, 1)
	b.owed = map[string]struct{}{}
	b.settled = make(chan struct{}, 1)

	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		b.workers.Wait()
	}()

	if b.Transport == TransportSSE {
		b.spawn(func() { b.legacyStream(ctx) })
	}

	lines := make(chan []byte)
	readErr := make(chan error, 1)
	go func() {
		readErr <- readLines(ctx, b.FromClient, lines)
	}()

	var streamOnce sync.Once
	var endpoint *url.URL
	for {
		select {
		case line := <-lines:
			if b.Analyzer != nil {
				b.Analyzer.Observe(FromClient, mcp.Frame{Raw: line})
			}
			m, _ := mcp.Parse(line)
			body := bytes.TrimRight(line, "\r\n")
			if b.Transport == TransportSSE {
				if endpoint == nil {
					select {
					case endpoint = <-b.endpoint:
					case err := <-b.fatal:
						return err
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				b.postLegacy(ctx, endpoint, body, m)
				continue
			}
			// initialize goes out alone: its answer carries the session id and protocol version
			// every later message needs. Other requests run concurrently, as a stdio server may
			// answer them in any order.
			if isRequest(m) && m.Method != mcp.MethodInitialize {
				b.inflight.Add(1)
				b.spawn(func() {
					defer b.inflight.Done()
					b.post(ctx, body, m)
				})
				continue
			}
			b.post(ctx, body, m)
			if m != nil && m.Method == "notifications/initialized" {
				streamOnce.Do(func() { b.spawn(func() { b.listen(ctx) }) })
			}
		case err := <-readErr:
			b.drain()
			if b.Transport == TransportHTTP {
				b.endSession()
			}
			return err
		case err := <-b.fatal:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (b *Bridge) spawn(fn func()) {
	b.workers.Add(1)
	go func() {
		defer b.workers.Done()
		fn()
	}()
}

func readLines(ctx context.Context, r io.Reader, lines chan<- []byte) error {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			select {
			case lines <- line:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func (b *Bridge) drain() {
	timeout := time.After(b.Grace)
	if b.Transport == TransportSSE {
		for {
			b.mu.Lock()
			n := len(b.owed)
			b.mu.Unlock()
			if n == 0 {
				return
			}
			select {
			case <-b.settled:
			case <-timeout:
				b.log.Debug("client gone with requests still unanswered", "url", logURL(b.URL), "requests", n)
				return
			}
		}
	}
	done := make(chan struct{})
	go func() {
		b.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-timeout:
		b.log.Debug("client gone with requests still in flight", "url", logURL(b.URL))
	}
}

func (b *Bridge) owe(id string, owed bool) {
	b.mu.Lock()
	if owed {
		b.owed[id] = struct{}{}
	} else {
		delete(b.owed, id)
	}
	b.mu.Unlock()
	if !owed {
		select {
		case b.settled <- struct{}{}:
		default:
		}
	}
}

func (b *Bridge) fail(err error) {
	select {
	case b.fatal <- err:
	default:
	}
}

func (b *Bridge) newRequest(ctx context.Context, method, target string, body []byte) (*http.Request, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return nil, err
	}
	for k, vs := range b.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if b.Transport == TransportHTTP {
		b.mu.Lock()
		session, protocol := b.session, b.protocol
		b.mu.Unlock()
		if session != "" {
			req.Header.Set(headerSession, session)
		}
		if protocol != "" {
			req.Header.Set(headerProtocol, protocol)
		}
	}
	return req, nil
}

// post sends one client message over Streamable HTTP and relays whatever the server answers.
func (b *Bridge) post(ctx context.Context, body []byte, m *mcp.Message) {
	if !isRequest(m) {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, shortPostTimeout)
		defer cancel()
	}
	req, err := b.newRequest(ctx, http.MethodPost, b.URL.String(), body)
	if err != nil {
		b.answerError(m, "build request: "+err.Error())
		return
	}
	req.Header.Set("Accept", "application/json, text/event-stream")

	b.mu.Lock()
	hadSession := b.session != ""
	b.mu.Unlock()

	resp, err := b.HTTP.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			b.log.Warn("upstream MCP request failed", "url", logURL(b.URL), "err", err)
		}
		b.answerError(m, "upstream unreachable")
		return
	}
	defer resp.Body.Close()

	if id := resp.Header.Get(headerSession); id != "" {
		b.mu.Lock()
		b.session = id
		b.mu.Unlock()
	}

	switch {
	case resp.StatusCode == http.StatusNotFound && hadSession:
		b.answerError(m, "upstream session expired")
		b.fail(ErrSessionExpired)
		return
	case resp.StatusCode == http.StatusAccepted:
		return
	case resp.StatusCode/100 != 2:
		b.log.Warn("upstream MCP server refused a message", "url", logURL(b.URL), "status", resp.Status)
		b.answerError(m, "upstream returned "+resp.Status)
		return
	}

	var initID string
	if m != nil && m.Method == mcp.MethodInitialize {
		initID = m.IDKey()
	}
	answered := false
	emit := func(data []byte) {
		if initID != "" {
			b.noteProtocol(initID, data)
		}
		if isAnswerTo(m, data) {
			answered = true
		}
		b.emit(data)
	}

	switch mediaType(resp.Header.Get("Content-Type")) {
	case "application/json":
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
		if err != nil || len(data) > maxBodyBytes {
			b.log.Warn("upstream MCP response unreadable", "url", logURL(b.URL), "err", err, "bytes", len(data))
			break
		}
		emit(data)
	case "text/event-stream":
		var lastID string
		var retry time.Duration
		each := func(ev sse.Event) {
			lastID, retry = ev.ID, ev.Retry
			if ev.Type == "message" {
				emit(ev.Data)
			}
		}
		_ = b.readEvents(resp.Body, each)
		// A server may close the stream before answering once it has given an event id, and
		// expect the client to pick the stream up again with Last-Event-ID.
		for attempt := 0; isRequest(m) && !answered && lastID != "" && attempt < maxResumes && ctx.Err() == nil; attempt++ {
			if retry > 0 {
				select {
				case <-time.After(min(retry, maxBackoff)):
				case <-ctx.Done():
				}
			}
			if !b.resume(ctx, lastID, each) {
				break
			}
		}
	}
	if isRequest(m) && !answered && ctx.Err() == nil {
		b.answerError(m, "upstream closed the response without answering")
	}
}

func (b *Bridge) resume(ctx context.Context, lastID string, each func(sse.Event)) bool {
	req, err := b.newRequest(ctx, http.MethodGet, b.URL.String(), nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set(headerLastID, lastID)
	resp, err := b.HTTP.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 || mediaType(resp.Header.Get("Content-Type")) != "text/event-stream" {
		return false
	}
	_ = b.readEvents(resp.Body, each)
	return true
}

func (b *Bridge) noteProtocol(initID string, data []byte) {
	r, err := mcp.Parse(data)
	if err != nil || !r.IsResponse() || r.IDKey() != initID || len(r.Result) == 0 {
		return
	}
	if info, err := mcp.ParseInitializeResult(r.Result); err == nil && info.ProtocolVersion != "" {
		b.mu.Lock()
		b.protocol = info.ProtocolVersion
		b.mu.Unlock()
	}
}

func (b *Bridge) readEvents(body io.Reader, each func(sse.Event)) error {
	r := sse.NewReader(body)
	for {
		ev, err := r.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		each(ev)
	}
}

// listen holds the optional GET stream a Streamable HTTP server uses for messages that are
// not answers to a request, such as notifications/tools/list_changed, which is how D4 learns
// a surface changed mid-session. It reconnects with Last-Event-ID until the session ends.
func (b *Bridge) listen(ctx context.Context) {
	backoff := time.Second
	lastID := ""
	for ctx.Err() == nil {
		got, retry, err := b.getStream(ctx, &lastID)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errNoStream) {
			b.log.Debug("upstream offers no server stream", "url", logURL(b.URL))
			return
		}
		if errors.Is(err, ErrSessionExpired) {
			b.fail(err)
			return
		}
		if got {
			backoff = time.Second
		}
		wait := backoff
		if retry > 0 {
			wait = retry
		}
		b.log.Debug("server stream ended; reconnecting", "url", logURL(b.URL), "err", err, "in", wait)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func (b *Bridge) getStream(ctx context.Context, lastID *string) (bool, time.Duration, error) {
	req, err := b.newRequest(ctx, http.MethodGet, b.URL.String(), nil)
	if err != nil {
		return false, 0, err
	}
	req.Header.Set("Accept", "text/event-stream")
	if *lastID != "" {
		req.Header.Set(headerLastID, *lastID)
	}
	resp, err := b.HTTP.Do(req)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusMethodNotAllowed:
		return false, 0, errNoStream
	case resp.StatusCode == http.StatusNotFound && req.Header.Get(headerSession) != "":
		return false, 0, ErrSessionExpired
	case resp.StatusCode/100 != 2:
		return false, 0, fmt.Errorf("server stream: %s", resp.Status)
	case mediaType(resp.Header.Get("Content-Type")) != "text/event-stream":
		return false, 0, errNoStream
	}
	got := false
	var retry time.Duration
	err = b.readEvents(resp.Body, func(ev sse.Event) {
		*lastID, retry = ev.ID, ev.Retry
		if ev.Type == "message" {
			got = true
			b.emit(ev.Data)
		}
	})
	return got, retry, err
}

func (b *Bridge) endSession() {
	b.mu.Lock()
	session := b.session
	b.mu.Unlock()
	if session == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), deleteTimeout)
	defer cancel()
	req, err := b.newRequest(ctx, http.MethodDelete, b.URL.String(), nil)
	if err != nil {
		return
	}
	resp, err := b.HTTP.Do(req)
	if err != nil {
		b.log.Debug("could not end the upstream session", "err", err)
		return
	}
	resp.Body.Close()
}

// legacyStream holds the 2024-11-05 transport's single GET stream. Its first event names the
// URL to POST to; every server message arrives on it after that. The stream ending ends the
// session, as a stdio server exiting would.
func (b *Bridge) legacyStream(ctx context.Context) {
	req, err := b.newRequest(ctx, http.MethodGet, b.URL.String(), nil)
	if err != nil {
		b.fail(err)
		return
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := b.HTTP.Do(req)
	if err != nil {
		b.fail(fmt.Errorf("interpose: open SSE stream: %w", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b.fail(fmt.Errorf("interpose: open SSE stream: %s", resp.Status))
		return
	}
	sent := false
	err = b.readEvents(resp.Body, func(ev sse.Event) {
		switch ev.Type {
		case "endpoint":
			if sent {
				return
			}
			u, err := b.sameOrigin(string(bytes.TrimSpace(ev.Data)))
			if err != nil {
				b.fail(err)
				return
			}
			sent = true
			b.endpoint <- u
		case "message":
			b.emit(ev.Data)
			if r, err := mcp.Parse(ev.Data); err == nil && r.IsResponse() {
				b.owe(r.IDKey(), false)
			}
		}
	})
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		b.fail(fmt.Errorf("interpose: SSE stream: %w", err))
		return
	}
	b.fail(nil)
}

// sameOrigin resolves the endpoint event against the stream URL and refuses one on another
// origin, which would otherwise receive every client message along with any credentials in
// Header.
func (b *Bridge) sameOrigin(raw string) (*url.URL, error) {
	ref, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("interpose: endpoint event %q: %w", raw, err)
	}
	u := b.URL.ResolveReference(ref)
	if !strings.EqualFold(u.Scheme, b.URL.Scheme) || !strings.EqualFold(u.Host, b.URL.Host) {
		return nil, fmt.Errorf("interpose: endpoint %s is not on the server's origin %s://%s; refusing to send messages there",
			logURL(u), b.URL.Scheme, b.URL.Host)
	}
	return u, nil
}

func (b *Bridge) postLegacy(ctx context.Context, endpoint *url.URL, body []byte, m *mcp.Message) {
	ctx, cancel := context.WithTimeout(ctx, shortPostTimeout)
	defer cancel()
	req, err := b.newRequest(ctx, http.MethodPost, endpoint.String(), body)
	if err != nil {
		b.answerError(m, "build request: "+err.Error())
		return
	}
	// Owed before the POST goes out: the answer can arrive on the stream before it returns.
	if isRequest(m) {
		b.owe(m.IDKey(), true)
	}
	resp, err := b.HTTP.Do(req)
	if err != nil {
		b.log.Warn("upstream MCP request failed", "url", logURL(endpoint), "err", err)
		b.unowe(m)
		b.answerError(m, "upstream unreachable")
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b.log.Warn("upstream MCP server refused a message", "url", logURL(endpoint), "status", resp.Status)
		b.unowe(m)
		b.answerError(m, "upstream returned "+resp.Status)
	}
}

// emit writes one server message to the client as a single line, then lets the Analyzer see
// it, in the order the stdio relay uses for server output.
func (b *Bridge) emit(data []byte) {
	line := oneLine(data)
	if len(line) == 0 {
		return
	}
	line = append(line, '\n')
	if err := b.out.write(line); err != nil {
		b.fail(fmt.Errorf("interpose: write to client: %w", err))
		return
	}
	if b.Analyzer != nil {
		b.Analyzer.Observe(FromServer, mcp.Frame{Raw: line})
	}
}

// answerError gives the client an error response for a request the server will now never
// answer, so the client fails the call rather than waiting on it. The Analyzer does not see
// it: it describes the bridge, not the server.
func (b *Bridge) answerError(m *mcp.Message, reason string) {
	if !isRequest(m) {
		return
	}
	resp := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: m.ID}
	resp.Error.Code = -32603
	resp.Error.Message = "mcp-interpose: " + reason
	raw, err := json.Marshal(resp)
	if err != nil {
		return
	}
	if err := b.out.write(append(raw, '\n')); err != nil {
		b.fail(fmt.Errorf("interpose: write to client: %w", err))
	}
}

func (b *Bridge) unowe(m *mcp.Message) {
	if isRequest(m) {
		b.owe(m.IDKey(), false)
	}
}

func isRequest(m *mcp.Message) bool {
	return m != nil && m.Method != "" && len(m.ID) > 0
}

func isAnswerTo(m *mcp.Message, data []byte) bool {
	if !isRequest(m) {
		return false
	}
	r, err := mcp.Parse(data)
	return err == nil && r.IsResponse() && r.IDKey() == m.IDKey()
}

// oneLine makes a JSON message safe for newline framing. A literal newline can only sit
// between tokens in valid JSON, never inside a string, so compacting removes them all; a
// body that is not valid JSON has them replaced instead, and the client decides what to do
// with it.
func oneLine(data []byte) []byte {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil
	}
	var buf bytes.Buffer
	if json.Compact(&buf, data) == nil {
		return buf.Bytes()
	}
	data = bytes.ReplaceAll(data, []byte("\r"), []byte(" "))
	return bytes.ReplaceAll(data, []byte("\n"), []byte(" "))
}

// logURL is a URL as it may appear on stderr, which Claude Code keeps in its MCP logs: a
// remote server's URL sometimes carries an API key in its query, so the query never appears.
func logURL(u *url.URL) string {
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
}

func mediaType(contentType string) string {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(contentType))
	}
	return mt
}

type lineWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lineWriter) write(line []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.w.Write(line); err != nil {
		return err
	}
	if f, ok := l.w.(flusher); ok {
		return f.Flush()
	}
	return nil
}

type flusher interface{ Flush() error }
