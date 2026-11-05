package hook

import (
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// defaultSessionQueue bounds how many payloads one session may have waiting for ingest. A session that
// outruns this loses the excess, which is counted (ambitd reports it as dropped), not blocked on.
const defaultSessionQueue = 1024

// ingest runs the handler for each payload after the hook's response has been sent, so the agent is never
// kept waiting on ambitd's bookkeeping. Payloads of one session are handled one at a time, in arrival order:
// a PreToolUse that arrives after the PostToolUse of the same session sees everything that PostToolUse
// ingested. Different sessions are handled in parallel.
type ingest struct {
	h     Handler
	limit int

	mu       sync.Mutex
	sessions map[string]*sessionQueue

	dropped atomic.Int64

	// panicked counts payloads whose handler panicked. The payload is lost, but its session's queue
	// and every other session carry on: one malformed or hostile payload cannot stop ambitd, which
	// would end collection until a restart and is itself what D7 alerts on.
	panicked atomic.Int64
	onPanic  func(v any, stack []byte)
}

type sessionQueue struct {
	pending []*Payload
	running bool
}

func newIngest(h Handler, limit int) *ingest {
	if limit <= 0 {
		limit = defaultSessionQueue
	}
	return &ingest{h: h, limit: limit, sessions: map[string]*sessionQueue{}}
}

func (in *ingest) enqueue(p *Payload) {
	in.mu.Lock()
	defer in.mu.Unlock()
	q := in.sessions[p.SessionID]
	if q == nil {
		q = &sessionQueue{}
		in.sessions[p.SessionID] = q
	}
	if len(q.pending) >= in.limit {
		in.dropped.Add(1)
		return
	}
	q.pending = append(q.pending, p)
	if !q.running {
		q.running = true
		go in.run(p.SessionID, q)
	}
}

// run handles one session's payloads until none are waiting, then forgets the session's queue. A payload
// enqueued after that starts a new run, so the order of a session's payloads is kept throughout.
func (in *ingest) run(session string, q *sessionQueue) {
	for {
		in.mu.Lock()
		if len(q.pending) == 0 {
			q.running = false
			delete(in.sessions, session)
			in.mu.Unlock()
			return
		}
		p := q.pending[0]
		q.pending[0] = nil
		q.pending = q.pending[1:]
		in.mu.Unlock()
		in.handle(p)
	}
}

func (in *ingest) handle(p *Payload) {
	defer func() {
		if v := recover(); v != nil {
			in.panicked.Add(1)
			if in.onPanic != nil {
				in.onPanic(v, debug.Stack())
			}
		}
	}()
	in.h.Handle(p)
}

// wait reports whether everything enqueued so far has been handled, waiting up to timeout for it to be.
func (in *ingest) wait(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		in.mu.Lock()
		idle := len(in.sessions) == 0
		in.mu.Unlock()
		if idle {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}
