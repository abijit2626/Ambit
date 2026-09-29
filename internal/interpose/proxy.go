package interpose

import (
	"context"
	"io"
	"log/slog"

	"github.com/abijit2626/ambit/internal/mcp"
)

// Proxy pumps an MCP stdio session through the analyzer.
//
// It owns no protocol state and makes no decisions: it forwards frames and hands
// copies to the analyzer. The separation is deliberate — the thing in the critical
// path should be small enough to audit in one sitting.
type Proxy struct {
	// FromClient is the agent's requests arriving on our stdin.
	FromClient io.Reader
	// ToServer is the wrapped server's stdin.
	ToServer io.Writer
	// FromServer is the wrapped server's stdout: the untrusted direction.
	FromServer io.Reader
	// ToClient is our stdout, which carries protocol only. Nothing else may ever
	// be written here — a stray log line on stdout is a protocol error that
	// presents as a mysteriously broken MCP server.
	ToClient io.Writer

	// CloseServerIn is called once the client's stream ends, so the wrapped server
	// sees EOF on stdin and exits rather than being left running.
	CloseServerIn func()

	Analyzer *Analyzer
	Logger   *slog.Logger
}

// Run pumps both directions until the client's input ends and the server's output
// ends, returning the first transport error.
//
// ctx cancellation is not a hard interrupt: a blocking read on a pipe cannot be
// unblocked portably, so cancellation is observed by the caller killing the child,
// which closes the pipes and ends both relays. This is stated rather than papered
// over because a reader might otherwise expect Run to return promptly on cancel.
func (p *Proxy) Run(ctx context.Context) error {
	log := p.Logger
	if log == nil {
		log = slog.Default()
	}

	clientErr := make(chan error, 1)
	serverErr := make(chan error, 1)

	go func() {
		// ObserveFirst: a request must be recorded before the server can answer it,
		// or a fast server's response arrives at the analyzer first and cannot be
		// matched to any method. See mcp.ObserveFirst.
		err := mcp.Relay(p.ToServer, p.FromClient, mcp.ObserveFirst, func(f mcp.Frame) {
			p.Analyzer.Observe(FromClient, f)
		})
		// The client is done talking. Closing the server's stdin is what makes the
		// wrapped process exit on its own instead of being killed.
		if p.CloseServerIn != nil {
			p.CloseServerIn()
		}
		clientErr <- err
	}()

	go func() {
		// ForwardFirst: results can be large, and the developer's data goes out
		// before our copy of it.
		serverErr <- mcp.Relay(p.ToClient, p.FromServer, mcp.ForwardFirst, func(f mcp.Frame) {
			p.Analyzer.Observe(FromServer, f)
		})
	}()

	// Wait on the server side first: its EOF means the session is over. The client
	// side may still be blocked reading a stdin that the agent never closes, which
	// is normal, so it is not waited on indefinitely.
	var firstErr error
	if err := <-serverErr; err != nil {
		log.Debug("server relay ended", "err", err)
		firstErr = err
	}
	select {
	case err := <-clientErr:
		if err != nil && firstErr == nil {
			log.Debug("client relay ended", "err", err)
			firstErr = err
		}
	case <-ctx.Done():
	}
	return firstErr
}
