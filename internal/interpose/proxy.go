package interpose

import (
	"context"
	"io"
	"log/slog"

	"github.com/abijit2626/ambit/internal/mcp"
)

type Proxy struct {
	FromClient io.Reader

	ToServer io.Writer

	FromServer io.Reader

	ToClient io.Writer

	CloseServerIn func()

	Analyzer *Analyzer
	Logger   *slog.Logger
}

func (p *Proxy) Run(ctx context.Context) error {
	log := p.Logger
	if log == nil {
		log = slog.Default()
	}

	clientErr := make(chan error, 1)
	serverErr := make(chan error, 1)

	go func() {

		err := mcp.Relay(p.ToServer, p.FromClient, mcp.ObserveFirst, func(f mcp.Frame) {
			p.Analyzer.Observe(FromClient, f)
		})

		if p.CloseServerIn != nil {
			p.CloseServerIn()
		}
		clientErr <- err
	}()

	go func() {

		serverErr <- mcp.Relay(p.ToClient, p.FromServer, mcp.ForwardFirst, func(f mcp.Frame) {
			p.Analyzer.Observe(FromServer, f)
		})
	}()

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
