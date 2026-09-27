// Package mcp holds the protocol half of the MCP interposer: stdio framing,
// message envelopes, tool metadata, and the canonical metadata hash that D4
// compares against an approved baseline.
//
// Two properties shape every decision in this package.
//
// It is a passthrough, not a gateway. The interposer sits in the path of a
// developer's MCP server, so a parse failure, an oversized frame or an unknown
// method must forward the bytes unchanged and report the problem out of band.
// Anything else turns an observability tool into an outage. See
// docs/08-mcp-interpose-decision.md on what this must never become.
//
// It reads bytes it does not trust. Everything arriving from the server is
// adversarial input by assumption — that is the whole premise of D4 and D5 — so
// frames are size-bounded, JSON is never re-serialized back into the stream, and
// no parse result is allowed to affect what gets forwarded.
package mcp

import (
	"bufio"
	"errors"
	"io"
)

// MaxFrameBytes bounds a single frame handed to the parser. The MCP stdio
// transport is newline-delimited JSON with no length prefix, so a malformed or
// hostile server could otherwise make us buffer without limit. Oversized frames
// are still forwarded in full — they are only excluded from parsing, because
// truncating the developer's traffic to protect our own analysis would be the
// wrong trade.
const MaxFrameBytes = 8 << 20 // 8 MiB

// ErrFrameTooLarge reports a frame that was forwarded but not parsed.
var ErrFrameTooLarge = errors.New("mcp: frame exceeds MaxFrameBytes; forwarded but not parsed")

// Frame is one newline-delimited message as it appeared on the wire.
//
// Raw includes the trailing newline when the sender sent one, so a relay can
// write Raw verbatim and produce a byte-identical stream. Truncated is true when
// the stream ended without a final newline, which is normal at shutdown.
type Frame struct {
	Raw       []byte
	Truncated bool
}

// TooLarge reports whether the frame exceeded the parse bound.
func (f Frame) TooLarge() bool { return len(f.Raw) > MaxFrameBytes }

// Order says whether a frame is observed before or after it is forwarded.
type Order int

const (
	// ForwardFirst forwards the frame, then observes it. The default, and correct
	// for the server-to-client direction: results can be megabytes, and copying one
	// before relaying it would put our analysis in front of the developer's data.
	ForwardFirst Order = iota

	// ObserveFirst records the frame, then forwards it. Required for the
	// client-to-server direction, for a reason that is not obvious.
	//
	// The two directions are relayed by separate goroutines. If a request were
	// observed only after being written to the server, a fast server could answer
	// it and have its response observed by the other goroutine first — and a
	// response with no recorded request is a response the analyzer cannot
	// recognize, because MCP responses carry no method name. tools/list would
	// intermittently go unanalyzed, more often the faster the server, which is the
	// worst shape a detection gap can have.
	//
	// The cost is a non-blocking channel send ahead of a small request write, which
	// is nanoseconds and cannot withhold the frame: observe must not block, and the
	// write follows immediately.
	ObserveFirst
)

// Relay copies frames from src to dst, handing each to observe.
//
// observe runs on the relay goroutine, so an implementation that blocks adds
// latency to the developer's MCP traffic; the analyzer in internal/interpose hands
// work to a bounded queue rather than doing anything inline, for exactly that
// reason.
//
// A write error to dst is fatal and returned: the peer is gone and there is
// nothing useful left to do. observe cannot fail the relay, which is why it
// returns nothing.
func Relay(dst io.Writer, src io.Reader, order Order, observe func(Frame)) error {
	r := bufio.NewReaderSize(src, 64<<10)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			frame := Frame{Raw: line, Truncated: err != nil}
			if observe != nil && order == ObserveFirst {
				observe(frame)
			}
			if _, werr := dst.Write(line); werr != nil {
				return werr
			}
			if f, ok := dst.(flusher); ok {
				// A buffered writer would hold a request until the buffer filled,
				// which on a request/response protocol is a hang, not a delay.
				_ = f.Flush()
			}
			if observe != nil && order == ForwardFirst {
				observe(frame)
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

type flusher interface{ Flush() error }
