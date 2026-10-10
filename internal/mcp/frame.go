package mcp

import (
	"bufio"
	"errors"
	"io"
)

const MaxFrameBytes = 8 << 20

var ErrFrameTooLarge = errors.New("mcp: frame exceeds MaxFrameBytes; forwarded but not parsed")

type Frame struct {
	Raw       []byte
	Truncated bool
}

func (f Frame) TooLarge() bool { return len(f.Raw) > MaxFrameBytes }

type Order int

const (
	ForwardFirst Order = iota

	ObserveFirst
)

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
