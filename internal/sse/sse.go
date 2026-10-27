// Package sse reads a text/event-stream as the HTML living standard defines it, which is the
// framing both MCP HTTP transports use for server-to-client messages.
package sse

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
	"time"
)

// MaxEventBytes bounds one event's data. A server that streams more than this without a blank
// line is not sending MCP messages, and holding it all would let it exhaust memory.
const MaxEventBytes = 64 << 20

var ErrEventTooLarge = errors.New("sse: event exceeds MaxEventBytes")

type Event struct {
	// Type is the event field, or "message" when the event has none.
	Type string
	Data []byte
	// ID is the last event id the stream has set, carried forward as the standard requires,
	// so a reconnect can send it as Last-Event-ID.
	ID string
	// Retry is the reconnection delay the server last asked for, or zero.
	Retry time.Duration
}

type Reader struct {
	r     *bufio.Reader
	max   int
	id    string
	retry time.Duration
	first bool
}

func NewReader(r io.Reader) *Reader {
	return &Reader{r: bufio.NewReaderSize(r, 64<<10), max: MaxEventBytes, first: true}
}

// Next returns the next event that carries data. Events with no data line are dropped, as the
// standard says, but their id and retry fields still apply. It returns io.EOF at the end of
// the stream; an event cut off by the end is discarded, because a half-delivered JSON-RPC
// message is worse than a missing one.
func (s *Reader) Next() (Event, error) {
	var (
		typ     string
		data    []byte
		hasData bool
		size    int
	)
	for {
		line, err := s.readLine(&size)
		if err != nil {
			return Event{}, err
		}
		if len(line) == 0 {
			if !hasData {
				typ, size = "", 0
				continue
			}
			if typ == "" {
				typ = "message"
			}
			return Event{Type: typ, Data: data, ID: s.id, Retry: s.retry}, nil
		}
		if line[0] == ':' {
			continue
		}
		field, value := line, []byte(nil)
		if i := bytes.IndexByte(line, ':'); i >= 0 {
			field, value = line[:i], line[i+1:]
			if len(value) > 0 && value[0] == ' ' {
				value = value[1:]
			}
		}
		switch string(field) {
		case "event":
			typ = string(value)
		case "data":
			if hasData {
				data = append(data, '\n')
			}
			data = append(data, value...)
			hasData = true
		case "id":
			if bytes.IndexByte(value, 0) < 0 {
				s.id = string(value)
			}
		case "retry":
			if ms, err := strconv.ParseUint(string(value), 10, 31); err == nil {
				s.retry = time.Duration(ms) * time.Millisecond
			}
		}
	}
}

// LastID is the id to send as Last-Event-ID when reconnecting.
func (s *Reader) LastID() string { return s.id }

// readLine returns one line without its terminator. CR, LF and CRLF all end a line. size
// accumulates across the lines of one event so that MaxEventBytes bounds the event, not
// the line.
func (s *Reader) readLine(size *int) ([]byte, error) {
	var line []byte
	for {
		b, err := s.r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, io.EOF
			}
			return nil, err
		}
		switch b {
		case '\n':
			return s.stripBOM(line), nil
		case '\r':
			if next, err := s.r.Peek(1); err == nil && next[0] == '\n' {
				_, _ = s.r.ReadByte()
			}
			return s.stripBOM(line), nil
		}
		*size++
		if *size > s.max {
			return nil, ErrEventTooLarge
		}
		line = append(line, b)
	}
}

func (s *Reader) stripBOM(line []byte) []byte {
	if s.first {
		s.first = false
		line = bytes.TrimPrefix(line, []byte("\xEF\xBB\xBF"))
	}
	return line
}
