package sse

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func readAll(t *testing.T, stream string) []Event {
	t.Helper()
	r := NewReader(strings.NewReader(stream))
	var out []Event
	for {
		ev, err := r.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		out = append(out, ev)
	}
}

func TestEventsAndFields(t *testing.T) {
	stream := "\xEF\xBB\xBF: a comment\n" +
		"event: endpoint\ndata: /messages?session=1\n\n" +
		"id: 7\nretry: 2500\ndata: {\"a\":1}\n\n" +
		"data:first\ndata: second\n\n" +
		"id: 8\n\n" +
		"data\n\n" +
		"data: cut off at the end"
	got := readAll(t, stream)
	want := []Event{
		{Type: "endpoint", Data: []byte("/messages?session=1")},
		{Type: "message", Data: []byte(`{"a":1}`), ID: "7", Retry: 2500 * time.Millisecond},
		{Type: "message", Data: []byte("first\nsecond"), ID: "7", Retry: 2500 * time.Millisecond},
		{Type: "message", Data: []byte(""), ID: "8", Retry: 2500 * time.Millisecond},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d events, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.Type != w.Type || string(g.Data) != string(w.Data) || g.ID != w.ID || g.Retry != w.Retry {
			t.Errorf("event %d: got %+v (data %q), want %+v (data %q)", i, g, g.Data, w, w.Data)
		}
	}
}

func TestLineEndings(t *testing.T) {
	for name, stream := range map[string]string{
		"lf":   "data: x\n\n",
		"crlf": "data: x\r\n\r\n",
		"cr":   "data: x\r\r",
	} {
		got := readAll(t, stream)
		if len(got) != 1 || string(got[0].Data) != "x" {
			t.Errorf("%s: got %+v", name, got)
		}
	}
}

func TestEventTypeDoesNotLeakIntoTheNext(t *testing.T) {
	got := readAll(t, "event: endpoint\n\ndata: x\n\n")
	if len(got) != 1 || got[0].Type != "message" {
		t.Fatalf("an event with no data kept its type for the next one: %+v", got)
	}
}

func TestIDWithNULIsIgnored(t *testing.T) {
	got := readAll(t, "id: 1\ndata: a\n\nid: 2\x003\ndata: b\n\n")
	if len(got) != 2 || got[1].ID != "1" {
		t.Fatalf("got %+v", got)
	}
}

func TestOversizedEventIsAnError(t *testing.T) {
	r := NewReader(strings.NewReader("data: 1\ndata: " + strings.Repeat("x", 1<<10) + "\n\n"))
	r.max = 1 << 10
	if _, err := r.Next(); !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("got %v, want ErrEventTooLarge", err)
	}
}

func FuzzReaderNeverPanics(f *testing.F) {
	f.Add("event: endpoint\ndata: /m\n\n")
	f.Add("id: 1\r\nretry: x\r\ndata: {}\r\n\r\n")
	f.Add(":\n\ndata\ndata:\n\n")
	f.Fuzz(func(t *testing.T, stream string) {
		r := NewReader(strings.NewReader(stream))
		for i := 0; i <= len(stream); i++ {
			ev, err := r.Next()
			if err != nil {
				return
			}
			if ev.Type == "" {
				t.Fatal("an event with no type")
			}
		}
		t.Fatal("more events than bytes")
	})
}
