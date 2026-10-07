package sink

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type rec struct {
	Kind string `json:"kind"`
	N    int    `json:"n"`
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			out = append(out, sc.Text())
		}
	}
	return out
}

func TestWriteOneObjectPerLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	w, err := Open(DefaultOptions(path))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if !w.Write(rec{Kind: "tool_pre", N: i}) {
			t.Fatalf("write %d dropped unexpectedly", i)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	lines := readLines(t, path)
	if len(lines) != 50 {
		t.Fatalf("got %d lines, want 50", len(lines))
	}
	// Every line must parse on its own: log_format json is documented as being
	// for single-line JSON files, so a multi-line object is silently unusable.
	for i, l := range lines {
		var r rec
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("line %d is not standalone JSON: %v", i, err)
		}
		if r.N != i {
			t.Errorf("line %d has n=%d; order must be preserved", i, r.N)
		}
	}
}

// TestWriteNeverEmitsRawNewline guards the one-object-per-line contract against
// content that contains newlines.
func TestWriteNeverEmitsRawNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	w, _ := Open(DefaultOptions(path))
	w.Write(map[string]string{"note": "line one\nline two\nline three"})
	w.Close()

	if lines := readLines(t, path); len(lines) != 1 {
		t.Fatalf("got %d lines, want 1: embedded newlines must not split a record", len(lines))
	}
}

// TestWriteNeverBlocks is the property that protects the hook path. A full queue
// must drop, not wait: a disk stall that became a developer stall would get the
// system disabled.
func TestWriteNeverBlocks(t *testing.T) {
	opts := DefaultOptions(filepath.Join(t.TempDir(), "events.jsonl"))
	opts.QueueSize = 4
	opts.FlushInterval = time.Hour // keep the drain goroutine idle
	w, err := Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 10000; i++ {
			w.Write(rec{Kind: "tool_pre", N: i})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Write blocked; it must drop rather than wait")
	}
	if w.Stats().Dropped == 0 {
		t.Error("expected drops with a queue of 4 and 10000 writes")
	}
}

// TestDropsEmitGapMarker: loss must be visible. A SIEM silently missing events
// is worse than one reporting a hole.
func TestDropsEmitGapMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	opts := DefaultOptions(path)
	opts.QueueSize = 1
	opts.FlushInterval = 10 * time.Millisecond
	w, err := Open(opts)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2000; i++ {
		w.Write(rec{Kind: "tool_pre", N: i})
	}
	// Give the drain goroutine time to emit a marker and then keep writing so a
	// post-drop event exists to precede.
	time.Sleep(200 * time.Millisecond)
	for i := 0; i < 50; i++ {
		w.Write(rec{Kind: "tool_pre", N: i})
		time.Sleep(time.Millisecond)
	}
	w.Close()

	var markers, total int64
	for _, l := range readLines(t, path) {
		var g gapMarker
		if err := json.Unmarshal([]byte(l), &g); err == nil && g.Kind == "sink_gap" {
			markers++
			total += g.Dropped
		}
	}
	if markers == 0 {
		t.Fatal("no gap marker emitted despite drops")
	}
	if total == 0 {
		t.Error("gap marker reported zero dropped events")
	}
	t.Logf("%d gap markers accounting for %d dropped events", markers, total)
}

func TestRotationBoundsDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	opts := DefaultOptions(path)
	opts.MaxBytes = 2 << 10 // 2 KiB
	opts.MaxFiles = 3
	opts.FlushInterval = 5 * time.Millisecond

	w, err := Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4000; i++ {
		w.Write(map[string]any{"kind": "tool_pre", "n": i, "pad": strings.Repeat("x", 64)})
		if i%200 == 0 {
			time.Sleep(2 * time.Millisecond)
		}
	}
	time.Sleep(200 * time.Millisecond)
	w.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// active file + at most MaxFiles rotated
	if len(entries) > opts.MaxFiles+1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("got %d files, want at most %d: disk must stay bounded (%v)", len(entries), opts.MaxFiles+1, names)
	}
	if len(entries) < 2 {
		t.Errorf("expected rotation to have occurred, got %d file(s)", len(entries))
	}
	t.Logf("files after rotation: %d", len(entries))
}

func TestReopenAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	w1, _ := Open(DefaultOptions(path))
	w1.Write(rec{Kind: "a", N: 1})
	w1.Close()

	w2, _ := Open(DefaultOptions(path))
	w2.Write(rec{Kind: "b", N: 2})
	w2.Close()

	if lines := readLines(t, path); len(lines) != 2 {
		t.Errorf("got %d lines, want 2: reopening must append, not truncate", len(lines))
	}
}

func TestFileModeIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	w, _ := Open(DefaultOptions(path))
	w.Write(rec{Kind: "a", N: 1})
	w.Close()

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows reports 0666 or 0444 whatever was asked for; there, privacy is the
	// directory ACL, which internal/fsperm tests.
	if perm := st.Mode().Perm(); runtime.GOOS != "windows" && perm != 0o600 {
		t.Errorf("mode = %o, want 600: events carry redacted but still sensitive metadata", perm)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	w, _ := Open(DefaultOptions(filepath.Join(t.TempDir(), "events.jsonl")))
	if err := w.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second close should be a no-op, got %v", err)
	}
}

func TestStats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	w, _ := Open(DefaultOptions(path))
	for i := 0; i < 10; i++ {
		w.Write(rec{Kind: "a", N: i})
	}
	w.Close()
	if got := w.Stats().Written; got != 10 {
		t.Errorf("Written = %d, want 10", got)
	}
}

// A rotation that cannot rename the live file must not strand the writer. On Windows
// that is routine — a log shipper tailing the file holds it open — and a writer that
// closed the file and then gave up would drop every later event with nothing but a
// counter to show for it.
func TestRotationFailureKeepsWriting(t *testing.T) {
	old := rotateRetry
	rotateRetry = 0
	defer func() { rotateRetry = old }()

	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	// A non-empty directory where the rotated file belongs makes the rename fail on
	// every platform, without needing a second process to hold the file open.
	blocker := path + ".1"
	if err := os.MkdirAll(filepath.Join(blocker, "keep"), 0o700); err != nil {
		t.Fatal(err)
	}

	opts := DefaultOptions(path)
	opts.MaxBytes, opts.MaxFiles = 200, 1
	w, err := Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	const total = 40
	for i := 0; i < total; i++ {
		w.Write(rec{Kind: "tool_pre", N: i})
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if got := len(readLines(t, path)); got != total {
		t.Errorf("got %d lines, want %d: a failed rotation must not lose events", got, total)
	}
	if w.Stats().WriteErrs == 0 {
		t.Error("the failed rotation was not counted, so nothing would show it happened")
	}
}

// Once whatever blocked the rename goes away, rotation resumes.
func TestRotationRecoversAfterFailure(t *testing.T) {
	old := rotateRetry
	rotateRetry = 0
	defer func() { rotateRetry = old }()

	path := filepath.Join(t.TempDir(), "events.jsonl")
	blocker := path + ".1"
	if err := os.MkdirAll(filepath.Join(blocker, "keep"), 0o700); err != nil {
		t.Fatal(err)
	}
	opts := DefaultOptions(path)
	opts.MaxBytes, opts.MaxFiles = 200, 1
	w, err := Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		w.Write(rec{Kind: "tool_pre", N: i})
	}
	time.Sleep(400 * time.Millisecond) // let the drain goroutine reach the failing rotation
	if err := os.RemoveAll(blocker); err != nil {
		t.Fatal(err)
	}
	for i := 20; i < 40; i++ {
		w.Write(rec{Kind: "tool_pre", N: i})
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(blocker); err != nil || st.IsDir() {
		t.Errorf("rotation never resumed after the blocker was removed: %v", err)
	}
}
