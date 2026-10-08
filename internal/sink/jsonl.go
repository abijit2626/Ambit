// Package sink writes events as JSON lines.
//
// Two properties are non-negotiable. Writing must never block the hook path:
// PreToolUse is synchronous on every tool call, and a disk stall that became a
// developer stall would get the whole system disabled. And loss must be visible:
// when the writer drops events it emits a gap marker, because a SIEM that
// silently misses events is worse than one that reports a hole.
//
// Single-line JSON is required by Wazuh's log_format json, which is documented
// as being for single-line JSON files. See docs/02-architecture.md.
package sink

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/abijit2626/ambit/internal/fsperm"
)

// rotateRetry is how long to wait before trying again after a rotation or a reopen
// failed. A variable so the test does not have to wait.
var rotateRetry = 30 * time.Second

// renameFile is os.Rename, replaceable so a test can make one specific rename fail.
var renameFile = os.Rename

// asideSuffix names the file the live log is moved to while older generations are
// shifted up. It exists so that nothing is deleted before the live file is known to
// have moved.
const asideSuffix = ".rotating"

// Stats reports writer health. ambitd emits these as ambitd_health events, which
// is what D11 keys on.
type Stats struct {
	Written    int64
	Dropped    int64
	QueueDepth int
	WriteErrs  int64
}

// Options configure a Writer.
type Options struct {
	// Path is the active file. Rotated files get a .1, .2, ... suffix.
	Path string
	// MaxBytes rotates the active file once it exceeds this size.
	MaxBytes int64
	// MaxFiles caps retained rotated files. The oldest is deleted on rotation,
	// which is the bounded-disk requirement: freeing space must always succeed
	// even when writes are failing.
	MaxFiles int
	// QueueSize bounds the in-memory buffer. Once full, events are dropped and
	// counted rather than blocking the caller.
	QueueSize int
	// FlushInterval bounds how long an event sits in the buffer. Events are not
	// fsynced per write; that trade is deliberate and the cost is that a hard
	// kill can lose up to one interval of events.
	FlushInterval time.Duration
	// FileMode is the permission for created files. Events carry redacted but
	// still sensitive metadata, so this defaults to owner-only.
	FileMode os.FileMode
}

func DefaultOptions(path string) Options {
	return Options{
		Path:          path,
		MaxBytes:      64 << 20, // 64 MiB
		MaxFiles:      8,        // ~512 MiB bounded
		QueueSize:     4096,
		FlushInterval: 250 * time.Millisecond,
		FileMode:      0o600,
	}
}

// Writer appends JSON lines asynchronously.
type Writer struct {
	opts Options

	ch   chan []byte
	done chan struct{}
	wg   sync.WaitGroup

	mu   sync.Mutex
	f    *os.File
	bw   *bufio.Writer
	size int64
	// rotateAfter holds off the next rotation or reopen attempt after one failed, so a
	// file that cannot be renamed or opened is not retried on every single write.
	rotateAfter time.Time

	written   atomic.Int64
	dropped   atomic.Int64
	writeErrs atomic.Int64

	closeOnce sync.Once
}

// Open creates the writer and starts its single drain goroutine.
func Open(opts Options) (*Writer, error) {
	if opts.FileMode == 0 {
		opts.FileMode = 0o600
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = 1024
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 250 * time.Millisecond
	}
	if err := fsperm.PrivateDir(filepath.Dir(opts.Path)); err != nil {
		return nil, fmt.Errorf("create sink dir: %w", err)
	}
	w := &Writer{
		opts: opts,
		ch:   make(chan []byte, opts.QueueSize),
		done: make(chan struct{}),
	}
	if err := w.openFile(); err != nil {
		return nil, err
	}
	w.wg.Add(1)
	go w.drain()
	return w, nil
}

// Write marshals v and enqueues it. It never blocks: if the queue is full the
// event is dropped and counted, and the next successful write is preceded by a
// gap marker.
//
// Returns false when the event was dropped, so the caller can decide whether to
// care. Callers on the hook path should not.
func (w *Writer) Write(v any) bool {
	line, err := json.Marshal(v)
	if err != nil {
		w.writeErrs.Add(1)
		return false
	}
	// Guard against an embedded newline breaking the one-object-per-line
	// contract that log_format json depends on. encoding/json escapes newlines
	// inside strings, so this is belt-and-braces against a future raw writer.
	for i := range line {
		if line[i] == '\n' {
			line[i] = ' '
		}
	}
	select {
	case w.ch <- line:
		return true
	default:
		w.dropped.Add(1)
		return false
	}
}

func (w *Writer) drain() {
	defer w.wg.Done()
	ticker := time.NewTicker(w.opts.FlushInterval)
	defer ticker.Stop()

	var lastReportedDrops int64
	for {
		select {
		case line, ok := <-w.ch:
			if !ok {
				w.flush()
				return
			}
			// Emit a gap marker before the next event whenever drops have
			// accumulated, so a hole in the stream is explicit rather than
			// inferred from missing sequence numbers.
			if d := w.dropped.Load(); d > lastReportedDrops {
				w.emitGapMarker(d - lastReportedDrops)
				lastReportedDrops = d
			}
			w.writeLine(line)
		case <-ticker.C:
			w.flush()
		case <-w.done:
			// Drain whatever is queued, then stop.
			for {
				select {
				case line := <-w.ch:
					w.writeLine(line)
				default:
					w.flush()
					return
				}
			}
		}
	}
}

// gapMarker is the record emitted when events were dropped. It is deliberately
// shaped like an event so a Wazuh rule can alert on it.
type gapMarker struct {
	SchemaV int    `json:"schema_v"`
	TS      string `json:"ts"`
	Kind    string `json:"kind"`
	Dropped int64  `json:"dropped_events"`
	Note    string `json:"note"`
}

func (w *Writer) emitGapMarker(n int64) {
	line, err := json.Marshal(gapMarker{
		SchemaV: 2,
		TS:      time.Now().UTC().Format(time.RFC3339Nano),
		Kind:    "sink_gap",
		Dropped: n,
		Note:    "sink queue full; events were dropped and are not recoverable",
	})
	if err != nil {
		return
	}
	w.writeLine(line)
}

func (w *Writer) writeLine(line []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.bw == nil && !w.reopenLocked() {
		w.writeErrs.Add(1)
		return
	}
	n, err := w.bw.Write(line)
	if err != nil {
		w.writeErrs.Add(1)
		return
	}
	if err := w.bw.WriteByte('\n'); err != nil {
		w.writeErrs.Add(1)
		return
	}
	w.size += int64(n) + 1
	w.written.Add(1)

	if w.opts.MaxBytes > 0 && w.size >= w.opts.MaxBytes && !time.Now().Before(w.rotateAfter) {
		if err := w.rotateLocked(); err != nil {
			w.writeErrs.Add(1)
		}
	}
}

func (w *Writer) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.bw != nil {
		if err := w.bw.Flush(); err != nil {
			w.writeErrs.Add(1)
		}
	}
}

func (w *Writer) openFile() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.openLocked()
}

// openLocked must be called with w.mu held. On failure the writer is left with no
// file and holds off further attempts for rotateRetry; writeLine then retries through
// reopenLocked, so a transient failure (a sharing violation while a virus scanner has
// the file, a disk that was briefly full) costs the events in that window instead of
// every event until the process restarts.
func (w *Writer) openLocked() error {
	f, err := os.OpenFile(w.opts.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, w.opts.FileMode)
	if err != nil {
		w.f, w.bw = nil, nil
		w.rotateAfter = time.Now().Add(rotateRetry)
		return fmt.Errorf("open sink %s: %w", w.opts.Path, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		w.f, w.bw = nil, nil
		w.rotateAfter = time.Now().Add(rotateRetry)
		return fmt.Errorf("stat sink %s: %w", w.opts.Path, err)
	}
	w.f, w.bw, w.size = f, bufio.NewWriterSize(f, 64<<10), st.Size()
	return nil
}

// reopenLocked tries to get a writer back after a failed open. It reports whether
// there is one now. Must be called with w.mu held.
func (w *Writer) reopenLocked() bool {
	if time.Now().Before(w.rotateAfter) {
		return false
	}
	return w.openLocked() == nil
}

// rotateLocked must be called with w.mu held.
//
// The live file is moved aside first, and older generations are shifted only after
// that has succeeded. The shift deletes the oldest generation, so doing it before
// knowing the live file can move would destroy history on every failed attempt, and
// attempts repeat every rotateRetry. On Windows a log shipper tailing the file or a
// virus scanner holding it without delete sharing makes that failure routine.
func (w *Writer) rotateLocked() error {
	if w.bw != nil {
		w.bw.Flush()
	}
	if w.f != nil {
		w.f.Close()
	}
	w.f, w.bw = nil, nil

	aside := w.opts.Path + asideSuffix
	// An aside file left by an interrupted rotation holds events that have not been
	// filed yet. Finish that rotation rather than overwriting it.
	if _, err := os.Stat(aside); err != nil {
		if err := renameFile(w.opts.Path, aside); err != nil && !os.IsNotExist(err) {
			// The live file could not be moved. On Windows that is what happens when
			// another process holds it open without sharing delete access; on Unix it
			// is a full or read-only directory. Nothing has been touched, so reopen
			// and carry on: giving up here would leave the writer without a file and
			// drop every later event. The size cap is soft until a rotation succeeds,
			// and the failure is counted by the caller.
			return w.abandonRotation(err)
		}
	}

	// Shift .N-1 -> .N, dropping the oldest. Deleting frees space even while writes
	// are failing for lack of it, which is why the cap is enforced by deletion rather
	// than by refusing to rotate.
	for i := w.opts.MaxFiles - 1; i >= 1; i-- {
		older := fmt.Sprintf("%s.%d", w.opts.Path, i+1)
		newer := fmt.Sprintf("%s.%d", w.opts.Path, i)
		os.Remove(older)
		os.Rename(newer, older)
	}
	if err := renameFile(aside, w.opts.Path+".1"); err != nil && !os.IsNotExist(err) {
		// Put the live content back where it was, so the next attempt starts clean. If
		// even that fails the aside file stays, and the next rotation files it.
		_ = renameFile(aside, w.opts.Path)
		return w.abandonRotation(err)
	}
	w.rotateAfter = time.Time{}
	return w.openLocked()
}

// abandonRotation reopens the live file after a rotation step failed and holds off
// the next attempt. It returns the rotation error, joined with any reopen error.
func (w *Writer) abandonRotation(cause error) error {
	if oerr := w.openLocked(); oerr != nil {
		return errors.Join(cause, oerr)
	}
	w.rotateAfter = time.Now().Add(rotateRetry)
	return cause
}

// Stats returns a snapshot.
func (w *Writer) Stats() Stats {
	return Stats{
		Written:    w.written.Load(),
		Dropped:    w.dropped.Load(),
		QueueDepth: len(w.ch),
		WriteErrs:  w.writeErrs.Load(),
	}
}

// Close flushes and stops the writer.
func (w *Writer) Close() error {
	var err error
	w.closeOnce.Do(func() {
		close(w.done)
		w.wg.Wait()
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.bw != nil {
			if ferr := w.bw.Flush(); ferr != nil {
				err = ferr
			}
		}
		if w.f != nil {
			if cerr := w.f.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}
	})
	return err
}

// RotatedFiles lists existing rotated files, newest first. Used by the
// investigation pull path.
func RotatedFiles(path string) ([]string, error) {
	matches, err := filepath.Glob(path + ".*")
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	return matches, nil
}
