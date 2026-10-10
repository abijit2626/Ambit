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

var rotateRetry = 30 * time.Second

var renameFile = os.Rename

const asideSuffix = ".rotating"

type Stats struct {
	Written    int64
	Dropped    int64
	QueueDepth int
	WriteErrs  int64
}

type Options struct {
	Path string

	MaxBytes int64

	MaxFiles int

	QueueSize int

	FlushInterval time.Duration

	FileMode os.FileMode
}

func DefaultOptions(path string) Options {
	return Options{
		Path:          path,
		MaxBytes:      64 << 20,
		MaxFiles:      8,
		QueueSize:     4096,
		FlushInterval: 250 * time.Millisecond,
		FileMode:      0o600,
	}
}

type Writer struct {
	opts Options

	ch   chan []byte
	done chan struct{}
	wg   sync.WaitGroup

	mu   sync.Mutex
	f    *os.File
	bw   *bufio.Writer
	size int64

	rotateAfter time.Time

	written   atomic.Int64
	dropped   atomic.Int64
	writeErrs atomic.Int64

	closeOnce sync.Once
}

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

func (w *Writer) Write(v any) bool {
	line, err := json.Marshal(v)
	if err != nil {
		w.writeErrs.Add(1)
		return false
	}

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

			if d := w.dropped.Load(); d > lastReportedDrops {
				w.emitGapMarker(d - lastReportedDrops)
				lastReportedDrops = d
			}
			w.writeLine(line)
		case <-ticker.C:
			w.flush()
		case <-w.done:

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

func (w *Writer) reopenLocked() bool {
	if time.Now().Before(w.rotateAfter) {
		return false
	}
	return w.openLocked() == nil
}

func (w *Writer) rotateLocked() error {
	if w.bw != nil {
		w.bw.Flush()
	}
	if w.f != nil {
		w.f.Close()
	}
	w.f, w.bw = nil, nil

	aside := w.opts.Path + asideSuffix

	if _, err := os.Stat(aside); err != nil {
		if err := renameFile(w.opts.Path, aside); err != nil && !os.IsNotExist(err) {

			return w.abandonRotation(err)
		}
	}

	for i := w.opts.MaxFiles - 1; i >= 1; i-- {
		older := fmt.Sprintf("%s.%d", w.opts.Path, i+1)
		newer := fmt.Sprintf("%s.%d", w.opts.Path, i)
		os.Remove(older)
		os.Rename(newer, older)
	}
	if err := renameFile(aside, w.opts.Path+".1"); err != nil && !os.IsNotExist(err) {

		_ = renameFile(aside, w.opts.Path)
		return w.abandonRotation(err)
	}
	w.rotateAfter = time.Time{}
	return w.openLocked()
}

func (w *Writer) abandonRotation(cause error) error {
	if oerr := w.openLocked(); oerr != nil {
		return errors.Join(cause, oerr)
	}
	w.rotateAfter = time.Now().Add(rotateRetry)
	return cause
}

func (w *Writer) Stats() Stats {
	return Stats{
		Written:    w.written.Load(),
		Dropped:    w.dropped.Load(),
		QueueDepth: len(w.ch),
		WriteErrs:  w.writeErrs.Load(),
	}
}

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

func RotatedFiles(path string) ([]string, error) {
	matches, err := filepath.Glob(path + ".*")
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	return matches, nil
}
