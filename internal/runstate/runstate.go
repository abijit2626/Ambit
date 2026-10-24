package runstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/fsperm"
)

const FileName = "ambitd.state"

const (
	StopClean   = "clean"
	StopUnclean = "unclean"
	StopUnknown = "unknown"
)

type state struct {
	RunID         string `json:"run_id"`
	Version       string `json:"version"`
	StartedAt     string `json:"started_at"`
	LastHeartbeat string `json:"last_heartbeat"`
	StoppedAt     string `json:"stopped_at,omitempty"`
}

type File struct {
	path string
	mu   sync.Mutex
	cur  state
}

func PathFor(trajectoryPath string) string {
	return filepath.Join(filepath.Dir(trajectoryPath), FileName)
}

func Open(path, runID, version string, now time.Time) (*File, *event.PrevRun, error) {
	if err := fsperm.PrivateDir(filepath.Dir(path)); err != nil {
		return nil, nil, fmt.Errorf("runstate dir: %w", err)
	}
	prev := readPrev(path, now)
	ts := now.UTC().Format(time.RFC3339Nano)
	f := &File{path: path, cur: state{RunID: runID, Version: version, StartedAt: ts, LastHeartbeat: ts}}
	if err := f.save(); err != nil {
		return nil, prev, err
	}
	return f, prev, nil
}

func readPrev(path string, now time.Time) *event.PrevRun {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	var s state
	if err != nil || json.Unmarshal(b, &s) != nil || s.RunID == "" {
		return &event.PrevRun{Stop: StopUnknown}
	}
	p := &event.PrevRun{RunID: s.RunID, Version: s.Version, LastHeartbeat: s.LastHeartbeat, Stop: StopUnclean}
	since := s.LastHeartbeat
	if s.StoppedAt != "" {
		p.Stop = StopClean
		since = s.StoppedAt
	}
	if t, err := time.Parse(time.RFC3339Nano, since); err == nil && now.After(t) {
		p.DownSec = int64(now.Sub(t).Seconds())
	}
	return p
}

func (f *File) RunID() string { return f.cur.RunID }

func (f *File) Beat(now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cur.LastHeartbeat = now.UTC().Format(time.RFC3339Nano)
	return f.saveLocked()
}

func (f *File) Stop(now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	ts := now.UTC().Format(time.RFC3339Nano)
	f.cur.LastHeartbeat, f.cur.StoppedAt = ts, ts
	return f.saveLocked()
}

func (f *File) save() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.saveLocked()
}

func (f *File) saveLocked() error {
	b, err := json.Marshal(f.cur)
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write runstate: %w", err)
	}
	if err := os.Rename(tmp, f.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace runstate: %w", err)
	}
	return nil
}
