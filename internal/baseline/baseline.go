package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/fsperm"
	"github.com/abijit2626/ambit/internal/mcp"
)

const SchemaVersion = 1

type State string

const (
	StateNew State = event.MCPStateNew

	StatePending State = event.MCPStatePending

	StateApproved State = event.MCPStateApproved

	StateDrift State = event.MCPStateDrift

	StateDriftUnapproved State = event.MCPStateDriftUnapproved

	StateRemoved State = event.MCPStateRemoved

	StateUnavailable State = event.MCPStateUnavailable
)

var severity = map[State]int{
	StateDrift:           60,
	StateDriftUnapproved: 50,
	StateRemoved:         40,
	StateUnavailable:     35,
	StateNew:             30,
	StatePending:         20,
	StateApproved:        10,
}

func Severity(s State) int { return severity[s] }

type Snapshot struct {
	MetadataHash string            `json:"metadata_hash"`
	FieldDigests map[string]string `json:"field_digests,omitempty"`
	Description  string            `json:"description,omitempty"`
	Title        string            `json:"title,omitempty"`
	Annotations  event.Annotations `json:"annotations"`
	FirstSeen    string            `json:"first_seen,omitempty"`
	LastSeen     string            `json:"last_seen,omitempty"`
	SeenCount    int               `json:"seen_count,omitempty"`
}

const MaxDescriptionBytes = 8 << 10

type ToolRecord struct {
	Name string `json:"name"`

	Baseline Snapshot `json:"baseline"`

	Current *Snapshot `json:"current,omitempty"`
}

type ServerRecord struct {
	SchemaV    int                   `json:"schema_v"`
	Server     string                `json:"server"`
	Approved   bool                  `json:"approved"`
	ApprovedAt string                `json:"approved_at,omitempty"`
	ApprovedBy string                `json:"approved_by,omitempty"`
	FirstSeen  string                `json:"first_seen,omitempty"`
	LastSeen   string                `json:"last_seen,omitempty"`
	ServerInfo mcp.ServerInfo        `json:"server_info,omitempty"`
	Tools      map[string]ToolRecord `json:"tools"`
}

type Verdict struct {
	Tool          string   `json:"tool"`
	State         State    `json:"state"`
	MetadataHash  string   `json:"metadata_hash,omitempty"`
	PrevHash      string   `json:"prev_metadata_hash,omitempty"`
	ChangedFields []string `json:"changed_fields,omitempty"`
}

type Result struct {
	Server   string    `json:"server"`
	Approved bool      `json:"approved"`
	Complete bool      `json:"complete"`
	Verdicts []Verdict `json:"verdicts"`
	Worst    State     `json:"worst"`
	Counts   Counts    `json:"counts"`
}

type Counts struct {
	Tools     int `json:"tools"`
	New       int `json:"new"`
	Drift     int `json:"drift"`
	Removed   int `json:"removed"`
	Unchanged int `json:"unchanged"`
}

type Store struct {
	dir string
	mu  sync.Mutex
}

func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("baseline: dir is required")
	}
	if err := fsperm.PrivateDir(dir); err != nil {
		return nil, fmt.Errorf("baseline: create %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

func (s *Store) Dir() string { return s.dir }

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9_.-]`)

func fileName(server string) string {
	safe := unsafeName.ReplaceAllString(server, "_")
	safe = strings.TrimLeft(safe, ".")
	if safe == "" {
		safe = "server"
	}
	if len(safe) > 48 {
		safe = safe[:48]
	}
	sum := sha256.Sum256([]byte(server))
	return safe + "-" + hex.EncodeToString(sum[:4]) + ".json"
}

func (s *Store) path(server string) string { return filepath.Join(s.dir, fileName(server)) }

func (s *Store) Load(server string) (ServerRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load(server)
}

func (s *Store) load(server string) (ServerRecord, error) {
	rec := ServerRecord{SchemaV: SchemaVersion, Server: server, Tools: map[string]ToolRecord{}}
	raw, err := os.ReadFile(s.path(server))
	if errors.Is(err, os.ErrNotExist) {
		return rec, nil
	}
	if err != nil {
		return rec, fmt.Errorf("baseline: read %s: %w", s.path(server), err)
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return rec, fmt.Errorf("baseline: parse %s: %w", s.path(server), err)
	}
	if rec.Tools == nil {
		rec.Tools = map[string]ToolRecord{}
	}
	rec.Server = server
	return rec, nil
}

func (s *Store) save(rec ServerRecord) error {
	rec.SchemaV = SchemaVersion
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("baseline: encode %s: %w", rec.Server, err)
	}
	raw = append(raw, '\n')
	final := s.path(rec.Server)
	tmp, err := os.CreateTemp(s.dir, ".baseline-*")
	if err != nil {
		return fmt.Errorf("baseline: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("baseline: chmod temp: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("baseline: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("baseline: close temp: %w", err)
	}

	if err := os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("baseline: rename into place: %w", err)
	}
	return nil
}

func (s *Store) Observe(server string, info mcp.ServerInfo, tools []mcp.Tool, complete bool, now time.Time) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, loadErr := s.load(server)
	stamp := now.UTC().Format(time.RFC3339Nano)
	if rec.FirstSeen == "" {
		rec.FirstSeen = stamp
	}
	rec.LastSeen = stamp
	if info.Name != "" || info.Version != "" {
		rec.ServerInfo = info
	}

	res := Result{Server: server, Approved: rec.Approved, Complete: complete}
	seen := map[string]bool{}

	for _, t := range tools {
		if t.Name == "" {
			continue
		}
		seen[t.Name] = true
		snap := snapshotOf(t, stamp)
		v := Verdict{Tool: t.Name, MetadataHash: snap.MetadataHash}

		old, known := rec.Tools[t.Name]
		switch {
		case !known:
			v.State = StateNew
			snap.SeenCount = 1
			rec.Tools[t.Name] = ToolRecord{Name: t.Name, Baseline: snap}
		case old.Baseline.MetadataHash == snap.MetadataHash &&
			len(mcp.ChangedFields(old.Baseline.FieldDigests, snap.FieldDigests)) == 0:
			if rec.Approved {
				v.State = StateApproved
			} else {
				v.State = StatePending
			}

			old.Baseline.LastSeen = stamp
			old.Baseline.SeenCount++
			old.Current = nil
			rec.Tools[t.Name] = old
		default:
			v.PrevHash = old.Baseline.MetadataHash
			v.ChangedFields = mcp.ChangedFields(old.Baseline.FieldDigests, snap.FieldDigests)
			if rec.Approved {

				v.State = StateDrift
				cur := snap
				if old.Current != nil && old.Current.MetadataHash == snap.MetadataHash {
					cur = *old.Current
					cur.LastSeen = stamp
					cur.SeenCount++
				} else {
					cur.SeenCount = 1
				}
				old.Current = &cur
				old.Baseline.LastSeen = stamp
				rec.Tools[t.Name] = old
			} else {

				v.State = StateDriftUnapproved
				snap.FirstSeen = old.Baseline.FirstSeen
				snap.SeenCount = 1
				rec.Tools[t.Name] = ToolRecord{Name: t.Name, Baseline: snap}
			}
		}
		res.Verdicts = append(res.Verdicts, v)
	}

	if complete {
		var removed []string
		for name := range rec.Tools {
			if !seen[name] {
				removed = append(removed, name)
			}
		}
		sort.Strings(removed)
		for _, name := range removed {

			res.Verdicts = append(res.Verdicts, Verdict{
				Tool:     name,
				State:    StateRemoved,
				PrevHash: rec.Tools[name].Baseline.MetadataHash,
			})
		}
	}

	res.Counts = countOf(res.Verdicts)
	res.Worst = worstOf(res.Verdicts)

	if err := s.save(rec); err != nil {
		return res, err
	}
	return res, loadErr
}

func (s *Store) Approve(server, by string, now time.Time) (ServerRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.load(server)
	if err != nil {
		return rec, err
	}
	if len(rec.Tools) == 0 {
		return rec, fmt.Errorf("baseline: nothing recorded for server %q yet; run a session first", server)
	}
	for name, tr := range rec.Tools {
		if tr.Current != nil {

			cur := *tr.Current
			cur.FirstSeen = tr.Baseline.FirstSeen
			tr.Baseline = cur
			tr.Current = nil
			rec.Tools[name] = tr
		}
	}
	rec.Approved = true
	rec.ApprovedAt = now.UTC().Format(time.RFC3339Nano)
	rec.ApprovedBy = by
	if err := s.save(rec); err != nil {
		return rec, err
	}
	return rec, nil
}

func (s *Store) Revoke(server string) (ServerRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.load(server)
	if err != nil {
		return rec, err
	}
	rec.Approved = false
	rec.ApprovedAt = ""
	rec.ApprovedBy = ""
	if err := s.save(rec); err != nil {
		return rec, err
	}
	return rec, nil
}

func snapshotOf(t mcp.Tool, stamp string) Snapshot {
	desc := t.Description
	if len(desc) > MaxDescriptionBytes {
		desc = desc[:MaxDescriptionBytes]
	}
	return Snapshot{
		MetadataHash: mcp.MetadataHash(t),
		FieldDigests: mcp.FieldDigests(t),
		Description:  desc,
		Title:        t.Title,
		Annotations:  t.EventAnnotations(),
		FirstSeen:    stamp,
		LastSeen:     stamp,
	}
}

func countOf(vs []Verdict) Counts {
	var c Counts
	for _, v := range vs {
		switch v.State {
		case StateNew:
			c.Tools++
			c.New++
		case StateDrift, StateDriftUnapproved:
			c.Tools++
			c.Drift++
		case StateRemoved:
			c.Removed++
		default:
			c.Tools++
			c.Unchanged++
		}
	}
	return c
}

func worstOf(vs []Verdict) State {
	worst := State("")
	for _, v := range vs {
		if severity[v.State] > severity[worst] {
			worst = v.State
		}
	}
	return worst
}
