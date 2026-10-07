// Package baseline implements detector D4: MCP tool metadata drift against an
// approved baseline.
//
// The state machine is the whole design, and one rule drives it: **an approved
// baseline is never silently overwritten.** A server whose metadata changes after
// approval reports drift on every listing until an operator approves the change.
// The tempting alternative — record the new hash and move on — turns a rug-pull
// detector into a change log that alerts once and then agrees with the attacker.
//
// Before approval the baseline is provisional: first sighting records what the
// server advertised and reports it as new, and subsequent changes report as
// unapproved change. That distinction matters to a runbook. Drift from an
// approved baseline means a human reviewed this surface and it has since changed.
// Change before approval means nobody has reviewed it yet.
//
// Known weakness, stated rather than mitigated away: this store is written by a
// process running as the developer, so malware holding the developer's privileges
// can rewrite it, and the operator approval step can be driven from the same
// machine the agent runs on. That is the same trust boundary Claude Code's own
// user-scope settings sit inside, and it is why managed settings exist at a higher
// precedence. The store lives under the ambit directory so Wazuh FIM can watch it
// (deploy/wazuh/ossec-syscheck.xml), which turns a silent rewrite into a D6 event.
// A stronger answer — approval held off the endpoint — is an M3 question tied to
// docs/07-open-questions.md Q8 on bundle signing.
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

// SchemaVersion is the on-disk format version. A mismatch is not an error: an
// older file is read as far as it parses, because failing to load a baseline
// would make every tool look new, which is an alert storm rather than a safe
// default.
const SchemaVersion = 1

// State is the per-tool D4 verdict.
type State string

// The state strings are defined in internal/event because they are schema: they
// cross to Wazuh in cleartext and the ruleset matches them literally.
const (
	// StateNew is a tool never seen before. Recorded as provisional.
	StateNew State = event.MCPStateNew
	// StatePending matches a provisional baseline nobody has approved.
	StatePending State = event.MCPStatePending
	// StateApproved matches the approved baseline. The quiet, common case.
	StateApproved State = event.MCPStateApproved
	// StateDrift differs from an APPROVED baseline. This is D4 proper.
	StateDrift State = event.MCPStateDrift
	// StateDriftUnapproved differs from a provisional baseline. Notable, weaker.
	StateDriftUnapproved State = event.MCPStateDriftUnapproved
	// StateRemoved was in the baseline and is absent from a complete listing.
	StateRemoved State = event.MCPStateRemoved
	// StateUnavailable means the store could not be read or written. Emitted so
	// that "no drift" can never be confused with "no baseline": a detector that
	// reports approval it never checked is worse than one that reports nothing.
	StateUnavailable State = event.MCPStateUnavailable
)

// severity ranks states so a listing can report its worst finding as a scalar.
var severity = map[State]int{
	StateDrift:           60,
	StateDriftUnapproved: 50,
	StateRemoved:         40,
	StateUnavailable:     35,
	StateNew:             30,
	StatePending:         20,
	StateApproved:        10,
}

// Severity exposes the ranking for callers comparing states.
func Severity(s State) int { return severity[s] }

// Snapshot is what a server advertised for one tool at one moment.
//
// Description holds the advertised text, truncated. It is third-party metadata,
// not our content, and keeping it locally is what makes a drift alert explainable:
// an investigator can read what the description actually said without the text
// ever crossing to a SIEM or to an external monitoring firm. See docs/01 on the
// MSSP posture.
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

// MaxDescriptionBytes bounds retained description text. A hostile server could
// otherwise grow this file without limit.
const MaxDescriptionBytes = 8 << 10

// ToolRecord is the baseline entry for one tool plus, when it has drifted, the
// live version.
type ToolRecord struct {
	Name string `json:"name"`
	// Baseline is the approved or provisional snapshot. Immutable once approved.
	Baseline Snapshot `json:"baseline"`
	// Current is set only while the live metadata differs from Baseline. It gives
	// an investigator the drifted text without destroying what was approved.
	Current *Snapshot `json:"current,omitempty"`
}

// ServerRecord is the stored baseline for one MCP server.
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

// Verdict is the per-tool result of comparing a listing against the baseline.
type Verdict struct {
	Tool          string   `json:"tool"`
	State         State    `json:"state"`
	MetadataHash  string   `json:"metadata_hash,omitempty"`
	PrevHash      string   `json:"prev_metadata_hash,omitempty"`
	ChangedFields []string `json:"changed_fields,omitempty"`
}

// Result is the whole listing's comparison.
type Result struct {
	Server   string    `json:"server"`
	Approved bool      `json:"approved"`
	Complete bool      `json:"complete"`
	Verdicts []Verdict `json:"verdicts"`
	Worst    State     `json:"worst"`
	Counts   Counts    `json:"counts"`
}

// Counts summarizes a listing for the per-server event, which is the one that
// crosses to Wazuh on every listing.
type Counts struct {
	Tools     int `json:"tools"`
	New       int `json:"new"`
	Drift     int `json:"drift"`
	Removed   int `json:"removed"`
	Unchanged int `json:"unchanged"`
}

// Store is a directory of per-server baseline files.
type Store struct {
	dir string
	mu  sync.Mutex
}

// Open prepares the store directory.
//
// Permissions are owner-only: the file holds third-party metadata and the record
// of what an operator approved, and it is read during incident response.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("baseline: dir is required")
	}
	if err := fsperm.PrivateDir(dir); err != nil {
		return nil, fmt.Errorf("baseline: create %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

// Dir reports the store directory.
func (s *Store) Dir() string { return s.dir }

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9_.-]`)

// fileName maps a server name to a file name that cannot escape the store.
//
// The server name comes from .mcp.json, which is attacker-writable in the threat
// model that motivates D6, so a name of "../../.ssh/authorized_keys" has to be
// impossible rather than unlikely. The digest suffix keeps two names that sanitize
// to the same string in separate files.
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

// Load reads a server's record. A missing file yields an empty record, not an
// error: never having seen a server is the normal starting state.
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
	// Rename rather than truncate-and-write: a crash mid-write would otherwise
	// leave a half-written baseline, and a baseline that fails to parse makes
	// every tool look new.
	if err := os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("baseline: rename into place: %w", err)
	}
	return nil
}

// Observe compares a listing against the stored baseline and records what it saw.
//
// complete must be false when the listing is one page of a paginated tools/list
// response. An incomplete listing can still report new tools and drift — those are
// positive observations — but it must not report removals, because the tools it did
// not mention are on another page rather than gone.
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
			// Seeing the approved surface again updates liveness only. Clearing
			// Current matters: a server that drifted and then reverted is back in
			// compliance, and leaving the drifted snapshot behind would keep
			// reporting a change that is no longer there.
			old.Baseline.LastSeen = stamp
			old.Baseline.SeenCount++
			old.Current = nil
			rec.Tools[t.Name] = old
		default:
			v.PrevHash = old.Baseline.MetadataHash
			v.ChangedFields = mcp.ChangedFields(old.Baseline.FieldDigests, snap.FieldDigests)
			if rec.Approved {
				// The approved snapshot is left exactly as approved. Only the live
				// side moves.
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
				// Provisional: the observation becomes the new provisional
				// baseline, because nothing has been approved to preserve.
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
			// A removed tool stays in the store. It is evidence: a rug pull that
			// removes a tool and re-adds it later with different metadata should
			// compare against what was approved, not against nothing.
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

// Approve promotes the current observation to the approved baseline.
//
// This is the explicit operator step M1's exit criteria require: a baseline nobody
// approved is an inventory, not a control. Approving takes whatever is live right
// now, which is why it prints what it approved rather than doing it silently.
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
			// Promote the drifted version: the operator is approving what is
			// there now, having been shown it.
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

// Revoke marks a server's baseline unapproved without discarding it, so an
// operator can withdraw approval after an incident and have every listing report
// against a provisional baseline again.
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
