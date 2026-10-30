// Package egress keeps the set of network destinations this endpoint has contacted, so that the first
// contact with a new one can be reported. It is the profile D9 is missing: the detector rules see one
// command or one denial at a time, and cannot tell a destination the endpoint always uses from one it has
// never touched.
//
// The profile holds keyed digests, never hostnames. Each digest is the same HMAC the collector uses for
// every other destination field, so a copy of the file reveals nothing about internal hosts.
package egress

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/abijit2626/ambit/internal/features"
	"github.com/abijit2626/ambit/internal/fsperm"
)

// DefaultMaxDestinations bounds one endpoint's profile. A developer machine reaches a few hundred
// registrable domains; reaching the bound means something is walking the network, and the profile stops
// learning rather than growing without limit. Overflow is counted so the operator can see it.
const DefaultMaxDestinations = 4096

// Profile is the destinations seen so far. It is safe for concurrent use. Its file is append-only, one
// digest per line, so recording a destination never rewrites the rest.
type Profile struct {
	mu       sync.Mutex
	path     string
	seen     map[string]struct{}
	max      int
	overflow int64
}

// Load reads the profile at path. A missing file is an empty profile, the first run on this endpoint. A
// file that cannot be read or holds a line that is not a digest is an error: the caller should run
// without a profile and say so, rather than quietly learn from a damaged one.
func Load(path string, max int) (*Profile, error) {
	if path == "" {
		return nil, errors.New("egress: profile path is required")
	}
	if max < 1 {
		max = DefaultMaxDestinations
	}
	p := &Profile{path: path, seen: map[string]struct{}{}, max: max}
	if err := fsperm.PrivateDir(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("egress: create %s: %w", filepath.Dir(path), err)
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, fmt.Errorf("egress: open profile: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 256), 256)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, features.DigestPrefix) {
			return nil, fmt.Errorf("egress: profile %s has a line that is not a digest", path)
		}
		if len(p.seen) < p.max {
			p.seen[line] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("egress: read profile: %w", err)
	}
	return p, nil
}

// NewMemory is a profile that is never written to disk, for replay, where every scenario starts on an
// endpoint that has contacted nothing.
func NewMemory(max int) *Profile {
	if max < 1 {
		max = DefaultMaxDestinations
	}
	return &Profile{seen: map[string]struct{}{}, max: max}
}

// IsNew reports whether digest is a destination this profile has not recorded. It changes nothing, so a
// caller can report the destination and only then Record it: a report the sink refused is not learned,
// and the next contact reports it again.
//
// Two contacts racing before either is recorded can both report the same destination. That duplicate is
// accepted over holding a lock across the sink write.
func (p *Profile) IsNew(digest string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.seen[digest]; ok {
		return false
	}
	if len(p.seen) >= p.max {
		p.overflow++
		return false
	}
	return true
}

// Record adds digest to the profile and appends it to the file. Recording a digest already present does
// nothing.
func (p *Profile) Record(digest string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.seen[digest]; ok {
		return nil
	}
	if len(p.seen) >= p.max {
		p.overflow++
		return nil
	}
	if p.path == "" {
		p.seen[digest] = struct{}{}
		return nil
	}
	f, err := os.OpenFile(p.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("egress: open profile: %w", err)
	}
	_, werr := io.WriteString(f, digest+"\n")
	cerr := f.Close()
	if werr != nil {
		return fmt.Errorf("egress: append to profile: %w", werr)
	}
	if cerr != nil {
		return fmt.Errorf("egress: close profile: %w", cerr)
	}
	p.seen[digest] = struct{}{}
	return nil
}

// Size is how many destinations the profile holds.
func (p *Profile) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.seen)
}

// Overflow is how many contacts with an unlearned destination were turned away because the profile was
// full. It counts contacts, not distinct destinations: the profile cannot tell those apart once full.
func (p *Profile) Overflow() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.overflow
}
