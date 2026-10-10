package prov

import (
	"sort"
	"sync"

	"github.com/abijit2626/ambit/internal/event"
)

const (
	ClassURL       = "url"
	ClassIBAN      = "iban"
	ClassEmail     = "email"
	ClassHiEntropy = "hi_entropy"
	ClassIP        = "ip"
	ClassDomain    = "domain"
	ClassShingle   = "shingle"
)

const (
	confURL = 0.95

	confIBAN      = 0.95
	confEmail     = 0.90
	confHiEntropy = 0.90
	confIP        = 0.80
	confDomain    = 0.80
	confShingle   = 0.30

	confCommonDomain = 0.40
)

const (
	DefaultMaxPerIngest = 256

	DefaultMaxFingerprints = 8192

	DefaultMaxEdges = 16
)

type Options struct {
	MaxPerIngest    int
	MaxFingerprints int
	MaxEdges        int

	CommonDomains map[string]bool

	Exclude map[string]bool
}

type key struct {
	class  string
	digest string
}

type Set struct {
	mu   sync.Mutex
	opts Options

	ingested map[key]string

	order []key

	declared map[key]bool
	taint    map[string]bool

	stats Stats
}

type Stats struct {
	Ingests int64

	Registered int64

	SkippedKnown int64

	TruncatedPerIngest int64

	Evicted int64

	Edges int64

	Live int
}

func New(opts Options) *Set {
	if opts.MaxPerIngest <= 0 {
		opts.MaxPerIngest = DefaultMaxPerIngest
	}
	if opts.MaxFingerprints <= 0 {
		opts.MaxFingerprints = DefaultMaxFingerprints
	}
	if opts.MaxEdges <= 0 {
		opts.MaxEdges = DefaultMaxEdges
	}
	return &Set{
		opts:     opts,
		ingested: map[key]string{},
		declared: map[key]bool{},
		taint:    map[string]bool{},
	}
}

func candidates(f *event.Features) []key {
	if f == nil {
		return nil
	}
	n := len(f.URLs) + len(f.IBANs) + len(f.Emails) + len(f.HiEntropy) + len(f.IPs) + len(f.Domains) + len(f.Shingles)
	out := make([]key, 0, n)
	add := func(class string, ds []string) {
		for _, d := range ds {
			if d != "" {
				out = append(out, key{class, d})
			}
		}
	}
	add(ClassURL, f.URLs)
	add(ClassIBAN, f.IBANs)
	add(ClassEmail, f.Emails)
	add(ClassHiEntropy, f.HiEntropy)
	add(ClassIP, f.IPs)
	add(ClassDomain, f.Domains)
	add(ClassShingle, f.Shingles)
	return out
}

func (s *Set) keys(f *event.Features) []key {
	ks := candidates(f)
	if len(s.opts.Exclude) == 0 {
		return ks
	}
	kept := ks[:0:0]
	for _, k := range ks {
		if !s.opts.Exclude[k.class] {
			kept = append(kept, k)
		}
	}
	return kept
}

func (s *Set) Declare(f *event.Features) {
	ks := s.keys(f)
	if len(ks) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range ks {

		if len(s.declared) >= s.opts.MaxFingerprints {
			return
		}
		s.declared[k] = true
	}
}

type IngestResult struct {
	Stored    int
	Skipped   int
	Truncated int
	Evicted   int
}

func (s *Set) Ingest(eventID string, result, own *event.Features) IngestResult {
	var res IngestResult
	ks := s.keys(result)
	if len(ks) == 0 || eventID == "" {
		return res
	}
	ownSet := map[key]bool{}
	for _, k := range s.keys(own) {
		ownSet[k] = true
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, k := range ks {
		if ownSet[k] || s.declared[k] {
			res.Skipped++
			continue
		}
		if _, seen := s.ingested[k]; seen {
			continue
		}
		if res.Stored >= s.opts.MaxPerIngest {

			res.Truncated++
			continue
		}
		res.Evicted += s.evictLocked()
		s.ingested[k] = eventID
		s.order = append(s.order, k)
		res.Stored++
	}
	s.stats.SkippedKnown += int64(res.Skipped)
	s.stats.TruncatedPerIngest += int64(res.Truncated)
	s.stats.Evicted += int64(res.Evicted)
	if res.Stored > 0 {
		s.stats.Ingests++
		s.stats.Registered += int64(res.Stored)
	}
	return res
}

func (s *Set) evictLocked() int {
	n := 0
	for len(s.ingested) >= s.opts.MaxFingerprints && len(s.order) > 0 {
		old := s.order[0]
		s.order = s.order[1:]
		if _, ok := s.ingested[old]; ok {
			delete(s.ingested, old)
			n++
		}
	}
	return n
}

func (s *Set) Match(action *event.Features) []event.Edge {
	ks := s.keys(action)
	if len(ks) == 0 {
		return nil
	}

	s.mu.Lock()
	var edges []event.Edge
	for _, k := range ks {
		from, ok := s.ingested[k]
		if !ok {
			continue
		}
		edges = append(edges, event.Edge{
			FromEvent:   from,
			MatchClass:  k.class,
			MatchDigest: k.digest,
			Confidence:  s.confidence(k),
		})
	}
	s.mu.Unlock()

	if len(edges) == 0 {
		return nil
	}
	sort.SliceStable(edges, func(i, j int) bool {
		a, b := edges[i], edges[j]
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		if a.MatchClass != b.MatchClass {
			return a.MatchClass < b.MatchClass
		}
		return a.MatchDigest < b.MatchDigest
	})
	if len(edges) > s.opts.MaxEdges {
		edges = edges[:s.opts.MaxEdges]
	}

	s.mu.Lock()
	s.stats.Edges += int64(len(edges))
	s.mu.Unlock()
	return edges
}

func (s *Set) confidence(k key) float64 {
	switch k.class {
	case ClassURL:
		return confURL
	case ClassIBAN:
		return confIBAN
	case ClassEmail:
		return confEmail
	case ClassHiEntropy:
		return confHiEntropy
	case ClassIP:
		return confIP
	case ClassDomain:
		if s.opts.CommonDomains[k.digest] {
			return confCommonDomain
		}
		return confDomain
	}
	return confShingle
}

func (s *Set) AddTaint(label string) bool {
	if label == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.taint[label] {
		return false
	}
	s.taint[label] = true
	return true
}

func (s *Set) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.Live = len(s.ingested)
	return st
}

func Refs(edges []event.Edge) []string {
	if len(edges) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range edges {
		if e.FromEvent == "" || seen[e.FromEvent] {
			continue
		}
		seen[e.FromEvent] = true
		out = append(out, e.FromEvent)
	}
	return out
}
