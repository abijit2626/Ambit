// Package prov is the provenance engine's per-session core: the set of
// fingerprints that entered a session through untrusted ingest, and the
// intersection of an action's own fingerprints against it.
//
// This is docs/03-detection.md Layer 2b, and the design says in so many words that
// it is an explicitly UNSOUND approximation. CaMeL tracks a dataflow graph through
// an interpreter we do not control; Claude Code is a black box that emits events.
// What this package can say is "a value the agent is now acting on also appeared in
// content it ingested earlier from an untrusted source". It cannot say the value
// was copied from there (the model may have reconstructed it, or the user may have
// supplied it too), and a paraphrase defeats it entirely. Nothing downstream may
// treat an edge as proof; it is evidence a reviewer can read.
//
// The intersection runs here, in memory, and only the resulting edge leaves. The raw
// set never crosses to the SIEM and is never written to the spool: it is live
// session state, and shipping every fingerprint of every ingest would be the
// firehose docs/04-data-model.md exists to prevent.
//
// # What counts as an ingest
//
// The caller decides. This package registers whatever it is handed; the collector
// hands it the results of tool calls whose own Rule-of-Two bit A is set, so the
// definition of "untrusted input" stays in internal/r2 and is not restated here.
//
// # Novelty
//
// Ingest registers only fingerprints the content INTRODUCED. A value the user typed
// in a prompt (Declare), or that the agent itself passed in the very call that
// fetched the content (the own argument to Ingest), is not introduced by that
// content: the page at https://docs.example.com/x naturally mentions
// docs.example.com, and without this rule every follow-up request to a host the
// agent was told to read would be an edge. This is a deliberate precision trade, and
// it has a cost that the doc comment on Ingest states.
package prov

import (
	"sort"
	"sync"

	"github.com/abijit2626/ambit/internal/event"
)

// Match classes. They are the strings carried in event.Edge.MatchClass and,
// flattened, in prov_edge_class; a Wazuh rule can key on them.
const (
	ClassURL       = "url"
	ClassIBAN      = "iban"
	ClassEmail     = "email"
	ClassHiEntropy = "hi_entropy"
	ClassIP        = "ip"
	ClassDomain    = "domain"
	ClassShingle   = "shingle"
)

// Confidence by class, from docs/03: domain, URL and high-entropy matches are far
// more specific than n-gram matches, and n-gram matches are advisory only.
//
// A URL outranks a bare domain because the same domain recurs for innocent
// reasons (a shared CDN, a package registry) while the same full URL appearing in
// ingested content and then in an action is rarely coincidence.
const (
	confURL = 0.95
	// confIBAN matches confURL: a checksum-valid IBAN is as specific as a full URL, and
	// the same account number in ingested content and then in a payment is the
	// redirected-payment attack.
	confIBAN      = 0.95
	confEmail     = 0.90
	confHiEntropy = 0.90
	confIP        = 0.80
	confDomain    = 0.80
	confShingle   = 0.30

	// confCommonDomain applies to a domain match when the operator has listed the
	// domain as one they trust for content. It is a DOWN-WEIGHT, not a
	// suppression. A trusted domain is also a perfectly good exfiltration sink —
	// s1ngularity wrote its loot to public repositories on github.com — so
	// dropping those matches would hide the very case the layer exists for. The
	// full-URL class is unaffected, which is where that attack is caught.
	confCommonDomain = 0.40
)

// Defaults for the bounds. Each exists because the alternative is unbounded growth
// on the hook path of a long-lived daemon, and each is reported through Stats when
// it bites, because a cap that truncates silently turns "no edge" into a claim the
// engine cannot back.
const (
	// DefaultMaxPerIngest bounds what one tool result may register. Without it a
	// single large page could fill the session's set and evict everything the
	// session ingested before it.
	DefaultMaxPerIngest = 256
	// DefaultMaxFingerprints bounds the whole session.
	DefaultMaxFingerprints = 8192
	// DefaultMaxEdges bounds the edges one action reports. The flattened event
	// carries only the strongest and a count, so this limits spool size, not what
	// Wazuh sees.
	DefaultMaxEdges = 16
)

// Options configure a Set. The zero value is usable and uses the defaults.
type Options struct {
	MaxPerIngest    int
	MaxFingerprints int
	MaxEdges        int
	// CommonDomains holds keyed digests of registrable domains the operator trusts
	// for content. A domain-class match on one of them is down-weighted, not
	// dropped; see confCommonDomain. Digests, not names: this package holds no
	// key, and the caller already computes them for its own trusted-domain check.
	CommonDomains map[string]bool
}

type key struct {
	class  string
	digest string
}

// Set is one session's provenance state. It is safe for concurrent use: the hook
// endpoint serves requests concurrently, and two for the same session can overlap.
type Set struct {
	mu   sync.Mutex
	opts Options

	// ingested maps a fingerprint to the event that first introduced it. First wins
	// and is never refreshed: the earliest ingest is the one that "introduced" the
	// value, and it is the one a reviewer needs to open.
	ingested map[key]string
	// order is insertion order, for eviction when the session cap is reached.
	order []key
	// declared holds what the user themselves wrote.
	declared map[key]bool
	taint    map[string]bool

	stats Stats
}

// Stats is the engine's account of itself. The truncation counters are the point:
// they are how an operator learns that "no edge" was produced by a set that had
// stopped being complete.
type Stats struct {
	// Ingests counts calls to Ingest that registered at least one fingerprint.
	Ingests int64
	// Registered counts fingerprints stored.
	Registered int64
	// SkippedKnown counts fingerprints not stored because the user or the agent had
	// already supplied them (the novelty rule).
	SkippedKnown int64
	// TruncatedPerIngest counts fingerprints dropped because one result exceeded
	// MaxPerIngest.
	TruncatedPerIngest int64
	// Evicted counts fingerprints discarded to stay within MaxFingerprints.
	Evicted int64
	// Edges counts edges returned by Match.
	Edges int64
	// Live is the current number of stored fingerprints.
	Live int
}

// New returns an empty Set.
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

// candidates flattens a Features value into keyed fingerprints in descending order
// of specificity. The order matters for exactly one reason: when MaxPerIngest
// truncates, it should be the advisory shingles that are lost and not the URLs.
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

// Declare records fingerprints the user themselves wrote, so a later ingest that
// merely repeats them does not register as having introduced them. It affects
// future Ingest calls only: a value already ingested stays ingested, because the
// user typing it afterwards is a fact about the future, not about where the
// agent first met it.
func (s *Set) Declare(f *event.Features) {
	ks := candidates(f)
	if len(ks) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range ks {
		// Bounded by the same cap as the ingested set: prompts are user-sized, but
		// a pasted log is not, and this map must not be the unbounded one.
		if len(s.declared) >= s.opts.MaxFingerprints {
			return
		}
		s.declared[k] = true
	}
}

// IngestResult is what one Ingest call did. The collector sums these across
// sessions into its own counters, so truncation stays visible after the session's
// Set is gone.
type IngestResult struct {
	Stored    int
	Skipped   int // already supplied by the user or the agent: the novelty rule
	Truncated int // dropped because the result exceeded MaxPerIngest
	Evicted   int // older fingerprints discarded to stay within MaxFingerprints
}

// Ingest registers the fingerprints in result as introduced by the event eventID.
//
// own is the features of the tool INPUT of the same call. Anything the agent passed
// in is excluded, for the reason in the package comment. The cost: a hostile page
// that tells the agent to contact the very host it was fetched from introduces
// nothing new at the DOMAIN level, so that domain draws no domain edge. It still
// draws a URL edge when the page spells out a full URL, which is how an
// instruction to POST somewhere is nearly always written, and a destination the
// agent was already talking to is not the exfiltration shape this layer targets.
//
// Fingerprints already ingested keep their original event as the source.
func (s *Set) Ingest(eventID string, result, own *event.Features) IngestResult {
	var res IngestResult
	ks := candidates(result)
	if len(ks) == 0 || eventID == "" {
		return res
	}
	ownSet := map[key]bool{}
	for _, k := range candidates(own) {
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
			// Counted per dropped fingerprint, so the operator can tell a result
			// that overflowed by three from one that overflowed by three thousand.
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

// evictLocked makes room for one more fingerprint, discarding the oldest.
//
// Oldest-first is the better of two imperfect options. Refusing new entries would
// let an early large ingest blind the engine to everything after it; evicting
// oldest lets a flood push out older ones. Neither is sound, which is why eviction
// is counted in Stats. The per-ingest cap is what keeps a flood from being cheap.
//
// The queue is advanced by reslicing. That does not leak: append reallocates at
// capacity and copies only the live tail, so the backing array stays proportional
// to the live set.
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

// Match intersects an action's fingerprints with the session's ingested set and
// returns one edge per matching fingerprint, strongest first. It returns nil when
// nothing matched, which is the overwhelmingly common case.
//
// Ordering is by confidence descending, then class and digest, so the same input
// yields byte-identical output: the flattened event takes the first edge as the
// strongest, and a test pins that.
func (s *Set) Match(action *event.Features) []event.Edge {
	ks := candidates(action)
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

// AddTaint records a session taint label (Layer 2a) and reports whether it was new.
// The caller emits a label only on the event that introduced it, the same
// transition-only discipline Rule-of-Two uses, so a long session does not make
// every later event wider.
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

// Stats returns a snapshot.
func (s *Set) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.Live = len(s.ingested)
	return st
}

// Refs returns the distinct source events of edges, in first-seen order. It is the
// provenance.ingest_refs field: rich-event only, resolvable from the spool, never
// flattened.
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
