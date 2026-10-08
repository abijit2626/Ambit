package prov

import (
	"fmt"
	"sync"
	"testing"

	"github.com/abijit2626/ambit/internal/event"
)

// feat builds a Features value out of already-digested strings. The package never
// sees a raw value or a key, so neither do its tests.
func feat(domains, urls []string) *event.Features {
	return &event.Features{Domains: domains, URLs: urls}
}

func TestMatchFindsAnIngestedFingerprint(t *testing.T) {
	s := New(Options{})
	s.Ingest("ev_page", feat([]string{"hmac:evil"}, []string{"hmac:evil-url"}), nil)

	edges := s.Match(feat([]string{"hmac:evil"}, nil))
	if len(edges) != 1 {
		t.Fatalf("got %d edges, want 1: %+v", len(edges), edges)
	}
	e := edges[0]
	if e.FromEvent != "ev_page" || e.MatchClass != ClassDomain || e.MatchDigest != "hmac:evil" {
		t.Errorf("edge = %+v, want domain hmac:evil from ev_page", e)
	}
	if e.Confidence != confDomain {
		t.Errorf("confidence = %v, want %v", e.Confidence, confDomain)
	}
}

func TestMatchReturnsNothingWhenNothingWasIngested(t *testing.T) {
	s := New(Options{})
	if got := s.Match(feat([]string{"hmac:x"}, nil)); got != nil {
		t.Errorf("empty set produced edges: %+v", got)
	}
	s.Ingest("ev1", feat([]string{"hmac:a"}, nil), nil)
	if got := s.Match(feat([]string{"hmac:b"}, nil)); got != nil {
		t.Errorf("disjoint fingerprints produced edges: %+v", got)
	}
	if got := s.Match(nil); got != nil {
		t.Errorf("nil features produced edges: %+v", got)
	}
}

// A class is part of the key. The same digest as a URL and as a domain is two
// different claims, and conflating them would let a domain match report URL
// confidence.
func TestClassIsPartOfTheKey(t *testing.T) {
	s := New(Options{})
	s.Ingest("ev1", &event.Features{Domains: []string{"hmac:same"}}, nil)
	if got := s.Match(&event.Features{URLs: []string{"hmac:same"}}); got != nil {
		t.Errorf("a URL fingerprint matched a domain ingest: %+v", got)
	}
}

func TestEdgesAreStrongestFirstAndDeterministic(t *testing.T) {
	s := New(Options{})
	s.Ingest("ev1", &event.Features{
		Domains:   []string{"hmac:d"},
		URLs:      []string{"hmac:u"},
		Emails:    []string{"hmac:e"},
		Shingles:  []string{"hmac:s"},
		HiEntropy: []string{"hmac:h"},
		IPs:       []string{"hmac:i"},
	}, nil)

	action := &event.Features{
		Domains:   []string{"hmac:d"},
		URLs:      []string{"hmac:u"},
		Emails:    []string{"hmac:e"},
		Shingles:  []string{"hmac:s"},
		HiEntropy: []string{"hmac:h"},
		IPs:       []string{"hmac:i"},
	}
	first := s.Match(action)
	if len(first) != 6 {
		t.Fatalf("got %d edges, want 6", len(first))
	}
	if first[0].MatchClass != ClassURL {
		t.Errorf("strongest edge is %q, want url: flatten takes the first one as the strongest", first[0].MatchClass)
	}
	if last := first[len(first)-1]; last.MatchClass != ClassShingle {
		t.Errorf("weakest edge is %q, want shingle (advisory only)", last.MatchClass)
	}
	for i := 1; i < len(first); i++ {
		if first[i].Confidence > first[i-1].Confidence {
			t.Errorf("edge %d (%v) outranks edge %d (%v)", i, first[i].Confidence, i-1, first[i-1].Confidence)
		}
	}
	// Same input, byte-identical output.
	again := s.Match(action)
	for i := range first {
		if first[i] != again[i] {
			t.Errorf("run 2 edge %d = %+v, run 1 = %+v: output must be deterministic", i, again[i], first[i])
		}
	}
}

// The earliest ingest is the one that introduced the value. A later ingest that
// repeats it must not steal the attribution, or an edge would point at the last page
// that mentioned the value and not the first.
func TestFirstIngestKeepsTheAttribution(t *testing.T) {
	s := New(Options{})
	s.Ingest("ev_first", feat([]string{"hmac:d"}, nil), nil)
	s.Ingest("ev_second", feat([]string{"hmac:d"}, nil), nil)

	edges := s.Match(feat([]string{"hmac:d"}, nil))
	if len(edges) != 1 || edges[0].FromEvent != "ev_first" {
		t.Fatalf("edges = %+v, want one edge from ev_first", edges)
	}
}

// The novelty rule, own-input half. A page the agent was told to fetch names its own
// host; that is not the page introducing it.
func TestOwnInputIsNotIntroducedByTheResult(t *testing.T) {
	s := New(Options{})
	own := feat([]string{"hmac:docs"}, []string{"hmac:docs-url"})
	result := feat([]string{"hmac:docs", "hmac:other"}, []string{"hmac:docs-url", "hmac:other-url"})

	if got := s.Ingest("ev1", result, own); got.Stored != 2 || got.Skipped != 2 {
		t.Errorf("ingest = %+v, want 2 stored (what the page introduced) and 2 skipped", got)
	}
	if got := s.Match(feat([]string{"hmac:docs"}, []string{"hmac:docs-url"})); got != nil {
		t.Errorf("the host the agent was sent to produced an edge: %+v", got)
	}
	if got := s.Match(feat(nil, []string{"hmac:other-url"})); len(got) != 1 {
		t.Errorf("a URL the page introduced must still match, got %+v", got)
	}
	if st := s.Stats(); st.SkippedKnown != 2 {
		t.Errorf("SkippedKnown = %d, want 2", st.SkippedKnown)
	}
}

// The cost of the rule, pinned so nobody believes it away. A page that points the
// agent back at the host it came from draws no DOMAIN edge, but a spelled-out URL
// still draws a URL edge.
func TestOwnHostDrawsNoDomainEdgeButANewURLStillDoes(t *testing.T) {
	s := New(Options{})
	own := feat([]string{"hmac:evil"}, []string{"hmac:evil-readme"})
	result := feat([]string{"hmac:evil"}, []string{"hmac:evil-readme", "hmac:evil-collect"})
	s.Ingest("ev1", result, own)

	if got := s.Match(feat([]string{"hmac:evil"}, nil)); got != nil {
		t.Errorf("domain edge appeared for a host the agent already knew: %+v", got)
	}
	got := s.Match(feat([]string{"hmac:evil"}, []string{"hmac:evil-collect"}))
	if len(got) != 1 || got[0].MatchClass != ClassURL {
		t.Errorf("edges = %+v, want exactly the url edge for the collection endpoint", got)
	}
}

// The novelty rule, user half.
func TestDeclaredByTheUserIsNotIntroducedByAnIngest(t *testing.T) {
	s := New(Options{})
	s.Declare(feat([]string{"hmac:mine"}, nil))
	s.Ingest("ev1", feat([]string{"hmac:mine", "hmac:theirs"}, nil), nil)

	if got := s.Match(feat([]string{"hmac:mine"}, nil)); got != nil {
		t.Errorf("a domain the user typed produced an edge: %+v", got)
	}
	if got := s.Match(feat([]string{"hmac:theirs"}, nil)); len(got) != 1 {
		t.Errorf("a domain the ingest introduced must match, got %+v", got)
	}
}

// Declare is not retroactive. The agent already met the value in untrusted content;
// the user typing it afterwards does not change where it was first met.
func TestDeclareDoesNotRewriteHistory(t *testing.T) {
	s := New(Options{})
	s.Ingest("ev1", feat([]string{"hmac:d"}, nil), nil)
	s.Declare(feat([]string{"hmac:d"}, nil))
	if got := s.Match(feat([]string{"hmac:d"}, nil)); len(got) != 1 {
		t.Errorf("got %+v, want the earlier ingest to still match", got)
	}
}

// A trusted domain is a down-weight, not a suppression: a trusted code host is also
// an exfiltration sink, and silently dropping it would blind the layer to
// s1ngularity-shaped attacks.
func TestCommonDomainIsDownweightedNotDropped(t *testing.T) {
	s := New(Options{CommonDomains: map[string]bool{"hmac:github": true}})
	s.Ingest("ev1", &event.Features{
		Domains: []string{"hmac:github", "hmac:evil"},
		URLs:    []string{"hmac:github-gist"},
	}, nil)

	got := s.Match(&event.Features{Domains: []string{"hmac:github"}})
	if len(got) != 1 {
		t.Fatalf("a trusted domain must still produce an edge, got %+v", got)
	}
	if got[0].Confidence != confCommonDomain {
		t.Errorf("confidence = %v, want the down-weighted %v", got[0].Confidence, confCommonDomain)
	}
	if got[0].Confidence >= confDomain {
		t.Error("a trusted domain must rank below an ordinary one")
	}

	// The full URL on the same trusted host is where the attack is caught, and is
	// not down-weighted.
	got = s.Match(&event.Features{URLs: []string{"hmac:github-gist"}})
	if len(got) != 1 || got[0].Confidence != confURL {
		t.Errorf("url on a trusted host = %+v, want full url confidence", got)
	}
	// An ordinary domain keeps the ordinary weight.
	got = s.Match(&event.Features{Domains: []string{"hmac:evil"}})
	if len(got) != 1 || got[0].Confidence != confDomain {
		t.Errorf("ordinary domain = %+v, want confidence %v", got, confDomain)
	}
}

func TestPerIngestCapKeepsSpecificClassesAndCountsTheRest(t *testing.T) {
	s := New(Options{MaxPerIngest: 3})
	f := &event.Features{
		URLs:     []string{"hmac:u1", "hmac:u2"},
		Domains:  []string{"hmac:d1", "hmac:d2"},
		Shingles: []string{"hmac:s1", "hmac:s2", "hmac:s3"},
	}
	got := s.Ingest("ev1", f, nil)
	if got.Stored != 3 || got.Truncated != 4 {
		t.Fatalf("ingest = %+v, want 3 stored and 4 truncated: truncation must be visible", got)
	}
	if st := s.Stats(); st.TruncatedPerIngest != 4 {
		t.Errorf("Stats.TruncatedPerIngest = %d, want 4", st.TruncatedPerIngest)
	}
	if s.Match(&event.Features{URLs: []string{"hmac:u1", "hmac:u2"}}) == nil {
		t.Error("URLs are the most specific class and must survive truncation")
	}
	if s.Match(&event.Features{Shingles: []string{"hmac:s1"}}) != nil {
		t.Error("advisory shingles must be what truncation drops")
	}
}

// One enormous result must not evict everything the session ingested earlier.
func TestOneLargeIngestCannotFlushTheSet(t *testing.T) {
	s := New(Options{MaxPerIngest: 4, MaxFingerprints: 100})
	s.Ingest("ev_early", feat([]string{"hmac:early"}, nil), nil)

	big := &event.Features{}
	for i := 0; i < 5000; i++ {
		big.HiEntropy = append(big.HiEntropy, fmt.Sprintf("hmac:noise%d", i))
	}
	s.Ingest("ev_flood", big, nil)

	if s.Match(feat([]string{"hmac:early"}, nil)) == nil {
		t.Error("an earlier ingest was lost to one oversized result")
	}
}

func TestSessionCapEvictsOldestAndCountsIt(t *testing.T) {
	s := New(Options{MaxFingerprints: 3})
	var evicted int
	for i := 1; i <= 5; i++ {
		evicted += s.Ingest(fmt.Sprintf("ev%d", i), feat([]string{fmt.Sprintf("hmac:d%d", i)}, nil), nil).Evicted
	}
	if evicted != 2 {
		t.Errorf("IngestResult.Evicted summed to %d, want 2", evicted)
	}
	st := s.Stats()
	if st.Live != 3 {
		t.Errorf("Live = %d, want 3 (the cap)", st.Live)
	}
	if st.Evicted != 2 {
		t.Errorf("Evicted = %d, want 2", st.Evicted)
	}
	if s.Match(feat([]string{"hmac:d1"}, nil)) != nil {
		t.Error("the oldest fingerprint should have been evicted")
	}
	if s.Match(feat([]string{"hmac:d5"}, nil)) == nil {
		t.Error("the newest fingerprint should be present")
	}
}

func TestMaxEdgesBoundsAnActionsReport(t *testing.T) {
	s := New(Options{MaxEdges: 2})
	f := &event.Features{Domains: []string{"hmac:a", "hmac:b", "hmac:c", "hmac:d"}}
	s.Ingest("ev1", f, nil)
	if got := s.Match(f); len(got) != 2 {
		t.Errorf("got %d edges, want the cap of 2", len(got))
	}
}

func TestIngestIgnoresEmptyInput(t *testing.T) {
	s := New(Options{})
	if s.Ingest("ev1", nil, nil).Stored != 0 || s.Ingest("ev1", &event.Features{}, nil).Stored != 0 {
		t.Error("an empty result registered something")
	}
	if s.Ingest("", feat([]string{"hmac:d"}, nil), nil).Stored != 0 {
		t.Error("an ingest with no event id registered something: an edge could not point anywhere")
	}
	if s.Stats().Ingests != 0 {
		t.Errorf("Ingests = %d, want 0", s.Stats().Ingests)
	}
}

func TestTaintReportsOnlyTheFirstOccurrence(t *testing.T) {
	s := New(Options{})
	if !s.AddTaint("mcp:github") {
		t.Error("first label should be new")
	}
	if s.AddTaint("mcp:github") {
		t.Error("a repeated label must not be reported as new: the caller emits only transitions")
	}
	if s.AddTaint("") {
		t.Error("an empty label must be ignored")
	}
}

func TestRefsAreDistinctAndOrdered(t *testing.T) {
	edges := []event.Edge{{FromEvent: "b"}, {FromEvent: "a"}, {FromEvent: "b"}, {FromEvent: ""}}
	got := Refs(edges)
	if len(got) != 2 || got[0] != "b" || got[1] != "a" {
		t.Errorf("Refs = %v, want [b a]", got)
	}
	if Refs(nil) != nil {
		t.Error("no edges, no refs")
	}
}

// The hook endpoint serves requests concurrently and two can be for one session.
// Run under -race.
func TestConcurrentUseIsSafe(t *testing.T) {
	s := New(Options{MaxFingerprints: 64})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				d := fmt.Sprintf("hmac:g%d-%d", g, i)
				s.Declare(feat([]string{d + "-decl"}, nil))
				s.Ingest(fmt.Sprintf("ev%d-%d", g, i), feat([]string{d}, nil), nil)
				s.Match(feat([]string{d}, nil))
				s.AddTaint(fmt.Sprintf("t%d", i%5))
				s.Stats()
			}
		}(g)
	}
	wg.Wait()
}
