package features

import (
	"testing"
)

// Registry examples, one per length class worth covering.
var validIBANs = []string{
	"GB29NWBK60161331926819",
	"DE89370400440532013000", // entropy 2.94: the high-entropy class misses this one
	"CH9300762011623852957",
	"NL91ABNA0417164300",
	"BE68539007547034",
	"FR1420041010050500013M02606",
	"NO9386011117947",
	"SE3550000000054910000003",
}

func TestValidIBANAcceptsRegistryExamples(t *testing.T) {
	for _, s := range validIBANs {
		if !validIBAN(s) {
			t.Errorf("%s rejected", s)
		}
	}
}

func TestValidIBANRejects(t *testing.T) {
	for s, why := range map[string]string{
		"US133000000121212121212": "the US issues no IBANs (AgentDojo's attacker account)",
		"DE89370400440532013001":  "one digit changed, so the check digits fail",
		// These two pass mod-97 and fail only on length, so they test the length rule.
		// Cases that merely add or drop a character fail the checksum first and would
		// pass even with the length check removed.
		"DE5137040044053201300":    "valid check digits, but a German IBAN is 22 characters, not 21",
		"GB31NWBK601613319268190":  "valid check digits, but a British IBAN is 22 characters, not 23",
		"AB12CDEFGHIJKLMNOP":       "not a country",
		"DE00370400440532013000":   "check digits 00 can never verify",
		"GB29NWBK60161331926819!!": "not alphanumeric",
	} {
		if validIBAN(s) {
			t.Errorf("%s accepted: %s", s, why)
		}
	}
}

func TestIBANsFindsPrintedCompactAndLowercaseForms(t *testing.T) {
	cases := map[string]string{
		"pay to DE89 3704 0044 0532 0130 00 today":      "DE89370400440532013000",
		"pay to DE89370400440532013000.":                "DE89370400440532013000",
		"iban: de89 3704 0044 0532 0130 00":             "DE89370400440532013000",
		"(GB29NWBK60161331926819)":                      "GB29NWBK60161331926819",
		"recipient=CH9300762011623852957&amount=10":     "CH9300762011623852957",
		"send to BE68 5390 0754 7034 from your account": "BE68539007547034",
	}
	for text, want := range cases {
		got := ibans(text)
		if !got[want] || len(got) != 1 {
			t.Errorf("%q: got %v, want exactly %s", text, keys(got), want)
		}
	}
}

// The printed form ends where the IBAN ends, but a following four-letter word looks like
// one more group. The match has to be trimmed back to the valid prefix, not dropped.
func TestIBANsTrimsATrailingWordThatLooksLikeAGroup(t *testing.T) {
	got := ibans("BE68 5390 0754 7034 from")
	if !got["BE68539007547034"] {
		t.Errorf("got %v; a valid IBAN followed by a four-letter word was lost", keys(got))
	}
}

func TestIBANsIgnoresLookalikes(t *testing.T) {
	for _, text := range []string{
		"order AB12CDEF34567890XYZ shipped",
		"transfer to US133000000121212121212",
		"commit 4c3a7442fa155e11cd1059373070330be9d7771a",
		"build DE12 3456 7890 1234 5678 90 failed", // IBAN-shaped, checksum fails
	} {
		if got := ibans(text); len(got) != 0 {
			t.Errorf("%q: matched %v", text, keys(got))
		}
	}
}

// One account must be one fingerprint, however it was typed, or a page that prints it with
// spaces and a payment that sends it compact would never match.
func TestExtractDigestsEveryFormOfAnIBANTheSame(t *testing.T) {
	e := New(testKey)
	a := e.Extract("pay DE89 3704 0044 0532 0130 00")
	b := e.Extract(`{"recipient":"de89370400440532013000"}`)
	if len(a.IBANs) != 1 || len(b.IBANs) != 1 || a.IBANs[0] != b.IBANs[0] {
		t.Errorf("printed %v vs compact %v: want one identical digest", a.IBANs, b.IBANs)
	}
	if a.IBANs[0] != e.Digest("DE89370400440532013000") {
		t.Error("the IBAN digest is not the digest of the normalized compact form")
	}
}

// The reason the class exists: this IBAN is below the high-entropy floor.
func TestExtractCatchesAnIBANTheHighEntropyClassMisses(t *testing.T) {
	e := New(testKey)
	f := e.Extract("DE89370400440532013000")
	if len(f.HiEntropy) != 0 {
		t.Fatalf("test premise broken: the high-entropy class now catches it: %v", f.HiEntropy)
	}
	if len(f.IBANs) != 1 {
		t.Errorf("IBANs = %v, want the IBAN", f.IBANs)
	}
}

func TestNotableFingerprintPrefersAnIBAN(t *testing.T) {
	e := New(testKey)
	f := e.Extract("contact ops@example.com, pay GB29NWBK60161331926819 via https://bank.example.com")
	if got := NotableFingerprint(f); got != f.IBANs[0] {
		t.Errorf("notable = %s, want the IBAN digest %s", got, f.IBANs[0])
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
