package intel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDomainSimilarity is the table for the metric that decides what enters the
// human queue and how it is ordered.
//
// What it pins, and why each row exists — the old implementation stripped the
// TLD off BOTH sides and returned a flat 0.85 for any substring containment, so
// `zeta.example`, `zeta.invalid` and the bare string `zeta`
// all scored 1.000 against zeta.test, and nearly every candidate scored exactly
// 0.85, making `ORDER BY similarity_score DESC` meaningless.
func TestDomainSimilarity(t *testing.T) {
	const threshold = ctSimilarityThreshold // 0.65 — at or above this it becomes a candidate
	tests := []struct {
		name    string
		cand    string
		monitor string
		want    float64
		why     string
	}{
		{"identical", "wonderszeta.test", "wonderszeta.test", 1.00, "the real certificate"},
		{"own subdomain", "login.zeta.test", "zeta.test", 1.00,
			"same registrable domain — only we can get this cert; ct.go drops it before scoring"},
		{"same label alt tld", "zeta.example", "zeta.test", simSameLabelAltTLD,
			"WAS 1.000: a different TLD is a different registration. Still a top squat signal, so it stays a candidate"},
		{"same label second alt tld", "zeta.invalid", "zeta.test", simSameLabelAltTLD, "same as zeta.example"},
		{"brand under two-label suffix", "zeta-fixture.co.uk", "zeta-fixture.test", simSameLabelAltTLD,
			"registrable label is zeta-fixture, not co — the suffix table earns its keep here"},
		{"homoglyph digit", "z3ta.test", "zeta.test", simHomoglyph, "visually identical in a URL bar"},
		{"homoglyph hyphen", "ze-ta.test", "zeta.test", simHomoglyph, "an inserted hyphen is near-invisible"},
		{"long brand homoglyph", "wondersz3ta.test", "wonderszeta.test", simHomoglyph, ""},
		{"affix suffix", "zetasecure.test", "zeta.test", simBrandAffix, ""},
		{"affix hyphen", "zeta-login.test", "zeta.test", simBrandAffix, ""},
		{"affix arg order swapped", "zeta.test", "zeta-secure.test", simBrandAffix,
			"containment signals must not depend on which side is the brand"},
		{"brand as subdomain label", "zeta.test.account-verify.example", "zeta.test", simBrandLabel,
			"the whole monitored domain hidden on the left of an attacker's suffix"},
		{"long brand embedded without a separator", "contosointakes.test", "contoso.test", simBrandEmbedded,
			"a 6+ char brand inside a longer word is not coincidence"},
		{"short brand embedded without a separator", "zetaladder.test", "zeta.test", 1 - 6.0/10,
			"the documented narrowing: 'zeta' is a plausible word fragment and this rule pulled in unrelated businesses at a flat 0.85"},
		{"brand as hyphen token", "zeta-box.test", "zeta.test", simBrandToken,
			"arbitrary neighbour word — weakest named signal, still queued rather than dropped"},
		{"transposition", "ztea.test", "zeta.test", 0.75,
			"one typo. Plain Levenshtein charged 2 for a swap and scored this 0.50 — below threshold"},
		{"one edit", "zetx.test", "zeta.test", 0.75, "the near-miss the CT partial-failure test relies on"},
		{"one edit long brand", "wondersztea.test", "wonderszeta.test", 1 - 1.0/11, ""},

		// Below the threshold on purpose: plausible benign look-alikes.
		{"different word containing brand", "www.testzeta.example", "zeta.test", 0.50,
			"testzeta is a different word, not a typo of zeta: 4 edits on an 8-char label"},
		{"compound word", "microzeta.test", "zeta.test", 1 - 5.0/9,
			"a compound word with a prefix, not a typo of the brand"},
		{"unrelated", "litware.test", "wonderszeta.test", 1 - 9.0/11, ""},

		// Not domains at all: values that come from certificate subject fields.
		{"certificate subject org", "zeta & zeta", "zeta.test", 0,
			"O= value, ingested verbatim as a 'domain'; now also rejected at ingest"},
		{"certificate subject street", "1 example street", "zeta.test", 0, "street= value"},
		{"bare label no tld", "zeta", "zeta.test", 0, "WAS 1.000 — the TLD strip made a bare word identical"},
		{"ip address", "192.168.1.1", "zeta.test", 0, "numeric suffix is not a public suffix"},
		{"empty", "", "wonderszeta.test", 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DomainSimilarity(tt.cand, tt.monitor)
			assert.InDelta(t, tt.want, got, 0.0001, "%s vs %s: %s", tt.cand, tt.monitor, tt.why)
			// The threshold is the actual behaviour under test: whether a human
			// ever sees this domain.
			if tt.want >= threshold {
				assert.GreaterOrEqual(t, got, threshold, "must remain a candidate")
			} else {
				assert.Less(t, got, threshold, "must not enter the human queue")
			}
		})
	}
}

// A flat score for everything is the failure mode that made the list unsortable:
// ordering is a product feature here ("ORDER BY similarity_score DESC"), so the
// tiers must actually separate.
func TestDomainSimilarityOrdersDistinctly(t *testing.T) {
	ordered := []string{
		"zeta.test",                        // 1.00 exact
		"z3ta.test",                        // 0.95 homoglyph
		"zeta.example",                     // 0.90 alt TLD
		"zeta-login.test",                  // 0.88 phishing affix
		"zeta.test.verify-account.example", // 0.86 brand as a label
		"zeta-box.test",                    // 0.80 brand as a token
		"ztea.test",                        // 0.75 one typo
		"microzeta.test",                   // 0.44 compound word (below threshold)
	}
	prev := 1.01
	for _, d := range ordered {
		got := DomainSimilarity(d, "zeta.test")
		assert.Less(t, got, prev, "%s (%.3f) must rank strictly below the previous tier (%.3f)", d, got, prev)
		prev = got
	}
}

func TestRegistrableLabel(t *testing.T) {
	tests := []struct {
		in         string
		wantLabel  string
		wantSuffix string
	}{
		{"zeta.test", "zeta", "test"},
		{"www.northwind.example", "northwind", "example"},
		{"*.zeta.test", "zeta", "test"},
		{"shop.zeta-fixture.co.uk", "zeta-fixture", "co.uk"},
		{"zeta-fixture.co.uk", "zeta-fixture", "co.uk"},
		{"zeta.xn--p1ai", "zeta", "xn--p1ai"}, // IDN TLD must still be scoreable
		{"zeta", "", ""},
		{"zeta & zeta", "", ""},
		{"192.168.1.1", "", ""},
		{"", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			label, suffix := registrableLabel(tt.in)
			assert.Equal(t, tt.wantLabel, label)
			assert.Equal(t, tt.wantSuffix, suffix)
		})
	}
}

func TestSplitDomain(t *testing.T) {
	tests := []struct {
		in       string
		wantBase string
		wantTLD  string
	}{
		{"wonderszeta.test", "wonderszeta", "test"},
		{"*.wonderszeta.test", "wonderszeta", "test"}, // wildcard stripped, then last dot
		{"sub.example.org", "sub.example", "org"},
		{"nodot", "nodot", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			base, tld := splitDomain(tt.in)
			assert.Equal(t, tt.wantBase, base)
			assert.Equal(t, tt.wantTLD, tld)
		})
	}
}

func TestCandidateIDStable(t *testing.T) {
	// Same inputs → same ID (idempotent ReplacingMergeTree key).
	a := CandidateID("evil-zeta.test", "zeta.test")
	b := CandidateID("evil-zeta.test", "zeta.test")
	assert.Equal(t, a, b)

	// Different inputs → different ID.
	c := CandidateID("unrelated.test", "zeta.test")
	assert.NotEqual(t, a, c)
}

func TestHeuristicTriage(t *testing.T) {
	tr := &Triager{}
	hits := []CTHit{
		{CommonName: "evil-zeta.test", MonitoredDomain: "zeta.test", Score: 0.9, Issuer: "Let's Encrypt"},
		{CommonName: "legit.test", MonitoredDomain: "zeta.test", Score: 0.66, Issuer: "DigiCert Inc"},
	}
	results := tr.heuristicTriage(hits)
	require.Len(t, results, 2)

	// High score + Let's Encrypt → phishing.
	assert.True(t, results[0].IsPhishing)
	assert.Greater(t, results[0].Confidence, float64(0.9))

	// Lower score + paid issuer → not flagged.
	assert.False(t, results[1].IsPhishing)
}
