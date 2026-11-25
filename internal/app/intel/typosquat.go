package intel

import (
	"strings"
	"unicode/utf8"
)

// commonAffixes are squatting prefixes and suffixes added to brand names.
var commonAffixes = struct {
	prefixes []string
	suffixes []string
}{
	prefixes: []string{"my", "the", "get", "app", "go"},
	suffixes: []string{"login", "secure", "auth", "app", "portal", "web", "online", "account"},
}

// Similarity tiers. Every tier is ≥ ctSimilarityThreshold (0.65) except the
// graded edit-distance fallback, so a named signal always keeps a candidate;
// only the graded measure can drop one.
//
// The tiers are ordered by how strong the squatting evidence is, which is also
// what makes `ORDER BY similarity_score DESC` mean something. A FLAT score for
// any substring containment, or stripping the TLD off both sides before
// comparing, would score nearly every candidate the same and score
// `acme.test`, `acme.invalid` and the bare string `acme` 1.000 against
// acme.example.
const (
	// simSameDomain: same registrable domain (the monitored domain itself, or a
	// subdomain of it). Only the domain owner can obtain such a certificate.
	simSameDomain = 1.00
	// simHomoglyph: the label is visually indistinguishable from the brand once
	// digit/letter look-alikes and hyphens are folded (acm3, acrne, ac-me; acne→no).
	// Ranked highest of the real squat signals: it is the pattern with the
	// fewest benign explanations.
	simHomoglyph = 0.95
	// simSameLabelAltTLD: the exact brand label under a different public suffix
	// (acme.test vs acme.example). A different TLD is a MATERIAL difference — a
	// different registration, a different owner — but registering the brand
	// under another TLD is also the single most common squatting pattern, so it
	// stays a high-confidence candidate rather than being scored as identical.
	simSameLabelAltTLD = 0.90
	// simBrandAffix: brand plus a known phishing affix (acme-login, acmesecure).
	simBrandAffix = 0.88
	// simBrandLabel: the brand appears as a whole DNS label somewhere else in the
	// name (acme.account-verify.example, login.acme.example.net).
	simBrandLabel = 0.86
	// simBrandToken: the brand appears as a whole hyphen-delimited token with an
	// arbitrary neighbour (acme-box). Weakest named signal — kept above the
	// threshold deliberately, because dropping a real typosquat costs more than
	// one row of human review.
	simBrandToken = 0.80
	// simBrandEmbedded: the brand is embedded in a longer label with no
	// separator at all (contosointakes for contoso). The pattern IS real — but it only
	// carries information for a brand long enough that the coincidence is
	// implausible, hence minEmbeddedBrandLen. Scored below every separator-backed
	// signal so it can never outrank an actual typo.
	simBrandEmbedded = 0.70
)

// minBrandLabelLen is the shortest brand label for which the containment
// signals (affix / whole-label / hyphen-token) are allowed to fire. Below it,
// "contains the brand" stops being evidence: a 3-character label occurs inside
// ordinary words constantly. Short brands still get the homoglyph, alt-TLD and
// graded edit-distance signals, which do not depend on containment.
const minBrandLabelLen = 4

// minEmbeddedBrandLen is the floor for the separatorless-containment signal,
// and it is the deliberate NARROWING in this metric — so, explicitly:
//
// Scoring ANY substring containment (brand ≥ 4 chars, longer side ≤ 3× the
// shorter) at a flat 0.85 does not work. A short monitored brand that also
// happens to be an ordinary word — take "nova" as an example — collides with
// unrelated compound words and business names constantly: novamaker.example,
// supernova.example, thenerdnova.example would all score the same flat 0.85 as a
// genuine squat, then hand the model that 0.85 as evidence, which it would
// rationalise into "high similarity score suggests intentional imitation". A signal that
// fires on everything is not a signal, and its cost is not just noise: it leaves
// a large fraction of the queue sitting at an indistinguishable score, where
// a real typosquat has to be noticed by a human.
//
// At 6 characters the coincidence stops being plausible, so "contosointakes" is
// still caught while "northwind" is not. What this LOSES is a short brand
// embedded without any separator in a longer word — e.g. a hypothetical
// acmemaster.example actually operated by a squatter. Everything else about such a
// domain still works: a hyphen ("acme-master"), a known affix ("acmesecure"), a
// label boundary ("acme.master.example"), or any misspelling of the brand itself all
// keep it, and only the no-separator-plus-arbitrary-word case for a ≤5-char
// brand is dropped. That is the narrowest place to pay for the ordering, and it
// is a conscious trade.
const minEmbeddedBrandLen = 6

// DomainSimilarity scores how much `candidate` (a name observed in a CT log)
// looks like `monitored` (a domain we watch). Result is in [0, 1]; ct.go keeps
// anything ≥ ctSimilarityThreshold.
//
// It compares REGISTRABLE domains, not TLD-stripped base names: the public
// suffix is part of the identity of a domain, so acme.test is not acme.example. It
// is deliberately asymmetric in meaning (candidate vs. brand) but the
// containment signals are applied to the longer/shorter pair, so callers that
// pass the arguments the other way round still get the same score.
//
// Threshold rationale (0.65, unchanged): a single edit on a 4-character brand
// scores 0.75 and a single edit on a 3-character brand 0.67, so every one-edit
// typo of even a very short brand survives; two edits on a short brand
// (0.50) do not, and in practice those are different words, not typos. Every
// named tier above sits well clear of the threshold, so the only candidates the
// metric can drop are ones whose sole relationship to the brand is a middling
// edit distance.
func DomainSimilarity(candidate, monitored string) float64 {
	c := normalizeHost(candidate)
	m := normalizeHost(monitored)
	if c == "" || m == "" {
		return 0
	}
	if c == m {
		return simSameDomain
	}

	cLabel, cSuffix := registrableLabel(c)
	mLabel, mSuffix := registrableLabel(m)
	// Not a hostname on one side (a bare word, a certificate subject fragment
	// like "13 acme road", an IP) — there is nothing domain-shaped to compare.
	// ct.go rejects these before scoring; returning 0 makes the metric itself
	// safe if anything else ever calls it with junk.
	if cLabel == "" || mLabel == "" {
		return 0
	}

	// Same registrable domain: the monitored domain itself or one of its
	// subdomains. Not a squat — nobody else can get a certificate for it.
	if cLabel == mLabel && cSuffix == mSuffix {
		return simSameDomain
	}

	best := 0.0
	if cLabel == mLabel {
		best = simSameLabelAltTLD
	}
	// Score every label to the left of the public suffix, not just the
	// registrable one: `acm3.attacker.test` and `acme.example.login.attacker.test`
	// both hide the brand in a subdomain label.
	for _, label := range hostLabels(c, cSuffix) {
		if s := labelScore(label, mLabel); s > best {
			best = s
		}
	}
	return best
}

// labelScore scores one DNS label against the monitored brand label.
func labelScore(label, brand string) float64 {
	if label == "" {
		return 0
	}
	if label == brand {
		return simBrandLabel
	}
	if foldLookAlikes(label) == foldLookAlikes(brand) {
		return simHomoglyph
	}

	// Containment signals: apply to the longer/shorter pair so the score does
	// not depend on argument order.
	short, long := label, brand
	if utf8.RuneCountInString(label) > utf8.RuneCountInString(brand) {
		short, long = brand, label
	}
	if utf8.RuneCountInString(short) >= minBrandLabelLen {
		if isAffixedBrand(long, short) {
			return simBrandAffix
		}
		for _, tok := range strings.Split(long, "-") {
			if tok == short {
				return simBrandToken
			}
		}
		ls, ll := utf8.RuneCountInString(short), utf8.RuneCountInString(long)
		if ls >= minEmbeddedBrandLen && ll <= 3*ls && strings.Contains(long, short) {
			return simBrandEmbedded
		}
	}

	// Graded fallback: Damerau-Levenshtein (adjacent transpositions cost 1, not
	// 2 — `amce.example` for `acme.example` is one typo, and plain Levenshtein scored it
	// 0.50, below the threshold).
	dist := damerauLevenshtein([]rune(label), []rune(brand))
	maxLen := max(utf8.RuneCountInString(label), utf8.RuneCountInString(brand))
	score := 1.0 - float64(dist)/float64(maxLen)
	if score < 0 {
		return 0
	}
	return score
}

// isAffixedBrand reports whether long is short plus a known phishing affix,
// with or without a hyphen separator ("acme-login", "acmesecure", "my-acme").
func isAffixedBrand(long, short string) bool {
	rest, ok := strings.CutPrefix(long, short)
	if ok {
		if affixSet[strings.TrimPrefix(rest, "-")] {
			return true
		}
	}
	if rest, ok := strings.CutSuffix(long, short); ok {
		if affixSet[strings.TrimSuffix(rest, "-")] {
			return true
		}
	}
	return false
}

// affixSet is the union of commonAffixes plus the credential-harvesting words
// that show up on real phishing registrations. Membership only promotes a
// candidate from simBrandToken to simBrandAffix — it never drops one — so an
// incomplete list cannot lose detection.
var affixSet = func() map[string]bool {
	s := map[string]bool{}
	for _, a := range commonAffixes.prefixes {
		s[a] = true
	}
	for _, a := range commonAffixes.suffixes {
		s[a] = true
	}
	for _, a := range []string{
		"mail", "support", "help", "pay", "payment", "payments", "billing",
		"verify", "verification", "id", "sso", "signin", "sign-in", "log-in",
		"service", "services", "security", "update", "confirm", "official",
	} {
		s[a] = true
	}
	return s
}()

// lookAlikeFolds maps characters to the letter they are visually confusable
// with, so a label can be reduced to a "skeleton" and compared for visual
// identity rather than textual identity.
var lookAlikeFolds = map[rune]rune{
	'0': 'o', '1': 'i', 'l': 'i', '3': 'e', '4': 'a',
	'5': 's', 'z': 's', '7': 't', '8': 'b', '9': 'g', 'q': 'g', '6': 'g',
}

// foldLookAlikes reduces a label to its visual skeleton: look-alike characters
// are folded to one representative, hyphens dropped (a hyphen inserted mid-brand
// is invisible at a glance in a URL bar), and the multi-character look-alikes
// "rn"→m and "vv"→w collapsed.
func foldLookAlikes(label string) string {
	var sb strings.Builder
	sb.Grow(len(label))
	for _, r := range label {
		if r == '-' {
			continue
		}
		if f, ok := lookAlikeFolds[r]; ok {
			r = f
		}
		sb.WriteRune(r)
	}
	s := sb.String()
	s = strings.ReplaceAll(s, "rn", "m")
	s = strings.ReplaceAll(s, "vv", "w")
	return s
}

// damerauLevenshtein computes the optimal-string-alignment distance: insertion,
// deletion, substitution and transposition of two adjacent characters each cost 1.
func damerauLevenshtein(a, b []rune) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	// prev2 = row i-2, prev = row i-1, cur = row i.
	prev2 := make([]int, lb+1)
	prev := make([]int, lb+1)
	cur := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				cur[j] = min(cur[j], prev2[j-2]+1)
			}
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return prev[lb]
}

// splitDomain splits "acme.example" into ("acme", "example").
// Returns ("", "") if domain is malformed.
func splitDomain(domain string) (base, tld string) {
	domain = strings.ToLower(strings.TrimPrefix(domain, "*."))
	idx := strings.LastIndex(domain, ".")
	if idx < 0 {
		return domain, ""
	}
	return domain[:idx], domain[idx+1:]
}

// normalizeHost lowercases and trims a hostname for comparison: whitespace, a
// leading "*." wildcard and a trailing root dot. It does NOT validate — see
// NormalizeDomain for that.
func normalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimPrefix(h, "*.")
	return strings.TrimSuffix(h, ".")
}

// twoLabelSuffixes are public suffixes made of two labels, where the
// registrable name sits one label deeper: <name>.co.uk is registered as
// "<name>", not "co". Not exhaustive (that needs the PSL), but it covers the suffixes a
// European brand actually meets. A suffix missing from this list is only ever
// UNDER-split — <name>.co.nz would compare "co" against "<name>" and score low —
// which is why the list matters for detection, not just for tidiness.
var twoLabelSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "net.uk": true, "me.uk": true,
	"co.nz": true, "co.za": true, "co.jp": true, "co.kr": true, "co.in": true, "co.il": true,
	"com.au": true, "net.au": true, "org.au": true, "com.br": true, "com.mx": true,
	"com.tr": true, "com.cn": true, "com.sg": true, "com.hk": true, "com.tw": true,
	"com.ar": true, "com.co": true, "com.pl": true, "com.ua": true, "com.ng": true,
}

// registrableLabel splits a hostname into its registrable label and public
// suffix: "www.northwind.example" → ("northwind", "example"), "shop.<name>.co.uk" →
// ("<name>", "co.uk"). Returns ("", "") when the input is not hostname-shaped
// (no dot, an empty or non-alphabetic suffix, an IP address).
func registrableLabel(host string) (label, suffix string) {
	labels := strings.Split(normalizeHost(host), ".")
	if len(labels) < 2 {
		return "", ""
	}
	last := labels[len(labels)-1]
	if !isSuffixLabel(last) {
		return "", "" // numeric TLD ⇒ an IP address, not a domain name
	}
	if len(labels) >= 3 {
		two := labels[len(labels)-2] + "." + last
		if twoLabelSuffixes[two] {
			return labels[len(labels)-3], two
		}
	}
	return labels[len(labels)-2], last
}

// hostLabels returns every label of host to the left of its public suffix,
// most-significant last: hostLabels("a.b.<name>.co.uk", "co.uk") → [a b <name>].
func hostLabels(host, suffix string) []string {
	h := normalizeHost(host)
	h = strings.TrimSuffix(h, "."+suffix)
	if h == "" {
		return nil
	}
	return strings.Split(h, ".")
}

// isSuffixLabel reports whether s can be the final label of a hostname: two or
// more letters, or an IDN A-label ("xn--p1ai" — kept so an internationalised
// TLD squat is still scored, not silently zeroed).
func isSuffixLabel(s string) bool {
	if len(s) < 2 {
		return false
	}
	if strings.HasPrefix(s, "xn--") {
		return true
	}
	for _, r := range s {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}
