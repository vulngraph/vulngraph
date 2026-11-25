package intel

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/pkg/log"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

const (
	ctSimilarityThreshold = 0.65
	ctHTTPTimeout         = 20 * time.Second
	// crtShURL asks crt.sh for every certificate whose identity CONTAINS the
	// monitored base name (`?q=%acme%`). The wildcard stays deliberately wide:
	// crt.sh has no fuzzy search, so a narrower query (`q=acme.example`, or an
	// anchored `%acme.%`) would stop returning the affix and subdomain squats
	// this pipeline exists to find — and it already cannot find pure homoglyphs
	// like acm3.example, which is a known coverage gap, not something to widen the
	// substring against. What IS tightened is both ends of the wildcard: the base
	// name is validated (NormalizeDomain) before it is interpolated, so a
	// malformed monitored row cannot produce a garbage query, and every
	// name coming back is validated before it can become a candidate.
	crtShURL = "https://crt.sh/?q=%%25%s%%25&output=json"
)

// ctClient wraps safenet for CT log queries.
type ctClient struct {
	http *http.Client
	// urlFmt is crtShURL in production. A field only so the blackout behaviour
	// above can be tested against a local server — crt.sh's real failure mode is
	// the thing under test and it cannot be summoned on demand.
	urlFmt string
}

func newCTClient() *ctClient {
	return &ctClient{http: safenet.New(ctHTTPTimeout), urlFmt: crtShURL}
}

// crtShEntry is a single row returned by crt.sh JSON API.
type crtShEntry struct {
	IssuerCAID int    `json:"issuer_ca_id"`
	IssuerName string `json:"issuer_name"`
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"` // SANs, newline-separated
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
}

// CTQueryStats reports how the per-domain crt.sh queries went, so the caller can
// tell "no squatting domains exist" from "we could not look".
type CTQueryStats struct {
	Queried int // domains with a usable base name, i.e. actually attempted
	Failed  int // of those, how many crt.sh calls errored
}

// CheckCTLogs queries crt.sh for certificates containing substrings of the
// monitored domain's base name, then scores each result against monitored
// domains using DomainSimilarity. Returns hits above ctSimilarityThreshold.
//
// A per-domain failure is tolerated (the remaining domains are still worth
// scanning) but it is LOGGED and COUNTED, and if every attempted domain failed
// the error is returned rather than an empty hit list.
//
// That last part is the whole point. crt.sh is a single upstream with no
// fallback, and it can return 502 for extended periods — on every monitored
// base name AND on its own root URL. If every query erroring produced ([], nil),
// RunScan would log hits=0, write no candidates, and the job would COMPLETE
// SUCCESSFULLY: phishing_candidates would stop growing and nothing would report
// the gap, because a total upstream blackout would be byte-identical to a clean
// bill of health.
//
// Note the asymmetry that makes returning an error safe here: candidates are only
// ever INSERTED by this path, never resolved or deleted by absence, so a failed
// scan cannot destroy anything. Failing loudly costs a retry; failing silently
// costs the entire detection.
func (c *ctClient) CheckCTLogs(ctx context.Context, monitored []string) ([]CTHit, CTQueryStats, error) {
	// Build a set of base names to query — one crt.sh query per monitored domain.
	seen := map[string]bool{} // (commonName, monitoredDomain) for dedup
	var hits []CTHit
	var stats CTQueryStats
	var firstErr error

	var skippedNames int
	for _, md := range monitored {
		// A monitored row that is not a valid hostname can never match anything:
		// crt.sh would be asked for something like `q=%acme,cin%`, which
		// burns a request, always returns nothing useful, and — worse — counts
		// toward Failed, so a permanently broken row could mask a real blackout.
		// NormalizeDomain rejects it at the API; this guards rows written any
		// other way.
		norm, err := NormalizeDomain(md)
		if err != nil {
			log.FromContext(ctx).Warn().Str("monitored_domain", md).
				Msg("intel: monitored domain is not a valid hostname — never scanned, delete or fix the row")
			continue
		}
		base, _ := splitDomain(norm)
		if base == "" {
			log.FromContext(ctx).Warn().Str("monitored_domain", md).
				Msg("intel: monitored domain has no usable base name — never scanned")
			continue
		}
		stats.Queried++

		entries, err := c.queryCRTSh(ctx, base)
		if err != nil {
			stats.Failed++
			if firstErr == nil {
				firstErr = err
			}
			log.FromContext(ctx).Warn().Err(err).Str("monitored_domain", md).Str("base", base).
				Msg("intel: crt.sh query failed — this domain was not scanned")
			continue
		}

		for _, e := range entries {
			names := parseCTNames(e)
			notBefore := parseCTTime(e.NotBefore)
			notAfter := parseCTTime(e.NotAfter)
			issuer := shortIssuer(e.IssuerName)

			for _, raw := range names {
				// crt.sh's common_name/name_value fields are NOT guaranteed to be
				// hostnames: they carry whatever the certificate's subject held, so
				// values like "jane acme", "1 example street" or "acme & acme"
				// (O=, street and S-MIME CN values) would otherwise land in
				// phishing_candidates as "domains". The same strict
				// validator that gates the monitored set gates ingestion too.
				cn, err := NormalizeDomain(raw)
				if err != nil {
					skippedNames++
					continue
				}
				score := DomainSimilarity(cn, norm)
				if score < ctSimilarityThreshold {
					continue
				}
				// Skip our own certificates: the monitored domain itself and any
				// subdomain of it. A certificate for *.acme.example or login.acme.example
				// requires control of acme.example, so it is never someone else's squat.
				if cn == norm || strings.HasSuffix(cn, "."+norm) {
					continue
				}
				key := cn + "|" + norm
				if seen[key] {
					continue
				}
				seen[key] = true
				hits = append(hits, CTHit{
					CommonName:      cn,
					Issuer:          issuer,
					NotBefore:       notBefore,
					NotAfter:        notAfter,
					MonitoredDomain: norm,
					Score:           score,
				})
			}
		}
	}
	if skippedNames > 0 {
		log.FromContext(ctx).Info().Int("skipped_names", skippedNames).
			Msg("intel: certificate names that are not hostnames were skipped (subject O=/street/S-MIME fields)")
	}
	// Every attempted domain failed: the upstream is down, not the internet clean.
	// Reported as an error so the job lands in River as retryable/discarded, which
	// is the only place a reader would ever see it — a successful job with zero
	// writes is exactly what would hide it.
	if stats.Queried > 0 && stats.Failed == stats.Queried {
		return nil, stats, fmt.Errorf("CheckCTLogs: all %d crt.sh queries failed, first: %w", stats.Failed, firstErr)
	}
	return hits, stats, nil
}

func (c *ctClient) queryCRTSh(ctx context.Context, base string) ([]crtShEntry, error) {
	url := fmt.Sprintf(c.urlFmt, base)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh: status %d", resp.StatusCode)
	}

	var entries []crtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("crt.sh decode: %w", err)
	}
	return entries, nil
}

// parseCTNames returns the unique set of domain names from a crt.sh entry
// (common_name + SANs).
func parseCTNames(e crtShEntry) []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		n = strings.TrimSpace(n)
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	add(e.CommonName)
	for san := range strings.SplitSeq(e.NameValue, "\n") {
		add(san)
	}
	return out
}

func parseCTTime(s string) time.Time {
	t, _ := time.Parse("2006-01-02T15:04:05", s)
	return t
}

// shortIssuer extracts the O= from an issuer DN for display.
func shortIssuer(dn string) string {
	for part := range strings.SplitSeq(dn, ", ") {
		if o, ok := strings.CutPrefix(part, "O="); ok {
			return o
		}
	}
	return dn
}

// CandidateID returns a stable deterministic ID for a CT hit, used for
// ReplacingMergeTree deduplication in ClickHouse.
func CandidateID(domain, monitoredDomain string) string {
	h := sha256.Sum256([]byte(domain + "|" + monitoredDomain))
	return fmt.Sprintf("%x", h[:16])
}
