package enrich

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

// HTTPGetter fetches a URL and returns the status and a (capped) body. The
// production implementation routes through safenet's SSRF-blocking client so a
// probe can never reach a private/reserved address, even though the hostname is
// third-party. Tests inject a fake.
type HTTPGetter interface {
	Get(ctx context.Context, url string) (status int, body string, err error)
}

// takeoverFingerprint is an unclaimed-service signature: an HTTP response body
// substring (and optional status) that a takeover-prone platform returns when
// the backing resource is gone. High-confidence, curated — matching one confirms
// the subdomain is claimable.
type takeoverFingerprint struct {
	service string
	status  int // 0 = any status
	body    string
}

// Curated set of well-known, low-false-positive takeover fingerprints.
var takeoverFingerprints = []takeoverFingerprint{
	{"AWS S3", 404, "NoSuchBucket"},
	{"GitHub Pages", 404, "There isn't a GitHub Pages site here"},
	{"Heroku", 404, "No such app"},
	{"Heroku", 0, "herokucdn.com/error-pages/no-such-app.html"},
	{"Fastly", 0, "Fastly error: unknown domain"},
	{"Shopify", 0, "Sorry, this shop is currently unavailable"},
	{"Surge.sh", 0, "project not found"},
	{"Bitbucket", 0, "Repository not found"},
	{"Azure", 404, "404 Web Site not found"},
	{"Cargo", 0, "404 Not Found: The requested resource was not found"},
	{"Tumblr", 0, "Whatever you were looking for doesn't currently exist at this address"},
	{"Zendesk", 0, "Help Center Closed"},
}

// TakeoverProbe is the HTTP-fingerprint verification source. It closes
// the gap the DNS source (DNSTakeover) leaves: a CNAME whose target still resolves
// (so DNS can't refute) but whose backing resource is unclaimed at the HTTP layer
// (a deleted S3 bucket serving "NoSuchBucket", an unclaimed Heroku app, …). It
// fetches the record's own hostname through the SSRF-blocking safenet client and
// confirms a takeover only on a curated unclaimed-service fingerprint match.
//
// Two outcomes carry signal: a fingerprint match elevates (page band); a clean
// 200 with NO fingerprint is this source's half of a refutation — the host
// resolves and serves normal content, so it LOOKS live and owned from the HTTP
// layer alone. That is not enough by itself: an HTTP 200 says nothing
// about whether the DNS record under investigation is the dangling one, so
// refutation additionally requires Resolver to corroborate that the record's
// own CNAME/ALIAS target resolves — the same fact DNSTakeover checks. (For a
// plain CNAME an HTTP 200 on the record name already implies the chain
// resolved, so the DNS check adds real independence mainly for ALIAS records;
// it is kept for both because it costs one lookup and fails toward caution.)
// Only when BOTH sources agree does the candidate demote, via a negative
// Factor AND a pipeline Ceiling — see the comment at the Factor for why both
// are needed (floors are applied after negatives). Every
// other combination — HTTP inconclusive, HTTP live but DNS unavailable/
// inconclusive/dangling, or DNS unavailable entirely — leaves the candidate
// untouched: for a security signal, a missed takeover is worse than a
// lingering low-confidence candidate, and a single source's evidence is not
// corroboration.
type TakeoverProbe struct {
	Assets AssetGetter
	HTTP   HTTPGetter // nil disables the source
	// Resolver corroborates the HTTP-layer "live and owned" finding against the
	// DNS layer. nil means no corroboration is possible, so this source can still
	// CONFIRM a takeover via fingerprint match but can never REFUTE one — the
	// fail-toward-caution default (see Evaluate).
	Resolver Resolver
}

func (TakeoverProbe) Name() string { return sourceTakeoverProbe }

// takeoverRefutedPoints is the negative Factor applied when both corroboration
// sources agree a takeover candidate is live and owned. The pipeline clamps the
// positive subtotal to 100 before negatives apply, so any value beyond 50
// guarantees the result lands below ThresholdPipeline (100-51=49) regardless
// of how much positive weight the rest of the scoring sources contributed —
// chosen with headroom over that minimum so the demotion reads unambiguously
// as "refuted", not as a near-miss.
const takeoverRefutedPoints = -60

func (p TakeoverProbe) Evaluate(ctx context.Context, f finding.Finding) (Factor, bool, error) {
	if p.Assets == nil || p.HTTP == nil || !takeoverCheckIDs[f.CheckID] || f.ResourceID == "" {
		return Factor{}, false, nil
	}
	a, err := p.Assets.Get(ctx, f.ResourceID)
	if err != nil {
		return Factor{}, false, err
	}
	host := strings.TrimSuffix(strings.TrimSpace(a.Domain), ".")
	if host == "" || strings.HasPrefix(host, "*") { // no host, or an unprobeable wildcard record
		return Factor{}, false, nil
	}
	status, body, gerr := p.HTTP.Get(ctx, "https://"+host)
	if gerr != nil {
		return Factor{}, false, nil // unreachable / blocked / timeout → inconclusive
	}
	for _, fp := range takeoverFingerprints {
		if fp.status != 0 && fp.status != status {
			continue
		}
		if strings.Contains(body, fp.body) {
			return Factor{
				Source: sourceTakeoverProbe,
				Points: 50,
				Floor:  ThresholdPage,
				Detail: host + " serves an unclaimed-resource fingerprint (" + fp.service + ") — subdomain takeover confirmed",
			}, true, nil
		}
	}
	if status != http.StatusOK {
		return Factor{}, false, nil // non-200 without a signature — inconclusive, stays a candidate
	}
	// HTTP layer alone says live and owned. Refutation needs the DNS layer to
	// agree the record's own target actually resolves — fail toward caution if
	// it doesn't (or can't be checked).
	if !p.dnsCorroboratesLive(ctx, a) {
		return Factor{}, false, nil
	}
	// Points AND Ceiling together: -60 alone is NOT floor-immune — score.go
	// applies floors AFTER negatives, so a
	// same-sweep DNSTakeover high floor (a DNS flap can give one source NXDOMAIN
	// and this one live) would push a refuted candidate back to the high band.
	// The Ceiling keeps the contract: only a genuine page/KEV floor
	// (>= ThresholdPage, which score.go exempts from ceilings) outranks a
	// refutation — a deliberate "KEV floor beats evidence of non-exploitability"
	// choice, pinned by TestTakeoverProbe_RefutationCannotBreachPageFloor.
	return Factor{
		Source:  sourceTakeoverProbe,
		Points:  takeoverRefutedPoints,
		Ceiling: ThresholdPipeline,
		Detail:  "takeover refuted: target resolves and serves an owned response",
	}, true, nil
}

// dnsCorroboratesLive reports whether the DNS-layer source's own fact (the
// asset's CNAME/ALIAS target resolves) agrees with this source's HTTP-layer
// "live and owned" finding. false on anything short of an affirmative
// resolution — no Resolver wired, no recorded target, or a resolver error —
// so a single source's evidence never demotes a candidate on its own.
func (p TakeoverProbe) dnsCorroboratesLive(ctx context.Context, a asset.Asset) bool {
	if p.Resolver == nil {
		return false
	}
	target := firstDNSValue(a.Metadata["values"])
	if target == "" {
		return false
	}
	found, err := p.Resolver.Resolves(ctx, target)
	return err == nil && found
}

// safenetGetter is the production HTTPGetter: a safenet SSRF-blocking client with
// a body cap so a hostile endpoint can't stream an unbounded response into enrich.
type safenetGetter struct {
	client  *http.Client
	maxBody int64
}

// NewSafenetGetter builds an HTTPGetter backed by safenet.New (private/reserved
// ranges rejected at dial time). maxBody caps the bytes read from any response.
func NewSafenetGetter(timeout time.Duration, maxBody int64) *safenetGetter {
	return &safenetGetter{client: safenet.New(timeout), maxBody: maxBody}
}

func (g *safenetGetter) Get(ctx context.Context, url string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, g.maxBody))
	return resp.StatusCode, string(b), nil
}
