package enrich

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type fakeHTTP struct {
	status int
	body   string
	err    error
}

func (f fakeHTTP) Get(context.Context, string) (int, string, error) {
	return f.status, f.body, f.err
}

func hostAsset(domain string) oneAsset {
	return oneAsset{a: asset.Asset{ID: "rec1", Type: "dns_record", Domain: domain, Metadata: map[string]string{}}}
}

// hostAssetWithTarget is hostAsset plus a recorded CNAME/ALIAS target, the
// fact DNSTakeover (and now TakeoverProbe's own corroboration check) reads
// from Metadata["values"].
func hostAssetWithTarget(domain, target string) oneAsset {
	return oneAsset{a: asset.Asset{
		ID: "rec1", Type: "dns_record", Domain: domain,
		Metadata: map[string]string{"values": target},
	}}
}

func probeFinding() finding.Finding {
	return finding.Finding{CheckID: "dns-cname-takeover-risk", ResourceID: "rec1"}
}

func TestTakeoverProbe_FingerprintConfirms(t *testing.T) {
	src := TakeoverProbe{Assets: hostAsset("cdn.example.com"), HTTP: fakeHTTP{status: 404, body: "... NoSuchBucket ..."}}
	f, ok, err := src.Evaluate(context.Background(), probeFinding())
	require.NoError(t, err)
	require.True(t, ok, "an S3 NoSuchBucket fingerprint confirms takeover")
	require.Equal(t, ThresholdPage, f.Floor)
	require.Contains(t, f.Detail, "AWS S3")
}

func TestTakeoverProbe_StatusMustMatchWhenSpecified(t *testing.T) {
	// NoSuchBucket requires 404; a 200 carrying the string (unlikely, but be strict)
	// must not CONFIRM on the status-gated fingerprint. It is a live 200 with no
	// matching fingerprint, so it is HTTP-layer refutation evidence — but with no
	// Resolver wired here, that is only one source's evidence, so it must not demote.
	src := TakeoverProbe{Assets: hostAsset("cdn.example.com"), HTTP: fakeHTTP{status: 200, body: "NoSuchBucket"}}
	f, ok, _ := src.Evaluate(context.Background(), probeFinding())
	require.False(t, ok, "one source's evidence alone must not confirm or refute")
	require.Zero(t, f.Floor, "must not confirm takeover on a mismatched status")
}

// Both corroborating sources must agree before a candidate refutes.
// TakeoverProbe's own HTTP-layer "live and owned" finding is corroborated by
// checking (via its Resolver) that the record's CNAME/ALIAS target — the same
// fact DNSTakeover checks — actually resolves.
func TestTakeoverProbe_BothOrgansAgree_Refutes(t *testing.T) {
	src := TakeoverProbe{
		Assets:   hostAssetWithTarget("cdn.example.com", "live.cloudfront.net"),
		HTTP:     fakeHTTP{status: 200, body: "<html>welcome</html>"},
		Resolver: fakeResolver{found: true},
	}
	f, ok, err := src.Evaluate(context.Background(), probeFinding())
	require.NoError(t, err)
	require.True(t, ok, "both sources agreeing live+owned must refute the pattern candidate")
	require.Equal(t, sourceTakeoverProbe, f.Source)
	require.Negative(t, f.Points, "refutation must carry strong negative weight")
	require.Zero(t, f.Floor)
	// Points AND Ceiling: the negative alone is not floor-immune (floors apply
	// after negatives), so the Ceiling pins the sub-pipeline landing against a
	// same-sweep high floor from a DNS flap; only a page/KEV floor outranks it.
	require.Equal(t, ThresholdPipeline, f.Ceiling)
	require.False(t, f.Suppress)
	require.Contains(t, f.Detail, "takeover refuted")

	got := Aggregate([]Factor{f})
	require.Less(t, int(got.Value), ThresholdPipeline, "a refuted candidate must land below the decide-pipeline threshold")
	require.Equal(t, BandMonitor, got.Band)
}

// The refutation must dominate regardless of how much positive weight the rest
// of the sources contributed — clamping the positive subtotal to 100
// before negatives apply, so takeoverRefutedPoints alone must be enough.
func TestTakeoverProbe_RefutationDominatesEvenAtMaxPositive(t *testing.T) {
	refute := Factor{Source: sourceTakeoverProbe, Points: takeoverRefutedPoints, Detail: "takeover refuted"}
	maxedOut := Factor{Source: "other", Points: 500} // clamped to 100 before negatives apply
	got := Aggregate([]Factor{refute, maxedOut})
	require.Less(t, int(got.Value), ThresholdPipeline)
	require.Equal(t, BandMonitor, got.Band)
}

func TestTakeoverProbe_HTTPLiveButResolverMissing_DoesNotRefute(t *testing.T) {
	// Only the HTTP source ran — no Resolver wired at all. Fail toward caution.
	src := TakeoverProbe{Assets: hostAssetWithTarget("cdn.example.com", "live.cloudfront.net"),
		HTTP: fakeHTTP{status: 200, body: "<html>welcome</html>"}}
	_, ok, err := src.Evaluate(context.Background(), probeFinding())
	require.NoError(t, err)
	require.False(t, ok, "HTTP evidence alone (no DNS corroboration) must not refute")
}

func TestTakeoverProbe_HTTPLiveButDNSDangling_DoesNotRefute(t *testing.T) {
	// The two sources actively DISAGREE: HTTP says live, DNS says the target does
	// not resolve. That is the dangling-record signal DNSTakeover itself raises
	// on — TakeoverProbe must not fight it by refuting.
	src := TakeoverProbe{
		Assets:   hostAssetWithTarget("cdn.example.com", "old-app.herokuapp.com"),
		HTTP:     fakeHTTP{status: 200, body: "<html>welcome</html>"},
		Resolver: fakeResolver{found: false},
	}
	_, ok, err := src.Evaluate(context.Background(), probeFinding())
	require.NoError(t, err)
	require.False(t, ok, "disagreeing sources must not refute")
}

func TestTakeoverProbe_HTTPLiveButResolverErrors_DoesNotRefute(t *testing.T) {
	src := TakeoverProbe{
		Assets:   hostAssetWithTarget("cdn.example.com", "live.cloudfront.net"),
		HTTP:     fakeHTTP{status: 200, body: "<html>welcome</html>"},
		Resolver: fakeResolver{err: errors.New("timeout")},
	}
	_, ok, err := src.Evaluate(context.Background(), probeFinding())
	require.NoError(t, err)
	require.False(t, ok, "a transient DNS error is not corroboration")
}

func TestTakeoverProbe_HTTPLiveButNoRecordedTarget_DoesNotRefute(t *testing.T) {
	// hostAsset carries no Metadata["values"] at all.
	src := TakeoverProbe{
		Assets:   hostAsset("cdn.example.com"),
		HTTP:     fakeHTTP{status: 200, body: "<html>welcome</html>"},
		Resolver: fakeResolver{found: true},
	}
	_, ok, err := src.Evaluate(context.Background(), probeFinding())
	require.NoError(t, err)
	require.False(t, ok, "no recorded target means nothing for the resolver to corroborate")
}

func TestTakeoverProbe_Non200WithoutSignatureInconclusive(t *testing.T) {
	// A 500/403/etc that matches no fingerprint is inconclusive — the backing
	// resource may still be claimable, so do not refute.
	src := TakeoverProbe{Assets: hostAsset("cdn.example.com"), HTTP: fakeHTTP{status: 503, body: "service unavailable"}}
	_, ok, err := src.Evaluate(context.Background(), probeFinding())
	require.NoError(t, err)
	require.False(t, ok, "a non-200 with no signature must not refute")
}

func TestTakeoverProbe_RefutationCannotBreachPageFloor(t *testing.T) {
	// A page-floor assertion from another source (e.g. KEV) is a stronger claim
	// than a demote — Aggregate applies floors AFTER negatives — so the page
	// floor wins even against the refutation's negative factor.
	refute := Factor{Source: sourceTakeoverProbe, Points: takeoverRefutedPoints}
	kev := Factor{Source: "kev", Points: 20, Floor: ThresholdPage}
	got := Aggregate([]Factor{refute, kev})
	require.GreaterOrEqual(t, int(got.Value), ThresholdPage, "a page floor beats the refutation demote")
	require.Equal(t, BandPage, got.Band)
}

// A DNS flap can hand DNSTakeover an NXDOMAIN (high floor) in the same sweep
// this source sees the target live: floors apply AFTER negatives, so without
// the refutation's Ceiling the flap would land the candidate back in the high
// band. The Ceiling caps
// any sub-page floor back below the pipeline threshold.
func TestTakeoverProbe_RefutationBeatsSameSweepHighFloor(t *testing.T) {
	refute := Factor{Source: sourceTakeoverProbe, Points: takeoverRefutedPoints, Ceiling: ThresholdPipeline}
	flap := Factor{Source: sourceDNSTakeover, Points: 40, Floor: ThresholdHigh}
	got := Aggregate([]Factor{refute, flap})
	require.Less(t, int(got.Value), ThresholdPipeline, "a high floor from a DNS flap must not outrank a corroborated refutation")
	require.Equal(t, BandMonitor, got.Band)
}

func TestTakeoverProbe_ErrorInconclusive(t *testing.T) {
	src := TakeoverProbe{Assets: hostAsset("cdn.example.com"), HTTP: fakeHTTP{err: errors.New("blocked by safenet")}}
	_, ok, err := src.Evaluate(context.Background(), probeFinding())
	require.NoError(t, err)
	require.False(t, ok)
}

func TestTakeoverProbe_WildcardHostSkipped(t *testing.T) {
	src := TakeoverProbe{Assets: hostAsset("*.example.com"), HTTP: fakeHTTP{status: 404, body: "NoSuchBucket"}}
	_, ok, _ := src.Evaluate(context.Background(), probeFinding())
	require.False(t, ok, "a wildcard record has no single host to probe")
}

func TestTakeoverProbe_OnlyTakeoverChecks(t *testing.T) {
	src := TakeoverProbe{Assets: hostAsset("cdn.example.com"), HTTP: fakeHTTP{status: 404, body: "NoSuchBucket"}}
	_, ok, _ := src.Evaluate(context.Background(), finding.Finding{CheckID: "aws-s3-public-bucket", ResourceID: "rec1"})
	require.False(t, ok)
}
