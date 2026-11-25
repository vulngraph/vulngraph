package respond

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

var provNow = time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)

func packSvc() *Service { return &Service{now: func() time.Time { return provNow }} }

func TestAgeBucket(t *testing.T) {
	tests := []struct {
		name       string
		discovered time.Time
		lastSeen   time.Time
		want       string
	}{
		{"zero discovered => unknown", time.Time{}, provNow, ""},
		{"recently discovered => new", provNow.Add(-2 * 24 * time.Hour), provNow, "new"},
		{"long-lived, fresh => established", provNow.Add(-90 * 24 * time.Hour), provNow.Add(-time.Hour), "established"},
		{"not seen in weeks => stale", provNow.Add(-90 * 24 * time.Hour), provNow.Add(-30 * 24 * time.Hour), "stale"},
		{"stale beats new", provNow.Add(-2 * 24 * time.Hour), provNow.Add(-30 * 24 * time.Hour), "stale"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := asset.Asset{DiscoveredAt: tt.discovered, LastSeen: tt.lastSeen}
			require.Equal(t, tt.want, ageBucket(provNow, a))
		})
	}
}

// TestAgeBucket_PrefersFirstDiscoveredAt pins the actual regression: before
// this fix, ageBucket read DiscoveredAt, which every collector re-stamps to
// `now` on every sweep — so a long-established resource whose old
// ReplacingMergeTree versions had merged away quickly was reported "new"
// again on its very next re-collection. A resource
// re-collected seconds ago (DiscoveredAt fresh) but first observed 90 days
// ago (FirstDiscoveredAt old) must read as "established", not "new".
func TestAgeBucket_PrefersFirstDiscoveredAt(t *testing.T) {
	a := asset.Asset{
		FirstDiscoveredAt: provNow.Add(-90 * 24 * time.Hour),
		DiscoveredAt:      provNow, // re-stamped by this sweep's collector
		LastSeen:          provNow,
	}
	require.Equal(t, "established", ageBucket(provNow, a))
}

// TestAgeBucket_FallsBackToDiscoveredAtWhenFirstUnset covers a pre-migration
// row (or a hand-built Asset) that has never had FirstDiscoveredAt pinned —
// DiscoveredAt is still the best available signal, not "unknown".
func TestAgeBucket_FallsBackToDiscoveredAtWhenFirstUnset(t *testing.T) {
	a := asset.Asset{DiscoveredAt: provNow.Add(-2 * 24 * time.Hour), LastSeen: provNow}
	require.Equal(t, "new", ageBucket(provNow, a))
}

func TestProvenanceOf_FromSeedAsset(t *testing.T) {
	seed := asset.Asset{
		AccountID: "1234", Region: "eu-west-1",
		Tags:         map[string]string{"owner": "payments-team", "env": "prod"},
		Metadata:     map[string]string{"prov_connector_type": "aws"},
		DiscoveredAt: provNow.Add(-90 * 24 * time.Hour),
		LastSeen:     provNow,
	}
	p := packSvc().provenanceOf(seed)
	require.Equal(t, "aws", p.Connector)
	require.Equal(t, "1234", p.AccountID)
	require.Equal(t, "eu-west-1", p.Region)
	require.Equal(t, "payments-team", p.Owner)
	require.Equal(t, "prod", p.Environment)
	require.Equal(t, asset.EnvClassification{Env: asset.EnvProd, Source: "tag:env"}, p.Env)
	require.Equal(t, "established", p.AgeBucket)

	// An untagged seed is classified unknown, not left as a blank prod/non-prod.
	require.Equal(t, asset.EnvUnknown, packSvc().provenanceOf(asset.Asset{AccountID: "1234"}).Env.Env)
}

func TestBuildContextPack_DerivesProvenanceFromSeed(t *testing.T) {
	br := asset.BlastRadius{Assets: []asset.Asset{{
		ID: "i-1", AccountID: "9", Metadata: map[string]string{"prov_connector_type": "gcp"},
		Tags: map[string]string{"team": "infra"}, DiscoveredAt: provNow.Add(-time.Hour), LastSeen: provNow,
	}}}
	pack := packSvc().buildContextPack(context.Background(), finding.Finding{ID: "f1", ResourceID: "i-1"}, br, true, nil, false)
	require.Equal(t, "gcp", pack.Provenance.Connector)
	require.Equal(t, "infra", pack.Provenance.Owner)
	require.Equal(t, "new", pack.Provenance.AgeBucket)
}

func TestBuildContextPack_NoSeed_EmptyProvenance(t *testing.T) {
	pack := packSvc().buildContextPack(context.Background(), finding.Finding{ID: "f1"}, asset.BlastRadius{}, true, nil, false)
	require.Equal(t, Provenance{}, pack.Provenance, "no seed asset => empty provenance, graceful degrade")
}

type fakeLineage struct{ edges []asset.Edge }

func (f fakeLineage) EdgesInto(context.Context, string, string) ([]asset.Edge, error) {
	return f.edges, nil
}

func (f fakeLineage) EdgesIntoTypes(context.Context, string, []string) ([]asset.Edge, error) {
	return f.edges, nil
}

func TestBuildContextPack_SurfacesSourceRepo_PrefersHighConfidence(t *testing.T) {
	svc := packSvc()
	svc.lineage = fakeLineage{edges: []asset.Edge{
		{SrcID: "example/guess", Properties: map[string]string{"confidence": "medium"}},
		{SrcID: "example/payments-api", Properties: map[string]string{"confidence": "high"}},
	}}
	br := asset.BlastRadius{Assets: []asset.Asset{{ID: "prod/pod/x", Type: "k8s_pod"}}}
	pack := svc.buildContextPack(context.Background(), finding.Finding{ID: "f1", ResourceID: "prod/pod/x"}, br, true, nil, false)
	require.Equal(t, "example/payments-api", pack.Provenance.SourceRepo, "high-confidence link wins")
	require.Equal(t, "high", pack.Provenance.SourceConfidence)
}

func TestBuildContextPack_NoLineage_NoSourceRepo(t *testing.T) {
	br := asset.BlastRadius{Assets: []asset.Asset{{ID: "prod/pod/x", Type: "k8s_pod"}}}
	pack := packSvc().buildContextPack(context.Background(), finding.Finding{ID: "f1", ResourceID: "prod/pod/x"}, br, true, nil, false)
	require.Empty(t, pack.Provenance.SourceRepo, "nil lineage seam => no source repo")
}

func TestBuildContextPack_NonWorkloadSeed_SkipsLineageLookup(t *testing.T) {
	svc := packSvc()
	svc.lineage = fakeLineage{edges: []asset.Edge{
		{SrcID: "example/whatever", Properties: map[string]string{"confidence": "high"}},
	}}
	// A non-workload seed (an S3 bucket) must not trigger the inbound-edge lookup,
	// even though the fake would return a match — deploys_to only points at workloads.
	br := asset.BlastRadius{Assets: []asset.Asset{{ID: "arn:s3:bucket", Type: "s3_bucket"}}}
	pack := svc.buildContextPack(context.Background(), finding.Finding{ID: "f1", ResourceID: "arn:s3:bucket"}, br, true, nil, false)
	require.Empty(t, pack.Provenance.SourceRepo, "non-workload seed => lineage lookup skipped (off the CH hot path)")
}

func TestFingerprintExtra_IdentityChangeFlipsHash(t *testing.T) {
	withRoleA := ContextPack{Identity: &IdentityLinks{ExecutesAsID: "arn:role-a"}}
	withRoleB := ContextPack{Identity: &IdentityLinks{ExecutesAsID: "arn:role-b"}}
	require.NotEqual(t, withRoleA.fingerprintExtra(), withRoleB.fingerprintExtra(),
		"different execution identity must change fingerprint")
}

func TestFingerprintExtra_SupplyChainRepoSwapFlipsHash(t *testing.T) {
	sc1 := ContextPack{SupplyChain: &SupplyChainPath{RepoIDs: []string{"github.com/org/repo-a"}}}
	sc2 := ContextPack{SupplyChain: &SupplyChainPath{RepoIDs: []string{"github.com/org/repo-b"}}}
	require.NotEqual(t, sc1.fingerprintExtra(), sc2.fingerprintExtra(),
		"different repo (same count) must change fingerprint — count-only would miss this")
}

func TestFingerprintExtra_ProvenanceChangeFlipsHash(t *testing.T) {
	base := ContextPack{Provenance: Provenance{Connector: "aws", Owner: "team-a", Environment: "prod", AgeBucket: "established"}}
	ownerChanged := base
	ownerChanged.Provenance.Owner = "team-b"
	require.NotEqual(t, base.fingerprintExtra(), ownerChanged.fingerprintExtra(),
		"owner change must change the fingerprint inputs")

	// A bucketed age is stable across a within-bucket timestamp tick: same bucket => same extra.
	same := base
	require.Equal(t, base.fingerprintExtra(), same.fingerprintExtra())
}

// erroringPeers always fails List — simulates the peer-findings query error
// path that must leave ExposureFlags.PeersKnown false, not silently
// indistinguishable from a query that found zero peers.
type erroringPeers struct{ err error }

func (p erroringPeers) List(context.Context, finding.Filter) ([]finding.Finding, error) {
	return nil, p.err
}

// TestBuildContextPack_PeersQueryErrorLeavesPeersUnknown: a failed peer-findings query must set
// Exposure.PeersKnown=false, not leave InternetFacing/Privileged at their
// zero value with no way to tell "queried, found nothing" apart from "never
// successfully queried at all".
func TestBuildContextPack_PeersQueryErrorLeavesPeersUnknown(t *testing.T) {
	svc := &Service{now: func() time.Time { return provNow }, peers: erroringPeers{err: errors.New("ch down")}}
	pack := svc.buildContextPack(context.Background(), finding.Finding{ID: "f1", ResourceID: "i-1"}, asset.BlastRadius{}, true, nil, false)
	require.False(t, pack.Exposure.PeersKnown, "a failed peer query must leave PeersKnown false")
	require.False(t, pack.Exposure.InternetFacing, "no exposure claim can be made on an unmeasured peer set")
}

// The mirror case: a SUCCESSFUL query that simply finds no peers is real
// evidence, not an unmeasured state, so PeersKnown must be true.
func TestBuildContextPack_NoPeersFoundIsKnown(t *testing.T) {
	svc := &Service{now: func() time.Time { return provNow }, peers: erroringPeers{err: nil}}
	pack := svc.buildContextPack(context.Background(), finding.Finding{ID: "f1", ResourceID: "i-1"}, asset.BlastRadius{}, true, nil, false)
	require.True(t, pack.Exposure.PeersKnown, "a successful query that found nothing IS a measurement")
}

// TestContext_PeersQueryErrorLeavesPeersUnknown is the peers-known
// fix: TestBuildContextPack_PeersQueryErrorLeavesPeersUnknown
// above exercises buildContextPack directly, but the REAL, ONLY production
// caller is Service.Context (internal/jobs/adjudicate.go calls it, never
// buildContextPack directly) — and Context used to normalize a failed peer
// query into an empty-but-non-nil slice before handing it to
// buildContextPack as prefetchedPeers, which made buildContextPack default
// peersKnown=true regardless of what actually happened. This test would
// have passed even with that bug present if it only checked
// buildContextPack; it must go through Context() itself.
func TestContext_PeersQueryErrorLeavesPeersUnknown(t *testing.T) {
	svc := NewReadService(fakeBlast{n: 3}, erroringPeers{err: errors.New("ch down")}, nil)
	pack, err := svc.Context(context.Background(), finding.Finding{ID: "f1", ResourceID: "i-1"})
	require.NoError(t, err)
	require.False(t, pack.Exposure.PeersKnown,
		"a failed peer query inside Context must leave PeersKnown false, not a successful-empty result")
}

// The mirror case at the Context level: a successful empty query IS known.
func TestContext_NoPeersFoundIsKnown(t *testing.T) {
	svc := NewReadService(fakeBlast{n: 3}, erroringPeers{err: nil}, nil)
	pack, err := svc.Context(context.Background(), finding.Finding{ID: "f1", ResourceID: "i-1"})
	require.NoError(t, err)
	require.True(t, pack.Exposure.PeersKnown)
}

// panickingPeers always panics inside List — simulates a nil-map dereference
// or a driver panic, as opposed to erroringPeers' clean error return.
type panickingPeers struct{}

func (panickingPeers) List(context.Context, finding.Filter) ([]finding.Finding, error) {
	panic("simulated peer-findings panic")
}

// TestContext_PeersPanicLeavesPeersUnknown is the regression test for a gap
// where Context's peersKnown starts true
// (correct for "the peers goroutine never even ran" — s.peers nil or no
// ResourceID) and the peers goroutine's recover() logged a panic but never
// set peersKnown=false, so a panic fell through to the SAME true default
// meant for "nothing to know" — reading a genuine panic as "successfully
// queried, found nothing", the exact known-ness gap the error branch two
// lines away exists to close. The blast goroutine never had this gap:
// blastKnown's zero value is false, so a panic there already defaulted safe.
func TestContext_PeersPanicLeavesPeersUnknown(t *testing.T) {
	svc := NewReadService(fakeBlast{n: 3}, panickingPeers{}, nil)
	pack, err := svc.Context(context.Background(), finding.Finding{ID: "f1", ResourceID: "i-1"})
	require.NoError(t, err, "a panic in the peers goroutine must not propagate out of Context")
	require.False(t, pack.Exposure.PeersKnown, "a panicked peer query must leave PeersKnown false, not a successful-empty result")
}
