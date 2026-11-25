package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/graphstore"
)

// stubSignalGraph implements signalGraph. sig is returned verbatim (err==nil) on
// every TryNodeSignals call when found=true; when found=false it returns the
// exact "not found" zero-value nodeSignalByID produces — NodeSignals{InternetHops:
// ReachUnknown} — with a nil error, reproducing what a pruned/not-yet-loaded
// resource ID looks like to a caller that only checks err.
type stubSignalGraph struct {
	ready bool
	found bool
	sig   graphstore.NodeSignals
}

func (s *stubSignalGraph) Ready() bool { return s.ready }

func (s *stubSignalGraph) TryNodeSignals(context.Context, string) (graphstore.NodeSignals, error) {
	if !s.found {
		return graphstore.NodeSignals{InternetHops: graphstore.ReachUnknown}, nil
	}
	return s.sig, nil
}

// A resource TryNodeSignals cannot find (err==nil, zero-value NodeSignals) must
// fall back to ClickHouse rather than being fingerprinted as "not exposed" /
// "zero privesc findings" — a false negative: nodeSignalByID only queries Asset/IamRole, so
// a pruned dns_record or a not-yet-loaded resource returns this same shape, and
// IsExposedEdge/PrivescBucket used to trust it as a confirmed answer.
func TestLadybugGraphCtx_NotFoundFallsBackToClickHouse(t *testing.T) {
	fallbackAssets := &stubExposedFallback{exposed: true}
	fallbackFindings := &stubFindingsFallback{findings: []finding.Finding{
		{Type: "ciem_privesc", ResourceID: "r-1"}, {Type: "ciem_privesc", ResourceID: "r-1"},
	}}
	g := &ladybugGraphCtx{
		graph:            &stubSignalGraph{ready: true, found: false},
		assetsFallback:   fallbackAssets,
		findingsFallback: fallbackFindings,
	}

	exposed, err := g.IsExposedEdge(context.Background(), "r-1")
	require.NoError(t, err)
	require.True(t, exposed, "a not-found Ladybug lookup must defer to the ClickHouse fallback, not report false")
	require.Equal(t, 1, fallbackAssets.calls)

	bucket, err := g.PrivescBucket(context.Background(), "r-1")
	require.NoError(t, err)
	require.NotEqual(t, "0", bucket, "a not-found Ladybug lookup must count real findings via the ClickHouse fallback, not report zero")
}

// A resource Ladybug does have signals for is trusted directly — no ClickHouse call.
func TestLadybugGraphCtx_FoundUsesLadybugSignalsDirectly(t *testing.T) {
	fallbackAssets := &stubExposedFallback{exposed: false}
	g := &ladybugGraphCtx{
		graph:          &stubSignalGraph{ready: true, found: true, sig: graphstore.NodeSignals{Exposed: true, InternetHops: 1}},
		assetsFallback: fallbackAssets,
	}

	exposed, err := g.IsExposedEdge(context.Background(), "r-1")
	require.NoError(t, err)
	require.True(t, exposed)
	require.Zero(t, fallbackAssets.calls, "a found node must not pay for a ClickHouse fallback")
}

// ladybugPeerFindings has the identical shape of bug: a not-found node must defer
// to the ClickHouse fallback rather than report zero peer findings.
func TestLadybugPeerFindings_NotFoundFallsBackToClickHouse(t *testing.T) {
	fallback := &stubFindingsList{findings: []finding.Finding{{Type: "ciem_privesc", ResourceID: "r-1"}}}
	k := &ladybugPeerFindings{graph: &stubSignalGraph{ready: true, found: false}, fallback: fallback}

	got, err := k.List(context.Background(), finding.Filter{ResourceID: "r-1"})
	require.NoError(t, err)
	require.Equal(t, fallback.findings, got, "a not-found Ladybug lookup must defer to the ClickHouse fallback")
}

type stubExposedFallback struct {
	exposed bool
	calls   int
}

func (s *stubExposedFallback) IsExposedEdge(context.Context, string) (bool, error) {
	s.calls++
	return s.exposed, nil
}

type stubFindingsFallback struct{ findings []finding.Finding }

func (s *stubFindingsFallback) ByResourceIDs(context.Context, []string) ([]finding.Finding, error) {
	return s.findings, nil
}

type stubFindingsList struct{ findings []finding.Finding }

func (s *stubFindingsList) List(context.Context, finding.Filter) ([]finding.Finding, error) {
	return s.findings, nil
}

type stubBlastGraph struct {
	built          bool // adjacency built (mirrors blastAdj != nil)
	seed           asset.Asset
	seedOK         bool
	edges          []asset.Edge
	nodes          []asset.Asset
	hopUnavailable bool
}

func (s *stubBlastGraph) BlastSeed(string) (asset.Asset, bool) {
	if !s.built {
		return asset.Asset{}, false
	}
	return s.seed, s.seedOK
}

func (s *stubBlastGraph) TryBlastNeighbors([]string) ([]asset.Edge, []asset.Asset, bool) {
	if !s.built || s.hopUnavailable {
		return nil, nil, false
	}
	return s.edges, s.nodes, true
}

type stubBlastAssets struct {
	br    asset.BlastRadius
	calls int
}

func (s *stubBlastAssets) BlastRadius(_ context.Context, seedID string, _ int) (asset.BlastRadius, error) {
	s.calls++
	br := s.br
	br.SeedID = seedID
	return br, nil
}

func (s *stubBlastAssets) ResolveID(_ context.Context, id string) (string, error) { return id, nil }

// A seed that filterLadybugAssets pruned (no retention edge, no risk score) must be
// answered by the ClickHouse BFS, not by the Go-adjacency walk's empty result.
// A pruned population can still carry open findings; a seed miss that fell
// through to a typeless one-asset blast radius with a nil error would let
// respond size a real compromise as zero-blast, since its recovery path only
// retries on err != nil.
func TestLadybugBlastProvider_PrunedSeedFallsBackToClickHouse(t *testing.T) {
	graph := &stubBlastGraph{built: true} // pruned: BlastSeed reports not found
	assets := &stubBlastAssets{br: asset.BlastRadius{
		Assets: []asset.Asset{{ID: "rec-1", Type: "dns_record"}, {ID: "zone-1", Type: "dns_zone"}},
		Edges:  []asset.Edge{{SrcID: "rec-1", DstID: "zone-1", EdgeType: "member_of_zone"}},
	}}
	p := &ladybugBlastProvider{graph: graph, assets: assets}

	br, err := p.BlastRadius(context.Background(), "rec-1", 2)
	require.NoError(t, err)
	require.Equal(t, 1, assets.calls, "a pruned seed must reach the ClickHouse BFS")
	require.Len(t, br.Assets, 2)
	require.Equal(t, "dns_record", br.Assets[0].Type,
		"the seed must carry its type — a typeless seed is what the reasoner was being handed")
}

// A seed the retained adjacency does hold is walked in Go, with zero ClickHouse
// reads — the whole point of the provider.
func TestLadybugBlastProvider_LoadedSeedStaysInAdjacency(t *testing.T) {
	graph := &stubBlastGraph{
		built:  true,
		seed:   asset.Asset{ID: "i-1", Type: "ec2_instance", Provider: "aws"},
		seedOK: true,
		edges:  []asset.Edge{{SrcID: "i-1", DstID: "sg-1", EdgeType: "connected_via_sg"}},
		nodes:  []asset.Asset{{ID: "sg-1", Type: "security_group"}},
	}
	assets := &stubBlastAssets{}
	p := &ladybugBlastProvider{graph: graph, assets: assets}

	br, err := p.BlastRadius(context.Background(), "i-1", 1)
	require.NoError(t, err)
	require.Zero(t, assets.calls, "a loaded seed must not pay for a ClickHouse BFS")
	require.Len(t, br.Assets, 2)
	require.Len(t, br.Edges, 1)
}

func TestLadybugBlastProvider_HopUnavailableAndNotBuiltFallBack(t *testing.T) {
	assets := &stubBlastAssets{br: asset.BlastRadius{Assets: []asset.Asset{{ID: "i-1"}}}}

	// Adjacency not built yet (pre-sync startup).
	p := &ladybugBlastProvider{graph: &stubBlastGraph{}, assets: assets}
	_, err := p.BlastRadius(context.Background(), "i-1", 2)
	require.NoError(t, err)
	require.Equal(t, 1, assets.calls)

	// Hop unavailable mid-walk.
	p = &ladybugBlastProvider{
		graph:  &stubBlastGraph{built: true, seed: asset.Asset{ID: "i-1"}, seedOK: true, hopUnavailable: true},
		assets: assets,
	}
	_, err = p.BlastRadius(context.Background(), "i-1", 2)
	require.NoError(t, err)
	require.Equal(t, 2, assets.calls)
}
