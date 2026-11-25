package asset

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeRepo is an in-memory asset graph for service tests.
type fakeRepo struct {
	highWater time.Time
	assets    map[string]Asset
	edges     map[string][]Edge // by src id
	// livePackages backs LivePackageIDs; packagePageSize the keyset page size.
	livePackages    map[string]bool
	packagePageSize int
	// byIDsErr fails the batch node hydration mid-walk, the way a ClickHouse
	// memory or timeout error does. See TestBlastRadius_HydrationFailureErrors.
	byIDsErr error
	// imageBases backs UpsertImageBases/ImageBases.
	imageBases []ImageBase
	// searchCalls counts List calls carrying a free-text Search filter — the
	// six-column ILIKE scan. See TestResolveID_UsesEqualityLookupNotSubstringScan:
	// a correctness test alone cannot catch ResolveID regressing back to this
	// path, because both FindByExactName and a substring List() converge on the
	// same answer through this fake (ResolveID re-checks for an exact match in
	// Go either way) — only a call-shape assertion can, which is exactly the
	// production distinction that matters (an indexable equality query vs. an
	// unindexable six-column wildcard scan that is expensive at scale).
	searchCalls int
	// byIDsCallSizes records the length of each ids slice ByIDs was called
	// with — see TestIngest_ChunksFirstDiscoveredAtLookup, which pins that a
	// large Ingest batch never sends one unchunked IN-list-sized ByIDs call
	// (an ARN-length id batch in one IN clause can exceed ClickHouse's 262,144-byte max_query_size).
	byIDsCallSizes []int
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{assets: map[string]Asset{}, edges: map[string][]Edge{}}
}

func (f *fakeRepo) addAsset(id string) { f.assets[id] = Asset{ID: id, Name: id} }
func (f *fakeRepo) link(src, dst, kind string) {
	f.edges[src] = append(f.edges[src], Edge{SrcID: src, DstID: dst, EdgeType: kind})
}

func (f *fakeRepo) UpsertAssets(_ context.Context, assets []Asset) error {
	for _, a := range assets {
		f.assets[a.ID] = a
	}
	return nil
}

func (f *fakeRepo) UpsertEdges(_ context.Context, edges []Edge) error {
	for _, e := range edges {
		f.edges[e.SrcID] = append(f.edges[e.SrcID], e)
	}
	return nil
}

func (f *fakeRepo) GetAsset(_ context.Context, id string) (Asset, error) {
	a, ok := f.assets[id]
	if !ok {
		return Asset{}, ErrNotFound
	}
	return a, nil
}

func (f *fakeRepo) ByIDs(_ context.Context, ids []string) ([]Asset, error) {
	f.byIDsCallSizes = append(f.byIDsCallSizes, len(ids))
	if f.byIDsErr != nil {
		return nil, f.byIDsErr
	}
	var out []Asset
	for _, id := range ids {
		if a, ok := f.assets[id]; ok {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f *fakeRepo) ExistingIDs(_ context.Context, ids []string) ([]string, error) {
	var out []string
	for _, id := range ids {
		if _, ok := f.assets[id]; ok {
			out = append(out, id)
		}
	}
	return out, nil
}

// LiveIDs: the fake has no last_seen model, so presence is liveness. Tests that
// need the ephemeral gate itself live in optimize_test.go against the real SQL.
func (f *fakeRepo) LiveIDs(ctx context.Context, ids []string) ([]string, error) {
	return f.ExistingIDs(ctx, ids)
}

// VerifyExpiredEphemeral: the fake has no liveness model beyond presence, so
// nothing it holds is ever a verified corpse. Tests that need the real
// ephemeral-liveness gate live in optimize_test.go / liveness_integration_test.go
// against the real SQL.
func (f *fakeRepo) VerifyExpiredEphemeral(context.Context, []string) (map[string]bool, error) {
	return map[string]bool{}, nil
}

func (f *fakeRepo) ProviderHighWater(context.Context, string) (time.Time, error) {
	return f.highWater, nil
}

func (f *fakeRepo) TypeHighWater(context.Context, string) (time.Time, error) {
	return f.highWater, nil
}

func (f *fakeRepo) TableStats(context.Context, string) (TableStats, error) {
	return TableStats{}, nil
}

func (f *fakeRepo) OptimizeTable(context.Context, string) error { return nil }

func (f *fakeRepo) ProviderStaleness(context.Context, int) ([]ProviderStaleness, error) {
	return nil, nil
}

func (f *fakeRepo) ProviderDimensionCounts(context.Context) ([]ProviderDimensions, error) {
	return nil, nil
}

func (f *fakeRepo) List(_ context.Context, filter Filter) ([]Asset, error) {
	if filter.Search != "" {
		f.searchCalls++
	}
	out := make([]Asset, 0, len(f.assets))
	for _, a := range f.assets {
		if filter.Provider != "" && string(a.Provider) != filter.Provider {
			continue
		}
		if filter.Type != "" && a.Type != filter.Type {
			continue
		}
		if filter.Search != "" &&
			!strings.Contains(a.ID, filter.Search) && !strings.Contains(a.Name, filter.Search) {
			continue
		}
		out = append(out, a)
	}
	// Deterministic order: ranging a map is random, and Limit truncation below
	// would otherwise return an arbitrary match.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, nil
}

func (f *fakeRepo) FindByExactName(_ context.Context, name string, limit int) ([]Asset, error) {
	var out []Asset
	for _, a := range f.assets {
		if a.Name == name {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeRepo) IsExposedEdge(_ context.Context, _ string) (bool, error) { return false, nil }
func (f *fakeRepo) AllEdgesForSync(_ context.Context, _ SyncProjection) (EdgeSyncResult, error) {
	var out []Edge
	for _, es := range f.edges {
		out = append(out, es...)
	}
	return EdgeSyncResult{Edges: out}, nil
}

func (f *fakeRepo) ListAllForSync(_ context.Context, _ SyncProjection) (AssetSyncResult, error) {
	out := make([]Asset, 0, len(f.assets))
	for _, a := range f.assets {
		out = append(out, a)
	}
	return AssetSyncResult{Assets: out}, nil
}

func (f *fakeRepo) WriteChangeLog(_ context.Context, _ string, _ []FieldChange) error { return nil }
func (f *fakeRepo) ChangeLog(_ context.Context, _ string, _ int) ([]FieldChange, error) {
	return nil, nil
}

func (f *fakeRepo) PurgeAccount(_ context.Context, provider, accountID string) (int, error) {
	n := 0
	for id, a := range f.assets {
		if string(a.Provider) == provider && a.AccountID == accountID {
			delete(f.assets, id)
			n++
		}
	}
	return n, nil
}

func (f *fakeRepo) AssetIDsByAccount(_ context.Context, provider, accountID string) ([]string, error) {
	var ids []string
	for id, a := range f.assets {
		if string(a.Provider) == provider && a.AccountID == accountID {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (f *fakeRepo) UpsertImageBases(_ context.Context, bases []ImageBase) error {
	f.imageBases = append(f.imageBases, bases...)
	return nil
}

func (f *fakeRepo) ImageBases(_ context.Context) ([]ImageBase, error) {
	return f.imageBases, nil
}

func TestService_ImageBasesRoundTrip(t *testing.T) {
	svc := NewService(newFakeRepo())
	in := []ImageBase{{ImageID: "image/sha256:a", BaseImageSource: "os_release", BaseOS: "Debian:12", ScannedAt: time.Now()}}
	require.NoError(t, svc.RecordImageBases(context.Background(), in))
	got, err := svc.ImageBases(context.Background())
	require.NoError(t, err)
	require.Equal(t, in, got)
}

func (f *fakeRepo) PurgeEdgesForAssets(_ context.Context, ids []string) (int, error) {
	match := make(map[string]bool, len(ids))
	for _, id := range ids {
		match[id] = true
	}
	n := 0
	for src, es := range f.edges {
		var kept []Edge
		if match[src] {
			n += len(es)
			continue
		}
		for _, e := range es {
			if match[e.DstID] {
				n++
				continue
			}
			kept = append(kept, e)
		}
		f.edges[src] = kept
	}
	return n, nil
}

func (f *fakeRepo) Summary(_ context.Context) (Summary, error) {
	out := Summary{ByProvider: map[string]int{}, ByType: map[string]int{}}
	for _, a := range f.assets {
		out.ByProvider[string(a.Provider)]++
		out.ByType[a.Type]++
		out.Total++
	}
	return out, nil
}

func (f *fakeRepo) ListExternal(_ context.Context, limit int) ([]Asset, error) {
	var out []Asset
	for _, a := range f.assets {
		if a.PublicIP != "" || a.Domain != "" {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f *fakeRepo) ListByType(_ context.Context, assetType string, _ int) ([]Asset, error) {
	var out []Asset
	for _, a := range f.assets {
		if a.Type == assetType {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f *fakeRepo) PackageRunners(_ context.Context, _ []string) ([]PackageRunner, error) {
	return nil, nil
}

func (f *fakeRepo) LivePackageIDs(_ context.Context) (map[string]bool, error) {
	return f.livePackages, nil
}

// PackageCoordsAfter pages f.assets' packages in id order, pageSize per page.
func (f *fakeRepo) PackageCoordsAfter(_ context.Context, after string) ([]PackageCoord, string, error) {
	var ids []string
	byID := map[string]Asset{}
	for _, a := range f.assets {
		if a.Type == "package" && a.ID > after {
			ids = append(ids, a.ID)
			byID[a.ID] = a
		}
	}
	sort.Strings(ids)
	ids = ids[:min(len(ids), f.packagePageSize)]
	out := make([]PackageCoord, 0, len(ids))
	next := ""
	for _, id := range ids {
		out = append(out, PackageCoord{ID: id, Metadata: byID[id].Metadata})
		next = id
	}
	return out, next, nil
}

func (f *fakeRepo) CountPackages(_ context.Context) (int64, error) {
	return 0, nil
}

func (f *fakeRepo) EdgesFrom(_ context.Context, srcIDs []string) ([]Edge, error) {
	var out []Edge
	for _, id := range srcIDs {
		out = append(out, f.edges[id]...)
	}
	return out, nil
}

func (f *fakeRepo) EdgesTo(_ context.Context, dstIDs []string) ([]Edge, error) {
	want := map[string]bool{}
	for _, id := range dstIDs {
		want[id] = true
	}
	var out []Edge
	for _, edges := range f.edges {
		for _, e := range edges {
			if want[e.DstID] {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func (f *fakeRepo) EdgesInto(_ context.Context, dstID, edgeType string) ([]Edge, error) {
	var out []Edge
	for _, edges := range f.edges {
		for _, e := range edges {
			if e.DstID == dstID && e.EdgeType == edgeType {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func (f *fakeRepo) EdgesIntoTypes(_ context.Context, dstID string, edgeTypes []string) ([]Edge, error) {
	want := map[string]bool{}
	for _, t := range edgeTypes {
		want[t] = true
	}
	var out []Edge
	for _, edges := range f.edges {
		for _, e := range edges {
			if e.DstID == dstID && want[e.EdgeType] {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func (f *fakeRepo) EdgesOut(_ context.Context, srcID, edgeType string) ([]Edge, error) {
	var out []Edge
	for _, e := range f.edges[srcID] {
		if e.EdgeType == edgeType {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeRepo) EdgesOutBatch(_ context.Context, srcIDs []string, edgeType string) ([]Edge, error) {
	var out []Edge
	for _, id := range srcIDs {
		for _, e := range f.edges[id] {
			if e.EdgeType == edgeType {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func (f *fakeRepo) CurrentHashesByConnector(_ context.Context, connectorID string) (map[string]string, error) {
	out := map[string]string{}
	for _, a := range f.assets {
		if a.Metadata["prov_connector_id"] == connectorID {
			out[a.ID] = ContentHash(a)
		}
	}
	return out, nil
}

func assetIDs(br BlastRadius) []string {
	ids := make([]string, 0, len(br.Assets))
	for _, a := range br.Assets {
		ids = append(ids, a.ID)
	}
	return ids
}

func TestBlastRadius_SeedNotFound(t *testing.T) {
	svc := NewService(newFakeRepo())
	_, err := svc.BlastRadius(context.Background(), "ghost", 2)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestBlastRadius_IsolatedSeed(t *testing.T) {
	repo := newFakeRepo()
	repo.addAsset("a")
	svc := NewService(repo)

	br, err := svc.BlastRadius(context.Background(), "a", 3)
	require.NoError(t, err)
	require.Equal(t, []string{"a"}, assetIDs(br))
	require.False(t, br.Truncated)
}

// TestBlastRadius_HydrationFailureErrors pins the walk's refusal to invent
// nodes it could not read.
//
// The batch hydration used to swallow its error (`fetched = nil // degrade to
// stubs below`) and keep walking, substituting Asset{ID, Type} placeholders for
// every node in the hop: no Provider, no RiskScore, no LastSeen. The COUNT
// stayed right, which is why nothing noticed — but summarizeBlast's ByType and
// topReachable render those placeholders to the LLM reasoner as measurements,
// Truncated stayed false so the reason-cache fingerprint did not even change,
// and the whole thing was returned with a nil error. respond.blastRadiusFor,
// whose decisions a person approves on that number, cannot tell a hydrated walk from
// a stubbed one, so the only honest answer is the error.
func TestBlastRadius_HydrationFailureErrors(t *testing.T) {
	repo := newFakeRepo()
	repo.addAsset("a")
	repo.addAsset("b")
	repo.link("a", "b", "runs_in")
	repo.byIDsErr = errors.New("clickhouse: Code: 241 Memory limit (total) exceeded")
	svc := NewService(repo)

	_, err := svc.BlastRadius(context.Background(), "a", 2)
	require.ErrorContains(t, err, "hydrate",
		"a hydration failure must propagate, not degrade to stub assets with a nil error")
}

func TestBlastRadius_RespectsDepth(t *testing.T) {
	repo := newFakeRepo()
	for _, id := range []string{"a", "b", "c", "d"} {
		repo.addAsset(id)
	}
	repo.link("a", "b", "runs_in")
	repo.link("b", "c", "runs_in")
	repo.link("c", "d", "runs_in")
	svc := NewService(repo)

	br, err := svc.BlastRadius(context.Background(), "a", 2)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"a", "b", "c"}, assetIDs(br), "depth 2 reaches a→b→c but not d")
}

func TestBlastRadiusDir_InAndBoth(t *testing.T) {
	repo := newFakeRepo()
	for _, id := range []string{"a", "b", "c"} {
		repo.addAsset(id)
	}
	// a → b → c : b is the seed; a reaches it, it reaches c.
	repo.link("a", "b", "runs_in")
	repo.link("b", "c", "runs_in")
	svc := NewService(repo)

	out, err := svc.BlastRadiusDir(context.Background(), "b", 3, DirOut)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"b", "c"}, assetIDs(out), "out: b can reach c")

	in, err := svc.BlastRadiusDir(context.Background(), "b", 3, DirIn)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"b", "a"}, assetIDs(in), "in: a can reach b")

	both, err := svc.BlastRadiusDir(context.Background(), "b", 3, DirBoth)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"a", "b", "c"}, assetIDs(both), "both: full neighbourhood")
}

func TestBlastRadius_DefaultDepthWhenZero(t *testing.T) {
	repo := newFakeRepo()
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		repo.addAsset(id)
	}
	repo.link("a", "b", "x")
	repo.link("b", "c", "x")
	repo.link("c", "d", "x")
	repo.link("d", "e", "x")
	svc := NewService(repo)

	br, err := svc.BlastRadius(context.Background(), "a", 0)
	require.NoError(t, err)
	require.Equal(t, defaultMaxDepth, br.MaxDepth)
	require.ElementsMatch(t, []string{"a", "b", "c", "d"}, assetIDs(br), "default depth 3 stops before e")
}

func TestBlastRadius_HandlesCycle(t *testing.T) {
	repo := newFakeRepo()
	repo.addAsset("a")
	repo.addAsset("b")
	repo.link("a", "b", "x")
	repo.link("b", "a", "x") // cycle must not loop forever
	svc := NewService(repo)

	br, err := svc.BlastRadius(context.Background(), "a", 10)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"a", "b"}, assetIDs(br))
}

func TestBlastRadius_DanglingEdgeRecordedAsStub(t *testing.T) {
	repo := newFakeRepo()
	repo.addAsset("a")
	repo.link("a", "missing", "deploys_to") // target never collected
	svc := NewService(repo)

	br, err := svc.BlastRadius(context.Background(), "a", 2)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"a", "missing"}, assetIDs(br))
}

func TestBlastRadius_TruncatesAtNodeBudget(t *testing.T) {
	repo := newFakeRepo()
	repo.addAsset("seed")
	// Fan out wider than the node budget from a single hop.
	for i := 0; i < maxNodeBudget+50; i++ {
		id := "n" + strconv.Itoa(i)
		repo.addAsset(id)
		repo.link("seed", id, "x")
	}
	svc := NewService(repo)

	br, err := svc.BlastRadius(context.Background(), "seed", 5)
	require.NoError(t, err)
	require.True(t, br.Truncated)
	require.LessOrEqual(t, len(br.Assets), maxNodeBudget+1)
}

func TestList_ReturnsAllAssets(t *testing.T) {
	repo := newFakeRepo()
	repo.addAsset("a")
	repo.addAsset("b")
	svc := NewService(repo)

	got, err := svc.List(context.Background(), Filter{})
	require.NoError(t, err)
	require.Len(t, got, 2)
}

func TestListByType_FiltersOnType(t *testing.T) {
	repo := newFakeRepo()
	require.NoError(t, repo.UpsertAssets(context.Background(), []Asset{
		{ID: "org/repo", Type: "github_repo"},
		{ID: "pkg:npm/lodash@4.17.21", Type: "package"},
	}))
	svc := NewService(repo)

	got, err := svc.ListByType(context.Background(), "package", 0)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "pkg:npm/lodash@4.17.21", got[0].ID)
}

func TestIngestThenGet(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)

	want := Asset{ID: "arn:x", Name: "web", Type: "ec2_instance", Provider: ProviderAWS, RiskScore: 42}
	require.NoError(t, svc.Ingest(context.Background(), []Asset{want}, []Edge{{SrcID: "arn:x", DstID: "sg-1", EdgeType: "protected_by"}}))

	got, err := svc.Get(context.Background(), "arn:x")
	require.NoError(t, err)
	require.Equal(t, want, got)
}

// TestIngest_PinsFirstDiscoveredAtAcrossReCollection pins the actual bug this
// column exists to fix: a collector re-stamping DiscoveredAt to `now` on
// every sweep must not reset how long an asset has actually existed. The
// second Ingest call simulates a re-collection sweep (DiscoveredAt jumps to
// "now", FirstDiscoveredAt left unset by the collector, same as every real
// producer) — the true first-observation time must survive.
func TestIngest_PinsFirstDiscoveredAtAcrossReCollection(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	ctx := context.Background()

	firstSeen := time.Now().Add(-90 * 24 * time.Hour)
	require.NoError(t, svc.Ingest(ctx, []Asset{{ID: "arn:x", DiscoveredAt: firstSeen}}, nil))

	got, err := svc.Get(ctx, "arn:x")
	require.NoError(t, err)
	require.True(t, got.FirstDiscoveredAt.IsZero(), "a brand-new asset's collector never sets FirstDiscoveredAt")

	// Re-collection: the collector stamps `now`, same as every real producer.
	require.NoError(t, svc.Ingest(ctx, []Asset{{ID: "arn:x", DiscoveredAt: time.Now()}}, nil))

	got, err = svc.Get(ctx, "arn:x")
	require.NoError(t, err)
	require.WithinDuration(t, firstSeen, got.FirstDiscoveredAt, time.Second,
		"FirstDiscoveredAt must carry the ORIGINAL observation forward, not the re-collection's DiscoveredAt")
}

// TestIngest_PinFirstDiscoveredAt_RepoErrorIsNonFatal mirrors
// finding.Service.pinFirstDetectedAt's best-effort contract: a lookup failure degrades
// (the incoming asset's own zero-value FirstDiscoveredAt ships as-is, which
// the repo's own firstDiscoveredAt() floor then covers) rather than failing
// the whole ingest.
func TestIngest_PinFirstDiscoveredAt_RepoErrorIsNonFatal(t *testing.T) {
	repo := newFakeRepo()
	repo.byIDsErr = errors.New("clickhouse: timeout")
	svc := NewService(repo)

	err := svc.Ingest(context.Background(), []Asset{{ID: "arn:x", DiscoveredAt: time.Now()}}, nil)
	require.NoError(t, err, "a ByIDs lookup failure must not fail Ingest")
}

// TestIngest_ChunksFirstDiscoveredAtLookup: pinFirstDiscoveredAt's ByIDs
// lookup must not send the ENTIRE incoming batch as one IN clause — a full
// connector-sync Ingest call can carry thousands of ARN/DNS-shaped ids, and
// ClickHouse's IN clause is query-string-interpolated (no true bind-parameter
// form), so an unchunked call risks exceeding max_query_size exactly the way
// internal/jobs/sync.go's maxPartialCorrelateIDs and asset.purgeEdgeChunk
// already guard against for the same ARN-length ids. No single ByIDs call
// here may exceed pinFirstDiscoveredAtChunkSize.
func TestIngest_ChunksFirstDiscoveredAtLookup(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)

	n := pinFirstDiscoveredAtChunkSize*2 + 137
	assets := make([]Asset, n)
	for i := range assets {
		assets[i] = Asset{ID: "arn:" + strconv.Itoa(i), DiscoveredAt: time.Now()}
	}
	require.NoError(t, svc.Ingest(context.Background(), assets, nil))

	require.Len(t, repo.byIDsCallSizes, 3, "n=2*chunk+137 must split into exactly 3 ByIDs calls")
	for _, size := range repo.byIDsCallSizes {
		require.LessOrEqual(t, size, pinFirstDiscoveredAtChunkSize)
	}
}

// TestIngest_ChunkFailureIsLoggedNotSilent: a chunk-level ByIDs failure must be visible (a log line),
// not swallowed — a silent skip would reintroduce "FirstDiscoveredAt means
// last collected" invisibly for every asset in the failed chunk, forever,
// with Ingest still reporting success. This test only asserts the
// non-fatal contract (the log line itself isn't asserted — pkg/log has no
// test hook here); TestIngest_PinFirstDiscoveredAt_RepoErrorIsNonFatal covers
// the same path for a single chunk.
func TestIngest_ChunkFailureIsLoggedNotSilent(t *testing.T) {
	repo := newFakeRepo()
	repo.byIDsErr = errors.New("clickhouse: timeout")
	svc := NewService(repo)

	assets := make([]Asset, pinFirstDiscoveredAtChunkSize+10)
	for i := range assets {
		assets[i] = Asset{ID: "arn:" + strconv.Itoa(i), DiscoveredAt: time.Now()}
	}
	require.NoError(t, svc.Ingest(context.Background(), assets, nil), "a chunk failure must not fail the whole Ingest")
	require.Len(t, repo.byIDsCallSizes, 2, "both chunks are attempted even though the first errors")
}

func TestEarliest(t *testing.T) {
	older := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	driverZero := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC) // a driver-decoded DateTime(0)

	require.True(t, earliest().IsZero(), "no arguments is unknown, not epoch")
	require.True(t, earliest(time.Time{}, driverZero).IsZero(), "all-zero-equivalent inputs stay unknown")
	require.Equal(t, older, earliest(newer, older), "the earlier non-zero timestamp wins regardless of argument order")
	require.Equal(t, older, earliest(older, newer))
	require.Equal(t, older, earliest(time.Time{}, older, driverZero), "zero/epoch candidates never win over a real timestamp")
}

func TestExistingIDs_ReturnsOnlyPresent(t *testing.T) {
	repo := newFakeRepo()
	repo.addAsset("i-live1")
	repo.addAsset("i-live2")
	svc := NewService(repo)

	got, err := svc.ExistingIDs(context.Background(), []string{"i-live1", "i-gone", "i-live2", "i-also-gone"})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"i-live1", "i-live2"}, got)
}

func TestExistingIDs_EmptyInput(t *testing.T) {
	svc := NewService(newFakeRepo())
	got, err := svc.ExistingIDs(context.Background(), nil)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestResolveID(t *testing.T) {
	const (
		roleName = "example-app-TaskRole-DEF456EXAMPLE"
		roleARN  = "arn:aws:iam::210987654321:role/" + roleName
	)
	repo := newFakeRepo()
	repo.assets[roleARN] = Asset{ID: roleARN, Name: roleName, Type: "iam_role"}
	// Decoys whose ID contains roleName as a SUBSTRING (the shape that used to
	// matter when ResolveID's fallback was an ILIKE substring scan over six
	// columns — see FindByExactName's doc comment for why that was replaced
	// with an equality lookup). Kept here as a regression guard: an equality
	// match on name naturally excludes these (their Name is the decoy's own
	// full ID, not roleName), so this also proves FindByExactName isn't
	// silently falling back to substring semantics.
	for _, decoy := range []string{
		"arn:aws:iam::210987654321:instance-profile/" + roleName,
		"arn:aws:ecs:us-west-2:210987654321:task-definition/" + roleName + ":7",
		"/aws/ecs/" + roleName + "/application",
	} {
		repo.assets[decoy] = Asset{ID: decoy, Name: decoy, Type: "log_group"}
	}
	svc := NewService(repo)

	tests := []struct {
		name       string
		identifier string
		want       string
		wantErr    error
	}{
		// The aws_guardduty iam_user case: finding.ResourceID is the role name,
		// the graph node is the ARN.
		{name: "name resolves to arn", identifier: roleName, want: roleARN},
		{name: "exact id is returned as-is", identifier: roleARN, want: roleARN},
		{name: "unknown identifier", identifier: "i-doesnotexist", wantErr: ErrNotFound},
		{name: "empty identifier", identifier: "", wantErr: ErrNotFound},
		// The role name is a substring of the instance-profile ARN, the task
		// definition ARN and the log group for the same workload. Filter.Search is
		// a substring ILIKE ordered by last_seen, so any of those can be row one —
		// only the exact-name match may be accepted.
		{name: "substring matches lose to the exact name", identifier: roleName, want: roleARN},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := svc.ResolveID(context.Background(), tt.identifier)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestResolveID_UsesEqualityLookupNotSubstringScan is the guard TestResolveID
// itself cannot be: a correctness test alone can't distinguish FindByExactName
// from List(Filter{Search: ...}), because ResolveID re-checks for an exact
// match in Go regardless of which one supplied the candidates — both converge
// on the same answer through this fake. The distinction that actually matters
// is the query ResolveID issues, not the value it returns: FindByExactName is
// an indexable equality lookup, List's Search path is a six-column ILIKE
// wildcard scan that is expensive at scale, for a lookup that only ever
// accepts an exact match. This asserts the call shape directly.
func TestResolveID_UsesEqualityLookupNotSubstringScan(t *testing.T) {
	repo := newFakeRepo()
	repo.assets["arn:aws:iam::1:role/svc"] = Asset{ID: "arn:aws:iam::1:role/svc", Name: "svc"}
	svc := NewService(repo)

	_, err := svc.ResolveID(context.Background(), "svc")
	require.NoError(t, err)
	require.Zero(t, repo.searchCalls,
		"ResolveID's fallback must be an equality lookup (FindByExactName), never List's free-text Search path")
}

// The default blast walk follows each edge the way an attacker moves along it
// (graphschema.AttackDirection), matching the Ladybug walk: sg_allows_from is
// walked dst→src, connected_via_sg both ways, accesses_secret src→dst only.
func TestBlastRadius_FollowsAttackerDirection(t *testing.T) {
	repo := newFakeRepo()
	for _, id := range []string{"lb-a", "lb-b", "lb-c", "hub", "lb-d", "role", "secret"} {
		repo.addAsset(id)
	}
	repo.link("lb-b", "lb-a", "sg_allows_from")    // lb-b permits ingress FROM lb-a → lb-a reaches lb-b
	repo.link("lb-a", "lb-c", "sg_allows_from")    // lb-a permits ingress from lb-c → lb-a does NOT reach lb-c
	repo.link("lb-b", "hub", "connected_via_sg")   // shared SG hub, walked both ways
	repo.link("lb-d", "hub", "connected_via_sg")   // so lb-b reaches lb-d through the hub
	repo.link("role", "secret", "accesses_secret") // a role reaches its secret, not the reverse
	svc := NewService(repo)

	br, err := svc.BlastRadius(context.Background(), "lb-a", 4)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"lb-a", "lb-b", "hub", "lb-d"}, assetIDs(br))
	require.Len(t, br.Edges, 3, "a two-way edge met from both ends is listed once")

	fromSecret, err := svc.BlastRadius(context.Background(), "secret", 3)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"secret"}, assetIDs(fromSecret), "a secret does not reach the role that reads it")

	fromRole, err := svc.BlastRadius(context.Background(), "role", 3)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"role", "secret"}, assetIDs(fromRole))
}
