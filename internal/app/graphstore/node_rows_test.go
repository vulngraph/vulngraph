package graphstore

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// typePerLabel returns one representative asset type for every node label that
// has a loader. Derived from assetTypeToNode (sorted, so it is deterministic)
// plus a catch-all type for NodeAsset — promoting a new type off Asset therefore
// cannot leave a label untested.
func typePerLabel(t *testing.T) map[string]string {
	t.Helper()
	types := make([]string, 0, len(assetTypeToNode))
	for ty := range assetTypeToNode {
		types = append(types, ty)
	}
	sort.Strings(types)

	byLabel := map[string]string{NodeAsset: "s3_bucket"}
	for _, ty := range types {
		lbl := assetTypeToNode[ty]
		if _, ok := byLabel[lbl]; !ok {
			byLabel[lbl] = ty
		}
	}
	for lbl := range nodeCSVCols {
		require.Contains(t, byLabel, lbl, "no asset type maps to label %s", lbl)
	}
	return byLabel
}

// Every node label's row must carry exactly the columns nodeCSVCols declares —
// no more, no fewer. appendNodeValues emits positionally and buildNodeRows zips
// the values back onto those column names, so a label whose value count drifts
// from its column list would shift every subsequent column's value into the
// wrong Ladybug property (or fail the COPY write outright).
func TestNodeRowKeysMatchCSVColumns(t *testing.T) {
	for label, ty := range typePerLabel(t) {
		if _, ok := nodeCSVCols[label]; !ok {
			continue // label has no loader (ElasticIP, DNSZone, IamPolicy)
		}
		a := asset.Asset{ID: "id-1", Name: "n", Type: ty, Provider: "aws"}
		byLabel := buildNodeRows([]asset.Asset{a}, nil, nil, true)
		rows := byLabel[label]
		require.Len(t, rows, 1, "label %s produced no row for type %s", label, ty)

		got := make([]string, 0, len(rows[0]))
		for k := range rows[0] {
			got = append(got, k)
		}
		want := append([]string(nil), nodeCSVCols[label]...)
		sort.Strings(got)
		sort.Strings(want)
		assert.Equal(t, want, got, "label %s row keys must match its CSV columns", label)
	}
}

// maxNodeCols sizes the buffer appendNodeValues appends into. Undersizing it
// only costs a realloc, but the constant is documentation of the widest label
// and must not silently drift from it.
func TestNodeValueBufferFitsEveryLabel(t *testing.T) {
	widest := 0
	for _, cols := range nodeCSVCols {
		if len(cols) > widest {
			widest = len(cols)
		}
	}
	assert.Equal(t, widest, maxNodeCols)
}

// The positional emit must land every value on the column that carries it. A
// reorder inside appendNodeValues keeps the key SET intact (so the parity test
// above still passes) while silently swapping, say, region into account_id — the
// exact class of defect column-order-by-position introduces. Full map equality
// per label is the pin.
func TestNodeRowValuesLandOnTheRightColumns(t *testing.T) {
	assets := []asset.Asset{
		{
			ID: "asset-1", Name: "web", Type: "s3_bucket", Provider: "aws",
			Region: "eu-west-1", AccountID: "111", RiskScore: 42,
			Metadata: map[string]string{
				"encrypted": "true", "public": "true", "public_tier": "confirmed",
				"expires_at": "2026-09-01", "days_until_expiry": "29", "expiring_soon": "true",
			},
		},
		{
			ID: "role-1", Name: "deployer", Type: "iam_role", Provider: "aws",
			Region: "eu-west-1", AccountID: "222", RiskScore: 7,
			Metadata: map[string]string{"trust_entry": "federated"},
		},
		{
			ID: "pkg-1", Name: "lodash", Type: "package", Provider: "github",
			Metadata: map[string]string{"ecosystem": "npm", "version": "4.17.21"},
		},
		{
			ID: "pod-1", Name: "api", Type: "k8s_pod", Provider: "gcp",
			Region: "europe-west4", AccountID: "proj", RiskScore: 9,
		},
		{ID: "subnet-1", Name: "private", Type: "subnet", Provider: "aws", Region: "eu-west-1", AccountID: "333", RiskScore: 1},
		{ID: "acct-1", Name: "prod", Type: "cloud_account", Provider: "aws", AccountID: "444"},
		{ID: "repo-1", Name: "graph", Type: "github_repo", Provider: "github"},
		{ID: "grp-1", Name: "engineers", Type: "sso_group", Provider: "aws"},
		{
			ID: "ps-1", Name: "AdministratorAccess", Type: "sso_permission_set",
			Provider: "aws", AccountID: "555", Metadata: map[string]string{"grants_admin": "true"},
		},
	}
	sigs := map[string]NodeSignals{
		"asset-1": {HasKEV: true, Exploitable: true, MaxScore: 90, PrivescCount: 2},
		"role-1":  {PrivescCount: 3, MaxScore: 55},
		"pkg-1":   {HasKEV: true, MaxScore: 80, CveID: "CVE-2021-23337", EPSSScore: 0.42},
		"pod-1":   {MaxScore: 30},
	}
	// asset-1 is internet-exposed (and privesc-capable → toxic combo); pod-1 is one
	// hop behind it.
	edges := []asset.Edge{
		{SrcID: "asset-1", SrcType: "s3_bucket", DstID: InternetNodeID, EdgeType: "exposed_to_internet"},
		{SrcID: "asset-1", SrcType: "s3_bucket", DstID: "pod-1", DstType: "k8s_pod", EdgeType: "targets"},
	}

	byLabel := buildNodeRows(assets, edges, sigs, true)
	rowOf := func(label, id string) map[string]any {
		for _, r := range byLabel[label] {
			if r["id"] == id {
				return r
			}
		}
		t.Fatalf("no %s row for %s", label, id)
		return nil
	}

	assert.Equal(t, map[string]any{
		"id": "asset-1", "name": "web", "type": "s3_bucket", "provider": "aws",
		"region": "eu-west-1", "account_id": "111", "score": int32(42),
		"exposed": int32(1), "has_kev": int32(1), "exploitable": int32(1), "toxic_combo": int32(1),
		"max_score": int32(90), "privesc_count": int32(2), "internet_hops": int32(0),
		"encrypted": assetEncrypted(assets[0].Metadata), "public": assetPublic(assets[0].Metadata),
		"public_tier": assetPublicTier(assets[0].Metadata),
		"expires_at":  "2026-09-01", "days_until_expiry": int32(29), "expiring_soon": int32(1),
	}, rowOf(NodeAsset, "asset-1"))

	assert.Equal(t, map[string]any{
		"id": "role-1", "name": "deployer", "provider": "aws", "account_id": "222",
		"score": int32(7), "type": "iam_role", "region": "eu-west-1",
		"exposed": int32(0), "has_kev": int32(0), "exploitable": int32(0), "toxic_combo": int32(0),
		"max_score": int32(55), "privesc_count": int32(3), "internet_hops": int32(ReachNone),
		"trust_entry": "federated",
	}, rowOf(NodeIamRole, "role-1"))

	assert.Equal(t, map[string]any{
		"id": "pkg-1", "name": "lodash", "ecosystem": "npm", "version": "4.17.21",
		"score": int32(80), "has_kev": int32(1), "exploitable": int32(0),
		"cve_id": "CVE-2021-23337", "epss_score": 0.42,
	}, rowOf(NodePackage, "pkg-1"))

	assert.Equal(t, map[string]any{
		"id": "pod-1", "name": "api", "type": "k8s_pod", "provider": "gcp",
		"region": "europe-west4", "account_id": "proj", "score": int32(9),
		"exposed": int32(0), "has_kev": int32(0), "exploitable": int32(0), "toxic_combo": int32(0),
		"max_score": int32(30), "privesc_count": int32(0), "internet_hops": int32(1),
	}, rowOf(NodeK8sWorkload, "pod-1"))

	assert.Equal(t, map[string]any{
		"id": "subnet-1", "name": "private", "type": "subnet", "provider": "aws",
		"region": "eu-west-1", "account_id": "333", "score": int32(1),
	}, rowOf(NodeSubnet, "subnet-1"))

	assert.Equal(t, map[string]any{
		"id": "acct-1", "name": "prod", "provider": "aws", "account_id": "444",
	}, rowOf(NodeCloudAccount, "acct-1"))

	assert.Equal(t, map[string]any{"id": "repo-1", "name": "graph", "provider": "github"}, rowOf(NodeRepo, "repo-1"))
	assert.Equal(t, map[string]any{"id": "grp-1", "name": "engineers", "provider": "aws"}, rowOf(NodeSSOGroup, "grp-1"))

	assert.Equal(t, map[string]any{
		"id": "ps-1", "name": "AdministratorAccess", "provider": "aws",
		"account_id": "555", "grants_admin": int32(1),
	}, rowOf(NodeSSOPermSet, "ps-1"))
}

// The streamed CSV the COPY loader feeds Ladybug must be exactly what the row maps
// say — same header, same values, same row count. This is the seam the streaming
// rewrite introduced: buildNodeRows is still what bulkSync and most tests
// exercise, so nothing else would notice the two drifting apart.
func TestNodeCSVSetMatchesRowMaps(t *testing.T) {
	assets, edges, sigs := copyFixture()

	dir := t.TempDir()
	csvs := newNodeCSVSet(dir)
	nodeLabel := map[string]string{}
	require.NoError(t, streamNodeRows(assets, newReachOverlay(edges), sigs, true, nodeLabel, csvs.write))
	require.NoError(t, csvs.close())

	byLabel := buildNodeRows(assets, edges, sigs, true)
	require.Len(t, csvs.labels, len(byLabel), "one CSV per label with rows")

	for label, rows := range byLabel {
		e := csvs.files[label]
		require.NotNil(t, e, "no CSV written for label %s", label)
		assert.Equal(t, len(rows), e.rows)

		f, err := os.Open(filepath.Clean(e.path))
		require.NoError(t, err)
		r := csv.NewReader(f)
		r.Comma = '|'
		recs, err := r.ReadAll()
		require.NoError(t, f.Close())
		require.NoError(t, err)

		cols := nodeCSVCols[label]
		require.Len(t, recs, len(rows)+1, "header + one line per row for %s", label)
		assert.Equal(t, cols, recs[0])
		for i, row := range rows {
			want := make([]string, len(cols))
			for j, c := range cols {
				want[j] = formatCSVValue(row[c])
			}
			assert.Equal(t, want, recs[i+1], "%s row %d", label, i)
		}
	}

	// nodeLabel is the dedup set AND the rel endpoint index: every emitted node,
	// exactly once, under the label it was written to.
	total := 0
	for _, e := range csvs.files {
		total += e.rows
	}
	assert.Len(t, nodeLabel, total)
	for label, rows := range byLabel {
		for _, row := range rows {
			assert.Equal(t, label, nodeLabel[row["id"].(string)])
		}
	}
}

// The whole point of streaming: the COPY loader must not build a second copy of
// the node set beside the asset slice it reads from. At large scale (over a
// million nodes) the map-per-node form is gigabytes of live heap held concurrently
// with the source assets, a spike that can push the worker over its memory
// limit. Measured as retained heap, because transient garbage was never the
// problem — the retention was.
func TestStreamNodeRowsRetainsNoRowSet(t *testing.T) {
	if testing.Short() {
		t.Skip("allocation measurement skipped under -short")
	}
	const n = 50_000
	assets := make([]asset.Asset, 0, n)
	for i := 0; i < n; i++ {
		assets = append(assets, asset.Asset{
			ID: "asset-" + itoa(i), Name: "svc-" + itoa(i), Type: "load_balancer",
			Provider: asset.ProviderAWS, Region: "eu-west-1", AccountID: "111", RiskScore: 200,
		})
	}

	// Streamed first: it retains only the nodeLabel index the COPY loader needs
	// anyway (and which replaced the separate nodeIDs and dedup sets), so the
	// baseline for the map measurement stays clean.
	streamed, streamedAllocs := retainedHeap(func() any {
		nodeLabel := make(map[string]string, len(assets))
		rows := 0
		err := streamNodeRows(assets, reachOverlay{}, nil, true, nodeLabel, func(string, string, []any) error {
			rows++
			return nil
		})
		require.NoError(t, err)
		require.Equal(t, n, rows)
		return nodeLabel
	})
	mapped, mappedAllocs := retainedHeap(func() any {
		return buildNodeRows(assets, nil, nil, true)
	})

	t.Logf("%d nodes — map rows: %d B retained (%.1f MiB), %d allocations; streamed: %d B retained (%.1f MiB), %d allocations",
		n, mapped, float64(mapped)/(1<<20), mappedAllocs, streamed, float64(streamed)/(1<<20), streamedAllocs)
	assert.Less(t, streamed*5, mapped,
		"streaming must retain a small fraction of the map-per-node form")
	// Both paths box each string value into an `any`; only the map path allocates a
	// map (plus its internals) per node on top of that, and only the map path keeps
	// any of it alive.
	assert.Less(t, streamedAllocs, mappedAllocs,
		"the map form allocates a map per node the streamed form does not")
}

// retainedHeap reports the live heap fn's result holds onto, in bytes, and how
// many heap objects fn allocated in total.
func retainedHeap(fn func() any) (heap, mallocs uint64) {
	runtime.GC()
	runtime.GC() // second pass settles anything the first made unreachable
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	v := fn()
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(v)
	mallocs = after.Mallocs - before.Mallocs
	if after.HeapAlloc < before.HeapAlloc {
		return 0, mallocs
	}
	return after.HeapAlloc - before.HeapAlloc, mallocs
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [12]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

// TestNodeRowsExposedIsConfirmedOnly pins the split between the two things
// an exposed_to_internet edge now means. The BFS seeds on BOTH tiers (see
// TestInternetHopsSeedTier) so a possible-tier serverless entry point has a
// finite distance; the `exposed` node flag stays CONFIRMED-only because it is an
// assertion, not a distance — it labels the node in the UI, it gates
// toxic_combo, and it is the independent witness the adjudicator corroborates a
// demotion against. Collapsing the two would have many possible-tier cloud
// functions asserting observed unauthenticated exposure.
func TestNodeRowsExposedIsConfirmedOnly(t *testing.T) {
	assets := []asset.Asset{
		{ID: "fn-possible", Type: "lambda_function"},
		{ID: "fn-confirmed", Type: "lambda_function"},
		{ID: "lb-untiered", Type: "load_balancer"},
	}
	exposure := func(src, tier string) asset.Edge {
		e := asset.Edge{SrcID: src, SrcType: "lambda_function", EdgeType: "exposed_to_internet", DstID: InternetNodeID}
		if tier != "" {
			e.Properties = map[string]string{asset.EdgePropPublicAccess: tier}
		}
		return e
	}
	edges := []asset.Edge{
		exposure("fn-possible", asset.PublicAccessPossible),
		exposure("fn-confirmed", asset.PublicAccessConfirmed),
		exposure("lb-untiered", ""),
	}

	got := map[string]bool{}
	for _, rows := range buildNodeRows(assets, edges, nil, true) {
		for _, r := range rows {
			id, _ := r["id"].(string)
			exposed, _ := r["exposed"].(int32)
			got[id] = exposed == 1
		}
	}

	assert.False(t, got["fn-possible"], "a possible-tier edge must not assert observed exposure")
	assert.True(t, got["fn-confirmed"])
	assert.True(t, got["lb-untiered"], "an untiered legacy edge must keep asserting exposure")
}

func TestAppendCertValuesDaysUntilExpiry(t *testing.T) {
	for name, tc := range map[string]struct {
		days string
		want int32
	}{
		"unset":      {"", 0},
		"positive":   {"29", 29},
		"negative":   {"-5", -5},
		"garbage":    {"soon", 0},
		"over int32": {"2147483648", 0},
		"wraps":      {"4294967325", 0},
	} {
		t.Run(name, func(t *testing.T) {
			got := appendCertValues(nil, map[string]string{"days_until_expiry": tc.days})
			require.Equal(t, tc.want, got[1])
		})
	}
}
