package correlate

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeLoader struct {
	assets    []asset.Asset
	truncated bool
	err       error
}

func (f fakeLoader) LoadView(context.Context) ([]asset.Asset, bool, error) {
	return f.assets, f.truncated, f.err
}

func (f fakeLoader) LoadViewForTypes(_ context.Context, _ []string) ([]asset.Asset, bool, error) {
	return f.assets, f.truncated, f.err
}

func (f fakeLoader) LoadByIDs(_ context.Context, _ []string) ([]asset.Asset, error) {
	return f.assets, f.err
}

// fakeWriter is the assetStore test double. fullAssets stands in for the real
// ClickHouse row ByIDs would return — every column populated, unlike the
// correlation view's minimal projection — so tests can pin the
// fetch-full-then-merge field-preservation invariant.
type fakeWriter struct {
	got        []asset.Edge
	gotAssets  []asset.Asset
	fullAssets []asset.Asset
	err        error
}

func (f *fakeWriter) IngestEdges(_ context.Context, edges []asset.Edge) error {
	if f.err != nil {
		return f.err
	}
	f.got = append(f.got, edges...)
	return nil
}

func (f *fakeWriter) IngestAssets(_ context.Context, assets []asset.Asset) error {
	if f.err != nil {
		return f.err
	}
	f.gotAssets = append(f.gotAssets, assets...)
	return nil
}

func (f *fakeWriter) ByIDs(_ context.Context, ids []string) ([]asset.Asset, error) {
	if f.err != nil {
		return nil, f.err
	}
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	var out []asset.Asset
	for _, a := range f.fullAssets {
		if want[a.ID] {
			out = append(out, a)
		}
	}
	return out, nil
}

func TestCorrelate_WritesDerivedEdges(t *testing.T) {
	loader := fakeLoader{assets: []asset.Asset{
		dnsRecord("rec", "A", "1.2.3.4"),
		{ID: "i-1", Type: "ec2_instance", PublicIP: "1.2.3.4"},
	}}
	w := &fakeWriter{}
	svc := NewService(loader, w, []Rule{DNSPointsTo{}})

	n, err := svc.Correlate(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Len(t, w.got, 1)
	require.Equal(t, "i-1", w.got[0].DstID)
}

func TestCorrelate_EmptyGraphIsNoop(t *testing.T) {
	w := &fakeWriter{}
	svc := NewService(fakeLoader{}, w, []Rule{DNSPointsTo{}})
	n, err := svc.Correlate(context.Background())
	require.NoError(t, err)
	require.Zero(t, n)
	require.Empty(t, w.got)
}

func TestCorrelate_LoadErrorPropagates(t *testing.T) {
	svc := NewService(fakeLoader{err: errors.New("ch down")}, &fakeWriter{}, []Rule{DNSPointsTo{}})
	_, err := svc.Correlate(context.Background())
	require.ErrorContains(t, err, "ch down")
}

// TestCorrelate_FailsClosedOnTruncatedView pins that a truncated view ERRORS and
// writes nothing. It used to log a Warn instead; a view sitting just under the
// row limit is one growth spurt away from crossing it, and a warning nobody reads
// in time is not a safety mechanism. Writing a partial edge set is worse than
// writing none: unwritten edges stop being re-stamped and leave the traversable
// graph within 48h.
func TestCorrelate_FailsClosedOnTruncatedView(t *testing.T) {
	loader := fakeLoader{
		assets: []asset.Asset{
			dnsRecord("rec", "A", "1.2.3.4"),
			{ID: "i-1", Type: "ec2_instance", PublicIP: "1.2.3.4"},
		},
		truncated: true,
	}
	w := &fakeWriter{}
	svc := NewService(loader, w, []Rule{DNSPointsTo{}})

	n, err := svc.Correlate(context.Background())
	require.ErrorIs(t, err, ErrViewTruncated)
	require.Zero(t, n)
	require.Empty(t, w.got, "a truncated view must write NO edges, not a partial set")
}

// TestPartialCorrelate_FailsClosedOnTruncatedView is the regression test for a
// discarded error: the partial path took `view, _, err := LoadViewForTypes(...)`,
// so it correlated a truncated view in total silence — on the path that runs on
// EVERY connector sync, and which can approach the row limit on a large
// inventory. Before the fix this returned a nil error.
func TestPartialCorrelate_FailsClosedOnTruncatedView(t *testing.T) {
	loader := fakeLoader{
		assets: []asset.Asset{
			dnsRecord("rec", "A", "1.2.3.4"),
			{ID: "i-1", Type: "ec2_instance", PublicIP: "1.2.3.4"},
		},
		truncated: true,
	}
	w := &fakeWriter{}
	svc := NewService(loader, w, []Rule{DNSPointsTo{}})

	n, err := svc.PartialCorrelate(context.Background(), []string{"rec"})
	require.ErrorIs(t, err, ErrViewTruncated)
	require.Zero(t, n)
	require.Empty(t, w.got, "a truncated view must write NO edges, not a partial set")
}

func TestPartialCorrelate_RunsRelevantRules(t *testing.T) {
	loader := fakeLoader{assets: []asset.Asset{
		dnsRecord("rec", "A", "1.2.3.4"),
		{ID: "i-1", Type: "ec2_instance", PublicIP: "1.2.3.4"},
	}}
	w := &fakeWriter{}
	svc := NewService(loader, w, []Rule{DNSPointsTo{}})

	// ec2_instance is in DNSPointsTo.InterestedIn() → should run
	n, err := svc.PartialCorrelate(context.Background(), []string{"i-1"})
	require.NoError(t, err)
	require.Equal(t, 1, n)
}

func TestPartialCorrelate_SkipsUnrelatedRules(t *testing.T) {
	loader := fakeLoader{assets: []asset.Asset{
		{ID: "sg-1", Type: "security_group", Metadata: map[string]string{"ingress": "[]"}},
	}}
	w := &fakeWriter{}
	// DNSPointsTo is not interested in security_group
	svc := NewService(loader, w, []Rule{DNSPointsTo{}})

	n, err := svc.PartialCorrelate(context.Background(), []string{"sg-1"})
	require.NoError(t, err)
	require.Zero(t, n)
	require.Empty(t, w.got)
}

func TestPartialCorrelate_EmptyIDsIsNoop(t *testing.T) {
	w := &fakeWriter{}
	svc := NewService(fakeLoader{}, w, []Rule{DNSPointsTo{}})
	n, err := svc.PartialCorrelate(context.Background(), nil)
	require.NoError(t, err)
	require.Zero(t, n)
}

// annotatorRule is a minimal Rule + AssetAnnotator test double, standing in
// for K8sManifestOwnership to pin the service-level wiring (Correlate must
// call CorrelateAssets on any rule that implements it, and write the result
// via IngestAssets) without depending on the k8s join logic itself.
type annotatorRule struct {
	assets []asset.Asset
}

func (annotatorRule) Name() string                          { return "annotator_rule" }
func (annotatorRule) InterestedIn() []string                { return []string{"declared_k8s_workload"} }
func (annotatorRule) Correlate(Graph) []asset.Edge          { return nil }
func (r annotatorRule) CorrelateAssets(Graph) []asset.Asset { return r.assets }

func TestCorrelate_WritesAssetAnnotations(t *testing.T) {
	loader := fakeLoader{assets: []asset.Asset{
		{ID: "declared:1", Type: "declared_k8s_workload"},
	}}
	w := &fakeWriter{fullAssets: []asset.Asset{
		{ID: "declared:1", Type: "declared_k8s_workload", Name: "declared:1"},
	}}
	flagged := asset.Asset{ID: "declared:1", Type: "declared_k8s_workload", Metadata: map[string]string{"drift": "declared_not_live"}}
	svc := NewService(loader, w, []Rule{annotatorRule{assets: []asset.Asset{flagged}}})

	_, err := svc.Correlate(context.Background())
	require.NoError(t, err)
	require.Len(t, w.gotAssets, 1)
	require.Equal(t, "declared_not_live", w.gotAssets[0].Metadata["drift"])
}

// TestCorrelate_AssetAnnotationPreservesFullFields pins the
// field-preservation invariant: correlate's LoadView loads
// only a minimal projection (id/type/public_ip/domain/tags/metadata) — Name,
// DiscoveredAt and LastSeen are zero on the AssetAnnotator's return value.
// Correlate must fetch the FULL current row via assetStore.ByIDs and merge
// only Metadata onto it before writing, never write the partial Graph copy
// straight through — writing it would blank name/discovered_at and, worse,
// zero last_seen makes the row immediately TTL-eligible for purge under
// ReplacingMergeTree(synced_at), deleting the very asset being flagged.
func TestCorrelate_AssetAnnotationPreservesFullFields(t *testing.T) {
	discovered := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lastSeen := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)

	loader := fakeLoader{assets: []asset.Asset{
		// the partial Graph copy: only id/type/metadata populated, exactly
		// what LoadView's minimal projection produces.
		{ID: "declared:1", Type: "declared_k8s_workload", Metadata: map[string]string{"repo": "org/repo"}},
	}}
	w := &fakeWriter{fullAssets: []asset.Asset{
		{
			ID: "declared:1", Type: "declared_k8s_workload", Name: "org/repo:d.yaml",
			Provider: "github", DiscoveredAt: discovered, LastSeen: lastSeen,
			Metadata: map[string]string{"repo": "org/repo"},
		},
	}}
	annotated := asset.Asset{
		ID: "declared:1", Type: "declared_k8s_workload",
		Metadata: map[string]string{"repo": "org/repo", "drift": "declared_not_live"},
	}
	svc := NewService(loader, w, []Rule{annotatorRule{assets: []asset.Asset{annotated}}})

	_, err := svc.Correlate(context.Background())
	require.NoError(t, err)
	require.Len(t, w.gotAssets, 1)

	written := w.gotAssets[0]
	require.Equal(t, "declared_not_live", written.Metadata["drift"], "the annotation itself must land")
	require.Equal(t, "org/repo", written.Metadata["repo"], "pre-existing metadata must survive")
	require.Equal(t, "org/repo:d.yaml", written.Name, "Name must be the real value, not blanked")
	require.False(t, written.DiscoveredAt.IsZero(), "DiscoveredAt must survive, not be blanked")
	require.False(t, written.LastSeen.IsZero(), "LastSeen must survive — zero makes the row TTL-eligible for immediate purge")
	require.Equal(t, discovered, written.DiscoveredAt)
	require.Equal(t, lastSeen, written.LastSeen)
	require.Equal(t, "github", string(written.Provider))
}

// TestCorrelate_AssetAnnotationMergesNotReplaces is the regression test for
// the bug that once blocked the metadata-key projection:
// writeAnnotations used to do `f.Metadata = a.Metadata`, a wholesale replace.
// Once the correlation view's metadata is server-side projected to a key
// subset, a.Metadata is DELIBERATELY partial, so a full replace would erase
// every stored key the view never selected. Here the full stored row carries
// {A, B} and the annotation write only sets C: the result must be {A, B, C},
// never just {C}.
func TestCorrelate_AssetAnnotationMergesNotReplaces(t *testing.T) {
	loader := fakeLoader{assets: []asset.Asset{
		{ID: "declared:1", Type: "declared_k8s_workload"},
	}}
	w := &fakeWriter{fullAssets: []asset.Asset{
		{
			ID: "declared:1", Type: "declared_k8s_workload",
			Metadata: map[string]string{"A": "1", "B": "2"},
		},
	}}
	// The annotation only carries the one key this write intends to change —
	// exactly what a partial metadata-key projection would leave a rule with.
	patch := asset.Asset{ID: "declared:1", Type: "declared_k8s_workload", Metadata: map[string]string{"C": "3"}}
	svc := NewService(loader, w, []Rule{annotatorRule{assets: []asset.Asset{patch}}})

	_, err := svc.Correlate(context.Background())
	require.NoError(t, err)
	require.Len(t, w.gotAssets, 1)

	written := w.gotAssets[0].Metadata
	require.Equal(t, map[string]string{"A": "1", "B": "2", "C": "3"}, written,
		"merge must keep A and B untouched, not replace the whole map with {C: 3}")
}

// TestCorrelate_AssetAnnotationDeleteSignalRemovesKey pins the other half of
// the merge contract: an annotation setting a key to "" deletes that key from
// the stored map (the convention withMetadata uses for clearing drift),
// rather than the merge writing a literal empty-string value.
func TestCorrelate_AssetAnnotationDeleteSignalRemovesKey(t *testing.T) {
	loader := fakeLoader{assets: []asset.Asset{
		{ID: "declared:1", Type: "declared_k8s_workload"},
	}}
	w := &fakeWriter{fullAssets: []asset.Asset{
		{
			ID: "declared:1", Type: "declared_k8s_workload",
			Metadata: map[string]string{"A": "1", "drift": "declared_not_live"},
		},
	}}
	patch := asset.Asset{ID: "declared:1", Type: "declared_k8s_workload", Metadata: map[string]string{"drift": ""}}
	svc := NewService(loader, w, []Rule{annotatorRule{assets: []asset.Asset{patch}}})

	_, err := svc.Correlate(context.Background())
	require.NoError(t, err)
	require.Len(t, w.gotAssets, 1)

	written := w.gotAssets[0].Metadata
	require.Equal(t, "1", written["A"], "unrelated key must survive")
	_, hasDrift := written["drift"]
	require.False(t, hasDrift, "empty value must delete the key, not store a literal empty string")
}

// TestCorrelate_AssetAnnotationTargetVanishedIsSkipped pins the fail-open
// path: if ByIDs can't find the full row for an annotation target (e.g. the
// asset was deleted between the view load and this write), it is logged and
// skipped rather than written as a partial row.
func TestCorrelate_AssetAnnotationTargetVanishedIsSkipped(t *testing.T) {
	loader := fakeLoader{assets: []asset.Asset{
		{ID: "declared:1", Type: "declared_k8s_workload"},
	}}
	w := &fakeWriter{} // fullAssets empty: ByIDs finds nothing
	annotated := asset.Asset{ID: "declared:1", Type: "declared_k8s_workload", Metadata: map[string]string{"drift": "declared_not_live"}}
	svc := NewService(loader, w, []Rule{annotatorRule{assets: []asset.Asset{annotated}}})

	_, err := svc.Correlate(context.Background())
	require.NoError(t, err)
	require.Empty(t, w.gotAssets, "vanished target must not be written partial")
}

func TestCorrelate_NoAnnotationsIsNoWrite(t *testing.T) {
	loader := fakeLoader{assets: []asset.Asset{
		dnsRecord("rec", "A", "1.2.3.4"),
	}}
	w := &fakeWriter{}
	svc := NewService(loader, w, []Rule{DNSPointsTo{}})

	_, err := svc.Correlate(context.Background())
	require.NoError(t, err)
	require.Empty(t, w.gotAssets, "no rule implements AssetAnnotator ⇒ no IngestAssets call")
}

func TestCorrelate_DedupesAcrossRules(t *testing.T) {
	// Two rules deriving the same edge → written once.
	loader := fakeLoader{assets: []asset.Asset{
		dnsRecord("rec", "A", "1.2.3.4"),
		{ID: "i-1", Type: "ec2_instance", PublicIP: "1.2.3.4"},
	}}
	w := &fakeWriter{}
	svc := NewService(loader, w, []Rule{DNSPointsTo{}, DNSPointsTo{}})

	n, err := svc.Correlate(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, n)
}

// countingRule reports how many copies of each asset the Graph holds, by
// emitting one edge per dns_record it sees.
//
// The index goes in DstID, not just in Properties: dedupe keys on
// (SrcID, EdgeType, DstID) and PartialCorrelate dedupes before returning, so an
// index carried only in Properties collapses the n=0 and n=1 edges into one and
// the double-index this rule exists to detect becomes invisible.
// statefulRule mimics CIAccess's shape: it accumulates into a receiver field
// that a caller reads AFTER Correlate returns, and it must reset that field
// on every call — including a call over an empty graph — or a later sweep's
// caller reads a prior sweep's stale accumulation.
type statefulRule struct {
	seen *[]string
}

func (statefulRule) Name() string           { return "stateful" }
func (statefulRule) InterestedIn() []string { return []string{"dns_record"} }
func (r statefulRule) Correlate(g Graph) []asset.Edge {
	var found []string
	for _, rec := range g.DNSRecords() {
		found = append(found, rec.ID)
	}
	*r.seen = found
	return nil
}

// TestCorrelate_EmptyViewStillRunsRulesToResetState pins the fix for a stale-
// accumulation bug: Correlate used to return early on an empty view, before
// the rule loop ran at all, so a stateful rule (CIAccess in production) never
// got the chance to reset its own accumulator — a later reader saw a PRIOR
// sweep's data as if it were current, indistinguishable from a genuinely
// empty, clean sweep (the exact degraded-input shape). An empty view must still run
// every rule once.
func TestCorrelate_EmptyViewStillRunsRulesToResetState(t *testing.T) {
	seen := []string{"stale-from-a-prior-sweep"}
	svc := NewService(fakeLoader{}, &fakeWriter{}, []Rule{statefulRule{seen: &seen}})

	n, err := svc.Correlate(context.Background())

	require.NoError(t, err)
	require.Zero(t, n)
	require.Empty(t, seen, "an empty view must still run the rule so it resets its own state")
}

type countingRule struct{}

func (countingRule) Name() string           { return "counting" }
func (countingRule) InterestedIn() []string { return []string{"dns_record"} }
func (countingRule) Correlate(g Graph) []asset.Edge {
	var edges []asset.Edge
	for i, rec := range g.DNSRecords() {
		n := strconv.Itoa(i)
		edges = append(edges, asset.Edge{
			SrcID: rec.ID, SrcType: "dns_record",
			DstID: "seen-" + n, DstType: "sentinel", EdgeType: "seen",
			Properties: map[string]string{"n": n},
		})
	}
	return edges
}

// PartialCorrelate loads a type-scoped view AND the changed assets; an asset in
// both must appear in the Graph ONCE, or every rule does its work twice.
func TestPartialCorrelate_DoesNotDoubleIndexChangedAssets(t *testing.T) {
	rec := dnsRecord("rec", "A", "1.2.3.4")
	// fakeLoader returns the same slice from LoadByIDs and LoadViewForTypes,
	// which is exactly the production overlap: the changed asset's type is in
	// the active rules' neededTypes, so the view already contains it.
	loader := fakeLoader{assets: []asset.Asset{rec}}
	w := &fakeWriter{}
	svc := NewService(loader, w, []Rule{countingRule{}})

	n, err := svc.PartialCorrelate(context.Background(), []string{"rec"})
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Len(t, w.got, 1,
		"the record must be indexed once — a second copy emits a second edge (n=1) that dedupe cannot collapse")
	require.Equal(t, "0", w.got[0].Properties["n"])
	require.Equal(t, "seen-0", w.got[0].DstID)
}

func TestMergeChangedIntoView_KeepsTheChangedCopy(t *testing.T) {
	view := []asset.Asset{
		{ID: "a", Type: "iam_role", Name: "stale"},
		{ID: "b", Type: "iam_role", Name: "untouched"},
	}
	changed := []asset.Asset{{ID: "a", Type: "iam_role", Name: "fresh"}}

	merged := mergeChangedIntoView(view, changed)
	require.Len(t, merged, 2)
	byID := map[string]string{}
	for _, a := range merged {
		byID[a.ID] = a.Name
	}
	require.Equal(t, "fresh", byID["a"], "the newer read wins")
	require.Equal(t, "untouched", byID["b"])
}

func TestDedupe_PrefersHigherConfidence(t *testing.T) {
	edge := func(rule, confidence string) asset.Edge {
		return asset.Edge{
			SrcID: "arn:role", SrcType: "iam_role",
			DstID: "org/repo", DstType: "github_repo",
			EdgeType: EdgeDefinedIn,
			Properties: map[string]string{
				"rule": rule, "confidence": confidence,
			},
		}
	}

	// A low-confidence edge registered first must not win over a later
	// high-confidence one — first-writer-wins would keep the guess.
	out := dedupe([]asset.Edge{
		edge("low_rule", confidenceLow),
		edge("tf_ownership", confidenceHigh),
		edge("k8s_manifest_ownership", confidenceMedium),
	})
	require.Len(t, out, 1)
	require.Equal(t, "tf_ownership", out[0].Properties["rule"])

	// Order-independent: high first still wins.
	out = dedupe([]asset.Edge{
		edge("tf_ownership", confidenceHigh),
		edge("low_rule", confidenceLow),
	})
	require.Len(t, out, 1)
	require.Equal(t, "tf_ownership", out[0].Properties["rule"])
}

func TestDedupe_TieKeepsFirstAndDistinctLinksSurvive(t *testing.T) {
	a := asset.Edge{SrcID: "s", DstID: "d", EdgeType: "e", Properties: map[string]string{"rule": "first"}}
	b := asset.Edge{SrcID: "s", DstID: "d", EdgeType: "e", Properties: map[string]string{"rule": "second"}}
	other := asset.Edge{SrcID: "s", DstID: "d2", EdgeType: "e"}

	out := dedupe([]asset.Edge{a, b, other})
	require.Len(t, out, 2)
	require.Equal(t, "first", out[0].Properties["rule"], "no confidence on either — stable, first wins")
	require.Equal(t, "d2", out[1].DstID)
}

// TestPartialCorrelate_InternetReachabilityRunsForEveryProducerType is a direct
// regression test for a bug class that bit this rule twice: a Graph field
// InternetReachability.Correlate reads from (PublicManaged/PublicRDSInstances,
// populated by NewGraph's asset-type switch) had a real producer for a type
// that was NOT in InterestedIn(). rulesFor only activates a rule when a CHANGED
// asset's type appears in its InterestedIn — so a sync that touched ONLY that
// type silently skipped recomputing reachability for it. The edge would not
// appear until the next PERIODIC FULL sweep (Correlate(), which runs every rule
// unconditionally) caught up, rather than in the immediate partial pass that
// normally reacts to changes in near-real-time. eks_cluster/gke_cluster/
// s3_bucket/gcs_bucket/rds_instance were all in this state at once.
//
// One asset per type, each the ONLY changed ID in its own sweep — the exact
// shape of sync that silently produced zero edges before the fix.
func TestPartialCorrelate_InternetReachabilityRunsForEveryProducerType(t *testing.T) {
	cases := []struct {
		id string
		a  asset.Asset
	}{
		{"eks-1", asset.Asset{ID: "eks-1", Type: "eks_cluster", Metadata: map[string]string{
			"endpoint_public_access": "true", "public_access": asset.PublicAccessPossible}}},
		{"gke-1", asset.Asset{ID: "gke-1", Type: "gke_cluster", Metadata: map[string]string{
			"endpoint_public_access": "true", "public_access": asset.PublicAccessPossible}}},
		{"b-1", asset.Asset{ID: "b-1", Type: "s3_bucket", Metadata: map[string]string{
			"public": "true", "public_access": asset.PublicAccessConfirmed}}},
		{"b-2", asset.Asset{ID: "b-2", Type: "gcs_bucket", Metadata: map[string]string{"public": "true"}}},
		{"db-1", asset.Asset{ID: "db-1", Type: "rds_instance", Metadata: map[string]string{"publicly_accessible": "true"}}},
		{"kms-1", asset.Asset{ID: "kms-1", Type: "kms_key", Metadata: map[string]string{"public_access": asset.PublicAccessConfirmed}}},
		{"ecr-1", asset.Asset{ID: "ecr-1", Type: "ecr_repository", Metadata: map[string]string{"public_access": asset.PublicAccessConfirmed}}},
		{"sqs-1", asset.Asset{ID: "sqs-1", Type: "sqs_queue", Metadata: map[string]string{"public_access": asset.PublicAccessConfirmed}}},
		{"sns-1", asset.Asset{ID: "sns-1", Type: "sns_topic", Metadata: map[string]string{"public_access": asset.PublicAccessConfirmed}}},
		{"ebs-1", asset.Asset{ID: "ebs-1", Type: "ebs_snapshot", Metadata: map[string]string{"public": "true"}}},
		{"rdssnap-1", asset.Asset{ID: "rdssnap-1", Type: "rds_snapshot", Metadata: map[string]string{"public": "true"}}},
		{"ami-1", asset.Asset{ID: "ami-1", Type: "ami", Metadata: map[string]string{"public": "true"}}},
		{"gcpimg-1", asset.Asset{ID: "gcpimg-1", Type: "gcp_image", Metadata: map[string]string{"public": "true"}}},
		{"gcpsnap-1", asset.Asset{ID: "gcpsnap-1", Type: "gcp_disk_snapshot", Metadata: map[string]string{"public": "true"}}},
		{"azdisk-1", asset.Asset{ID: "azdisk-1", Type: "azure_disk", Metadata: map[string]string{"internet_exportable": "true"}}},
	}
	for _, tc := range cases {
		t.Run(tc.a.Type, func(t *testing.T) {
			loader := fakeLoader{assets: []asset.Asset{tc.a}}
			w := &fakeWriter{}
			svc := NewService(loader, w, []Rule{InternetReachability{}})

			n, err := svc.PartialCorrelate(context.Background(), []string{tc.id})
			require.NoError(t, err)
			require.Equal(t, 1, n,
				"%s changing alone must activate InternetReachability and produce its edge — "+
					"if this is 0, the type is missing from InternetReachability.InterestedIn()", tc.a.Type)
		})
	}
}
