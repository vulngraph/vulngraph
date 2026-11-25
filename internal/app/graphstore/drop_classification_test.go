package graphstore

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// writeRelCSV must tell the two reasons a row is dropped apart. A dangling
// endpoint is permanent, irreducible reality — most CanAssume drops
// are typically AWS cross-account root principals
// (arn:aws:iam::…:root) that are not assets and never will be. A label mismatch
// is always a bug. Summing them meant the drop alarm fired identically on every
// single build, so a real mismatch arriving underneath it would have changed
// nothing an operator could see.
func TestWriteRelCSVSeparatesLabelMismatchFromAbsentEndpoint(t *testing.T) {
	spec := relEndpoints{from: NodeAsset, to: NodeIamRole, prop: []relProp{{"via", "via"}}}
	var rr relRows
	rr.add(asset.Edge{EdgeType: "has_role", SrcID: "ec2-1", SrcType: "ec2_instance", DstID: "role-1", DstType: "iam_role"},
		map[string]any{"src": "ec2-1", "dst": "role-1"}) // both endpoints fine
	rr.add(asset.Edge{EdgeType: "has_role", SrcID: "ec2-1", SrcType: "ec2_instance", DstID: "arn:…:root", DstType: "iam_user"},
		map[string]any{"src": "ec2-1", "dst": "arn:…:root"}) // dst not in the graph
	rr.add(asset.Edge{EdgeType: "has_role", SrcID: "pod-1", SrcType: "k8s_pod", DstID: "role-1", DstType: "iam_role"},
		map[string]any{"src": "pod-1", "dst": "role-1"}) // src is loaded, but as K8sWorkload
	rr.add(asset.Edge{EdgeType: "can_assume", SrcID: "ec2-1", SrcType: "ec2_instance", DstID: "role-mislabel", DstType: "iam_role"},
		map[string]any{"src": "ec2-1", "dst": "role-mislabel"}) // dst loaded as Asset, not IamRole

	nodeLabel := map[string]string{
		"ec2-1":         NodeAsset,
		"role-1":        NodeIamRole,
		"pod-1":         NodeK8sWorkload,
		"role-mislabel": NodeAsset,
	}
	stats, err := writeRelCSV(filepath.Join(t.TempDir(), "rel.csv"), spec, rr, nodeLabel, map[string]bool{})
	require.NoError(t, err)

	assert.Equal(t, 1, stats.written)
	assert.Equal(t, 2, stats.labelMismatch, "pod-1 (K8sWorkload) and role-mislabel (Asset) are both mislabelled, not absent")
	assert.Equal(t, 1, stats.endpointAbsent, "the cross-account root principal is genuinely not in the graph")
	assert.Zero(t, stats.endpointExpired, "no endpoint here is a departed ephemeral resource")

	assert.Equal(t, edgeTypeLoad{loaded: 1, labelMismatch: 1, endpointAbsent: 1}, stats.byType["has_role"])
	assert.Equal(t, edgeTypeLoad{labelMismatch: 1}, stats.byType["can_assume"])
}

// The third drop reason, and the one that made the other two readable. An edge
// whose missing endpoint is a DEPARTED EPHEMERAL resource is not a dangling
// reference: the pod existed, the producer stamped the edge while it did, and the
// asset read then excluded it because it had been dead longer than the
// liveness grace. Dropping the row is correct; counting it as "absent" would put
// executes_as and targets at a double-digit percentage missing on every single build, with
// no way to tell that from an exposure chain actually losing its last hop.
//
// Both directions are covered because the shapes differ: executes_as loses its
// SRC (pod → ServiceAccount) while targets and deploys_to lose their DST.
//
// verifiedExpired stands in for the bulk asset-table check bulkSyncCopy runs
// before classification: dead-1 and dead-2 are ids the check confirmed are an
// aged-out asset row, gone-sa deliberately is not, so a merely-declared-ephemeral
// id with no corresponding verification can never be classified as expired.
func TestDropClassificationSeparatesExpiredEphemeralFromDangling(t *testing.T) {
	nodeLabel := map[string]string{
		"svc-1":  NodeAsset,
		"live-1": NodeK8sWorkload,
		"sa-1":   NodeK8sWorkload,
	}
	verifiedExpired := map[string]bool{"dead-1": true, "dead-2": true}
	set := newRelCSVSet(t.TempDir())
	t.Cleanup(func() { _ = set.closeAll() })

	edges := []asset.Edge{
		// targets → a pod that is still live: loads.
		{EdgeType: "targets", SrcID: "svc-1", SrcType: "k8s_service", DstID: "live-1", DstType: "k8s_pod"},
		// targets → a pod that died past the liveness cut: expired, not lost.
		{EdgeType: "targets", SrcID: "svc-1", SrcType: "k8s_service", DstID: "dead-1", DstType: "k8s_pod"},
		// executes_as FROM a departed pod — the other side of the same shape.
		{EdgeType: "executes_as", SrcID: "dead-2", SrcType: "k8s_pod", DstID: "sa-1", DstType: "k8s_service_account"},
		// binds FROM a ServiceAccount that is not in the inventory at all: dangling.
		{EdgeType: "binds", SrcID: "gone-sa", SrcType: "k8s_service_account", DstID: "svc-1", DstType: "k8s_cluster_role_binding"},
	}
	for i := range edges {
		require.NoError(t, set.add(&edges[i], nodeLabel, verifiedExpired))
	}

	got := map[string]edgeTypeLoad{}
	for _, rw := range set.writers {
		for et, l := range rw.stats.byType {
			agg := got[et]
			agg.loaded += l.loaded
			agg.labelMismatch += l.labelMismatch
			agg.endpointAbsent += l.endpointAbsent
			agg.endpointExpired += l.endpointExpired
			got[et] = agg
		}
	}

	assert.Equal(t, edgeTypeLoad{loaded: 1, endpointExpired: 1}, got["targets"],
		"a service targeting a departed pod is a corpse edge, not a lost Reach hop")
	assert.Equal(t, edgeTypeLoad{endpointExpired: 1}, got["executes_as"],
		"the departed endpoint is the SRC here — the split must read whichever side is missing")
	assert.Equal(t, edgeTypeLoad{endpointAbsent: 1}, got["binds"],
		"a ServiceAccount that is in no namespace we collected is a genuine dangling reference")
}

// The budget is what makes endpoint_absent alertable, so it must be evaluated
// against the DECLARED number and must ignore the expired rows entirely — the
// worst types are typically almost all expiry, and any threshold that saw them was
// either permanently firing or blind.
//
// verifiedExpiry: true on every fixture here — these represent a completed,
// ClickHouse-verified build (the only kind whose endpointAbsent/endpointExpired
// split is trustworthy). TestDanglingBudgetRequiresVerifiedExpiry below covers
// the unverified case this test deliberately does not.
func TestDanglingBudgetIgnoresExpiryAndSmallSamples(t *testing.T) {
	// An executes_as shape: a large share of rows dropped, every one of them expiry.
	expiryOnly := copyStats{verifiedExpiry: true, byType: map[string]edgeTypeLoad{
		"executes_as": {fetched: 80000, loaded: 68000, endpointExpired: 12000},
	}}
	assert.Empty(t, expiryOnly.danglingOverBudget(),
		"expired ephemeral endpoints must never make an edge type look like it is losing data")

	// A binds shape before the collector fix: a large share dangling (above its 0.25 budget).
	dangling := copyStats{verifiedExpiry: true, byType: map[string]edgeTypeLoad{
		"binds": {fetched: 1400, loaded: 1000, endpointAbsent: 400},
	}}
	assert.Equal(t, map[string]int{"binds": 400}, dangling.danglingOverBudget())

	// can_assume's cross-account principals: real, permanent, and under budget.
	crossAccount := copyStats{verifiedExpiry: true, byType: map[string]edgeTypeLoad{
		"can_assume": {fetched: 14000, loaded: 13700, endpointAbsent: 300},
	}}
	assert.Empty(t, crossAccount.danglingOverBudget(),
		"a low-single-digit dangling share is the irreducible cross-account reality the budget is sized for")

	// a tiny type fetches a few dozen rows; two dangling reads as several percent and must not fire.
	smallSample := copyStats{verifiedExpiry: true, byType: map[string]edgeTypeLoad{
		"grants_admin": {fetched: 30, loaded: 28, endpointAbsent: 2},
	}}
	assert.Empty(t, smallSample.danglingOverBudget(),
		"a share computed over a denominator below DanglingBudgetMinRows is noise")
}

// TestDanglingBudgetRequiresVerifiedExpiry guards the fix for a
// false-positive alarm on EVERY worker restart: LoadFromSnapshot's fast-boot
// path runs with verifyExpired == nil (see bulkSyncCopy), so classifyRelEndpoints
// has no verified map to consult and counts every expired-ephemeral endpoint as
// endpointAbsent instead. Seconds after a snapshot
// warm-start, deploys_to/executes_as/targets — all three on the strict 5%
// default budget — read tens of percent "endpoint_absent" this way, entirely
// from rows that were really endpointExpired. danglingOverBudget must refuse to
// verdict on that build at all (mirroring expiredShareStepChanges' identical
// guard just above it), and must resume verdicting the instant a build IS
// verified, even with the exact same numbers.
func TestDanglingBudgetRequiresVerifiedExpiry(t *testing.T) {
	// A post-restart shape: everything that would have been endpointExpired
	// under verification instead landed in endpointAbsent because there was no
	// verified map. a share far above the 5% default budget would fire every time.
	unverified := copyStats{verifiedExpiry: false, byType: map[string]edgeTypeLoad{
		"deploys_to": {fetched: 28000, loaded: 18000, endpointAbsent: 10000},
	}}
	assert.Empty(t, unverified.danglingOverBudget(),
		"an unverified build's endpointAbsent count cannot be trusted — classifyRelEndpoints had no verified map to separate expiry from genuine dangling")

	// The identical shape, verified: the same numbers must now be trusted and must
	// still trip the budget. Proves the guard suppresses based on trustworthiness,
	// not by quietly loosening the threshold.
	verified := copyStats{verifiedExpiry: true, byType: map[string]edgeTypeLoad{
		"deploys_to": {fetched: 28000, loaded: 18000, endpointAbsent: 10000},
	}}
	assert.Equal(t, map[string]int{"deploys_to": 10000}, verified.danglingOverBudget(),
		"a VERIFIED build with the same shape is real signal and must still alarm")
}

// The bug-class alarm must fire on label mismatches ONLY. Absent endpoints
// are routine dangling-endpoint attrition, never zero, so an alarm on them
// would fire on every build and hide a new mismatch instance.
func TestDroppedSecurityEdgesFiresOnMismatchNotAbsence(t *testing.T) {
	absentOnly := copyStats{droppedEndpointMiss: 400, reachRelsMismatched: map[string]int{}}
	assert.False(t, absentOnly.droppedSecurityEdges(),
		"dangling endpoints are permanent reality — alarming on them makes the alarm meaningless")

	mismatch := copyStats{droppedLabelMismatch: 100, reachRelsMismatched: map[string]int{"ExecutesAsK8sWorkload": 100}}
	assert.True(t, mismatch.droppedSecurityEdges(),
		"a Reach rel losing rows to a label mismatch is the bug class and must alarm")
}

// notLoaded is the residue of the four-way split, and the split must be exact:
// the parity gauge is only trustworthy if loaded + the three drop reasons
// account for every fetched row.
func TestEdgeTypeLoadNotLoadedIsTheResidue(t *testing.T) {
	l := edgeTypeLoad{fetched: 100, loaded: 60, labelMismatch: 5, endpointAbsent: 15, endpointExpired: 10}
	assert.Equal(t, 10, l.notLoaded())
	assert.Equal(t, l.fetched, l.loaded+l.labelMismatch+l.endpointAbsent+l.endpointExpired+l.notLoaded())
}
