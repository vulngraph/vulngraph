package correlate

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// TestCorrelationTypes_IncludesK8sManifestOwnershipInputs pins that
// the correlate LoadView must read both the manifest-ingest intermediate
// (declared_k8s_workload) and every live k8s workload kind it joins against —
// without k8s_statefulset/k8s_daemonset/k8s_job the ownership rule can never
// see live StatefulSets/DaemonSets/Jobs to correlate manifests to.
func TestCorrelationTypes_IncludesK8sManifestOwnershipInputs(t *testing.T) {
	require.Contains(t, correlationTypes, "declared_k8s_workload")
	require.Contains(t, correlationTypes, "k8s_statefulset")
	require.Contains(t, correlationTypes, "k8s_daemonset")
	require.Contains(t, correlationTypes, "k8s_job")
}

// TestCorrelationTypes_IncludesTFOwnershipInputs pins that the correlate
// LoadView must read the Terraform-state-parse intermediate
// (declared_tf_resource) plus EVERY live type TFOwnership is allowed to join
// it to (tfOwnershipSafeLiveTypes). A type present in the allow-list but
// absent from correlationTypes means its live assets never load on the full
// sweep, so a declared_tf_resource naming that type can never find a match —
// the class of bug this test exists to catch (dynamodb_table,
// elasticache_cluster, azure_function were all missing until this fix).
func TestCorrelationTypes_IncludesTFOwnershipInputs(t *testing.T) {
	require.Contains(t, correlationTypes, "declared_tf_resource")
	for liveType := range tfOwnershipSafeLiveTypes {
		require.Contains(t, correlationTypes, liveType,
			"tfOwnershipSafeLiveTypes entry %q must be loaded by the full correlate sweep", liveType)
	}
}

// Correlation's asset view must exclude dead ephemeral resources. Every rule's
// input comes from this one query and no rule can tell a corpse from inventory —
// an asset row is an asset row — so without this filter correlation derives fresh
// edges for resources deleted weeks earlier (e.g. fresh exposed_to_internet edges
// on pods that no longer exist).
func TestLoadViewAppliesEphemeralLiveness(t *testing.T) {
	require.Contains(t, loadView, asset.EphemeralLivenessCond,
		"correlation must not derive edges from dead ephemeral resources")
}

// TestLoadViewHasNoRecencyFilter pins that the full-sweep view is a read of
// EVERY live asset of the requested types, not a "changed since last sweep"
// incremental read.
//
// This matters because it is the tempting cost fix: loadView's synced_at is
// right there, feeding argMax, and the read is expensive per call (seconds to
// tens of seconds and GiB-scale memory) against a large table. A predicate like
// `AND synced_at > ?` would look like a clean win in isolation.
//
// It would silently break correlation instead. Correlate/PartialCorrelate
// build a fresh in-memory Graph from the view on every call and rerun every
// rule from zero (service.go: NewGraph(assets) then r.Correlate(g) for each
// rule) — rules do not accumulate edges across sweeps. A rule that matches an
// UNCHANGED asset A against a CHANGED asset B (e.g. DNSPointsTo resolving a
// dns_record to an ec2_instance, or SharedSecurityGroup joining two instances
// on the same SG) needs A in the view on every sweep that touches B, not only
// on the sweep where A itself last synced. A synced_at floor drops A from the
// view once it stops being "recent" and silently deletes every edge that
// needs it — the exact "dropped edge type" bug class this codebase has hit
// repeatedly (see correlationTypes' history above).
//
// If a future change needs an incremental full sweep, it has to change HOW
// the Graph is built (carry state across sweeps), not just narrow this SELECT
// — so any such change belongs in service.go's sweep loop, with its own test
// proving a row changed between sweeps is still visible to every rule that
// needs it, not here.
func TestLoadViewHasNoRecencyFilter(t *testing.T) {
	for _, q := range []struct{ name, sql string }{
		{"loadView", loadView},
		{"loadByIDs", loadByIDs},
	} {
		predicate := "WHERE type IN"
		if q.name == "loadByIDs" {
			predicate = "WHERE id IN"
		}
		start := strings.Index(q.sql, predicate)
		require.NotEqual(t, -1, start)
		where := q.sql[start:]
		where = where[:strings.Index(where, "GROUP BY")]
		// synced_at may appear only inside argMax(...) (already excluded — WHERE
		// starts after the SELECT clause) or inside EphemeralLivenessCond's
		// last_seen high-water lookup, which anchors to another asset's high
		// water mark, not to "now" or to this sweep's start time. Any other
		// appearance of synced_at in the WHERE is a recency/incremental filter.
		require.False(t, strings.Contains(where, "synced_at"),
			"%s's WHERE clause mentions synced_at — a time-bound filter here would make "+
				"the full/partial sweep skip unchanged assets that other changed assets still "+
				"need to correlate against, silently dropping edges. See test comment.", q.name)
	}
}
