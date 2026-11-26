package jobs

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/forget"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/obs"
)

// fakeScopeForgetter captures the Sweep it was called with, so tests can pin
// exactly which scopes evaluateForget let through.
type fakeScopeForgetter struct {
	sw  forget.Sweep
	n   int
	err error
}

func (f *fakeScopeForgetter) Evaluate(_ context.Context, sw forget.Sweep) (int, error) {
	f.sw = sw
	return f.n, f.err
}

// fakeLifecycler serves stored findings by resource and records Resolve calls.
// calls records the id list of every ByResourceIDs invocation so tests can pin
// the batching itself, not just its results.
type fakeLifecycler struct {
	stored     []finding.Finding
	resolved   []finding.Finding
	reasons    []finding.ResolutionReason
	readErr    error
	resolveErr error
	calls      [][]string
}

func (f *fakeLifecycler) ByResourceIDs(_ context.Context, ids []string) ([]finding.Finding, error) {
	f.calls = append(f.calls, append([]string(nil), ids...))
	if f.readErr != nil {
		return nil, f.readErr
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []finding.Finding
	for _, fnd := range f.stored {
		if want[fnd.ResourceID] {
			out = append(out, fnd)
		}
	}
	return out, nil
}

func (f *fakeLifecycler) Resolve(_ context.Context, findings []finding.Finding, reason finding.ResolutionReason) error {
	if f.resolveErr != nil {
		return f.resolveErr
	}
	f.resolved = append(f.resolved, findings...)
	f.reasons = append(f.reasons, reason)
	return nil
}

// The core lifecycle edge: a stored open cspm finding on a checked
// resource that the checks did NOT re-emit is fixed → resolved. Re-emitted,
// already-resolved, other-source, and unchecked-resource findings are left alone.
func TestReconcileResolvedFindings(t *testing.T) {
	targets := []asset.Asset{{ID: "i-1"}, {ID: "i-2"}}
	emitted := []finding.Finding{{ID: "keep", Source: "cspm", ResourceID: "i-1"}}
	svc := &fakeLifecycler{stored: []finding.Finding{
		{ID: "keep", Source: "cspm", ResourceID: "i-1"},                         // re-emitted → stays open
		{ID: "fixed", Source: "cspm", ResourceID: "i-1"},                        // not re-emitted → resolve
		{ID: "fixed2", Source: "cspm", ResourceID: "i-2"},                       // not re-emitted → resolve
		{ID: "gd", Source: "aws_guardduty", ResourceID: "i-1"},                  // provider-native → untouched
		{ID: "done", Source: "cspm", ResourceID: "i-2", ResolvedAt: time.Now()}, // already resolved → untouched
		{ID: "elsewhere", Source: "cspm", ResourceID: "i-9"},                    // resource not checked → untouched
	}}

	reconcileResolvedFindings(context.Background(), svc, nil, targets, emitted, false)

	ids := make([]string, len(svc.resolved))
	for i, f := range svc.resolved {
		ids[i] = f.ID
	}
	require.ElementsMatch(t, []string{"fixed", "fixed2"}, ids)
	// This path means the check ran against a LIVE resource and no longer reports
	// the problem — the control was corrected. It is the one outcome that says the
	// finding was worth surfacing, and the counterpart to the deleted-asset path
	// below. If both declared the same reason the junk-rate metric would be blind.
	require.Equal(t, []finding.ResolutionReason{finding.ReasonFixed}, svc.reasons)
}

// TestReconcileResolvedFindings_IaCTerraformReconciled proves the
// unreadable_tf_state coverage finding (Source "iac_terraform") follows the
// same re-emit/absence contract as cspm findings: gone when the bucket
// becomes readable and stops being re-emitted, kept open while it's still
// re-emitted each sweep, and other provider-native sources (e.g. GHAS) stay
// excluded.
func TestReconcileResolvedFindings_IaCTerraformReconciled(t *testing.T) {
	targets := []asset.Asset{{ID: "org/repo"}, {ID: "org/repo2"}}
	emitted := []finding.Finding{{ID: "still-unreadable", Source: "iac_terraform", ResourceID: "org/repo2"}}
	svc := &fakeLifecycler{stored: []finding.Finding{
		{ID: "now-readable", Source: "iac_terraform", ResourceID: "org/repo"},      // not re-emitted → resolve
		{ID: "still-unreadable", Source: "iac_terraform", ResourceID: "org/repo2"}, // re-emitted → stays open
		{ID: "cspm-fixed", Source: "cspm", ResourceID: "org/repo"},                 // regression: cspm still resolves
		{ID: "ghas", Source: "github_ghas", ResourceID: "org/repo"},                // provider-native → untouched
	}}

	reconcileResolvedFindings(context.Background(), svc, nil, targets, emitted, false)

	ids := make([]string, len(svc.resolved))
	for i, f := range svc.resolved {
		ids[i] = f.ID
	}
	require.ElementsMatch(t, []string{"now-readable", "cspm-fixed"}, ids)
}

func TestReconcileResolvedFindings_NoTargetsNoop(t *testing.T) {
	svc := &fakeLifecycler{stored: []finding.Finding{{ID: "f", Source: "cspm", ResourceID: "i-1"}}}
	reconcileResolvedFindings(context.Background(), svc, nil, nil, nil, false)
	require.Empty(t, svc.resolved)
}

func TestReconcileResolvedFindings_ReadErrorBestEffort(t *testing.T) {
	svc := &fakeLifecycler{readErr: context.DeadlineExceeded}
	// Must not panic or resolve anything on read failure.
	reconcileResolvedFindings(context.Background(), svc, nil, []asset.Asset{{ID: "i-1"}}, nil, false)
	require.Empty(t, svc.resolved)
}

// A deleted resource resolves ALL its findings, any source.
func TestResolveFindingsForDeletedAssets(t *testing.T) {
	svc := &fakeLifecycler{stored: []finding.Finding{
		{ID: "a", Source: "cspm", ResourceID: "vol-1"},
		{ID: "b", Source: "aws_guardduty", ResourceID: "vol-1"},
		{ID: "c", Source: "cspm", ResourceID: "vol-2", ResolvedAt: time.Now()}, // already resolved
		{ID: "d", Source: "cspm", ResourceID: "vol-9"},                         // not deleted
	}}
	resolveFindingsForDeletedAssets(context.Background(), svc, []string{"vol-1", "vol-2"})

	ids := make([]string, len(svc.resolved))
	for i, f := range svc.resolved {
		ids[i] = f.ID
	}
	require.ElementsMatch(t, []string{"a", "b"}, ids)
	// The resource was deleted — nobody fixed anything. Must NOT be ReasonFixed.
	require.Equal(t, []finding.ResolutionReason{finding.ReasonResourceGone}, svc.reasons)
}

// fakeDeletionApplier records the calls applyDeletions makes, in order.
type fakeDeletionApplier struct {
	recordErr error
	calls     []string
}

func (f *fakeDeletionApplier) RecordAssetDeletions(_ context.Context, _ string, ids []string, _ time.Time) ([]string, error) {
	f.calls = append(f.calls, "record")
	return ids, f.recordErr
}

func (f *fakeDeletionApplier) DeleteAssetHashes(context.Context, string, []string) error {
	f.calls = append(f.calls, "delete-hashes")
	return nil
}

// The deletion record is written first; if it fails, the hashes stay (so the
// next complete sweep re-decides and records it) and nothing is resolved.
// Dropping the hashes without the record would lose the proof for good.
func TestApplyDeletions_RecordFirstAndStopOnFailure(t *testing.T) {
	svc := &fakeLifecycler{stored: []finding.Finding{{ID: "a", Source: "cspm", ResourceID: "vol-1"}}}
	ok := &fakeDeletionApplier{}
	applyDeletions(context.Background(), ok, svc, "c1", []string{"vol-1"}, time.Now())
	require.Equal(t, []string{"record", "delete-hashes"}, ok.calls)
	require.Len(t, svc.resolved, 1)

	svc = &fakeLifecycler{stored: []finding.Finding{{ID: "a", Source: "cspm", ResourceID: "vol-1"}}}
	failing := &fakeDeletionApplier{recordErr: errors.New("pg down")}
	applyDeletions(context.Background(), failing, svc, "c1", []string{"vol-1"}, time.Now())
	require.Equal(t, []string{"record"}, failing.calls, "no hash delete without the record")
	require.Empty(t, svc.resolved, "nothing resolved on a decision that was not recorded")
}

func TestApplyDeletions_RetainsRetryStateUntilFindingsReconciled(t *testing.T) {
	for _, phase := range []string{"read", "resolve"} {
		t.Run(phase, func(t *testing.T) {
			svc := &fakeLifecycler{stored: []finding.Finding{{ID: "f", Source: "cspm", ResourceID: "i-gone"}}}
			if phase == "read" {
				svc.readErr = errors.New("temporary read failure")
			} else {
				svc.resolveErr = errors.New("temporary write failure")
			}
			conns := &fakeDeletionApplier{}
			applyDeletions(context.Background(), conns, svc, "c", []string{"i-gone"}, time.Now())
			require.Equal(t, []string{"record"}, conns.calls)
			require.Empty(t, svc.resolved)
			svc.readErr, svc.resolveErr = nil, nil
			applyDeletions(context.Background(), conns, svc, "c", []string{"i-gone"}, time.Now())
			require.Equal(t, []string{"record", "record", "delete-hashes"}, conns.calls)
			require.Len(t, svc.resolved, 1)
		})
	}
}

// A derived finding sits on a representative resource, but it describes a
// group — a real VM fleet, a base image's running images, a package every
// runner shares. Deleting the representative does not end the group: its own job
// reconciles membership, so the deleted-asset edge leaves it alone. Closing it
// here closed a whole fleet when one instance terminated, and the next regroup
// reopened it as a new alert.
func TestResolveFindingsForDeletedAssets_SkipsDerivedFindings(t *testing.T) {
	svc := &fakeLifecycler{stored: []finding.Finding{
		{ID: "own", Source: "cspm", ResourceID: "i-1"},
		{ID: "fleet", Source: vmVulnSource, ResourceID: "i-1", Metadata: map[string]string{"fleet_kind": "asg"}},
		{ID: "solo", Source: vmVulnSource, ResourceID: "i-1", Metadata: map[string]string{"fleet_kind": "instance"}},
		{ID: "base", Source: baseImageSource, CheckID: baseImageGroupCheckID, ResourceID: "image/sha256:a"},
		{ID: "eol", Source: baseImageSource, CheckID: "container-image-os-end-of-life", ResourceID: "image/sha256:a"},
		{ID: "pkg", Source: "supply_chain", ResourceType: "package", ResourceID: "pkg:npm/a@1"},
		{ID: "image-cov", Source: "supply_chain", ResourceType: "container_image", ResourceID: "image/sha256:a"},
	}}
	resolveFindingsForDeletedAssets(context.Background(), svc,
		[]string{"i-1", "image/sha256:a", "pkg:npm/a@1"})

	ids := make([]string, len(svc.resolved))
	for i, f := range svc.resolved {
		ids[i] = f.ID
	}
	require.ElementsMatch(t, []string{"own", "solo", "eol", "image-cov"}, ids,
		"findings about the deleted resource itself resolve — a hand-built host IS its fleet, an end-of-life finding is about its image; "+
			"derived group findings are their job's to reconcile")
}

// TestReconcileResolvedFindings_WithholdsWhenCheckCouldNotEvaluate is the
// regression guard for closing findings as fixed on absent evidence.
//
// Cspm findings could close as "fixed" when the check's required evidence key
// was absent from every fresh asset those findings sit on — the check never
// evaluated anything, and the reconcile read its silence as remediation (e.g.
// a github-no-branch-protection closure on a repository that was still
// unprotected). The closure REASON is wrong in every such case; the outcome is
// only accidentally right sometimes.
func TestReconcileResolvedFindings_WithholdsWhenCheckCouldNotEvaluate(t *testing.T) {
	reg := checks.Default()
	blind := asset.Asset{
		ID: "org/blind", Type: "github_repo", Provider: asset.ProviderGitHub,
		Metadata: map[string]string{"archived": "false"}, // branch_protection never collected
	}
	observed := asset.Asset{
		ID: "org/seen", Type: "github_repo", Provider: asset.ProviderGitHub,
		Metadata: map[string]string{"archived": "false", "branch_protection": "enabled"},
	}
	svc := &fakeLifecycler{stored: []finding.Finding{
		{ID: "blind-f", Source: "cspm", CheckID: "github-no-branch-protection", ResourceID: "org/blind"},
		{ID: "real-fix", Source: "cspm", CheckID: "github-no-branch-protection", ResourceID: "org/seen"},
	}}

	reconcileResolvedFindings(context.Background(), svc, reg, []asset.Asset{blind, observed}, nil, false)

	ids := make([]string, len(svc.resolved))
	for i, f := range svc.resolved {
		ids[i] = f.ID
	}
	require.Equal(t, []string{"real-fix"}, ids,
		"only the finding whose check actually observed the repository may close as fixed")
}

// The gate must not become a blanket freeze: when the collector supplies the
// evidence, absence of a finding is still remediation and still resolves.
func TestReconcileResolvedFindings_ResolvesWhenEvidencePresent(t *testing.T) {
	reg := checks.Default()
	bucket := asset.Asset{
		ID: "b-1", Type: "s3_bucket", Provider: asset.ProviderAWS,
		Metadata: map[string]string{"encryption": "AES256", "versioning": "enabled", "logging": "enabled"},
	}
	svc := &fakeLifecycler{stored: []finding.Finding{
		{ID: "log", Source: "cspm", CheckID: "aws-s3-access-logging-disabled", ResourceID: "b-1"},
		{ID: "ver", Source: "cspm", CheckID: "aws-s3-no-versioning", ResourceID: "b-1"},
	}}

	reconcileResolvedFindings(context.Background(), svc, reg, []asset.Asset{bucket}, nil, false)

	ids := make([]string, len(svc.resolved))
	for i, f := range svc.resolved {
		ids[i] = f.ID
	}
	require.ElementsMatch(t, []string{"log", "ver"}, ids)
	require.Equal(t, []finding.ResolutionReason{finding.ReasonFixed}, svc.reasons)
}

// Paths the gate treats as conclusive, so they resolve as they would without it:
//
//   - a finding with no check_id (provider-native re-addressed, iac coverage);
//   - a check_id not in the registry (a CIEM rule);
//   - a check whose asset type is not the target's and is not a pod check
//     rolled up onto a k8s workload (see the rollup test below).
func TestReconcileResolvedFindings_GateOnlyAppliesToCheckedResources(t *testing.T) {
	reg := checks.Default()
	pod := asset.Asset{
		ID: "prod/pod/billing/p-1", Type: "k8s_pod", Provider: asset.ProviderKubernetes,
		Metadata: map[string]string{"namespace": "billing", "phase": "Running"},
	}
	svc := &fakeLifecycler{stored: []finding.Finding{
		{ID: "no-check-id", Source: "cspm", ResourceID: "prod/pod/billing/p-1"},
		{ID: "unregistered-check", Source: "cspm", CheckID: "aws-privesc-15", ResourceID: "prod/pod/billing/p-1"},
		{ID: "wrong-asset-type", Source: "cspm", CheckID: "aws-s3-access-logging-disabled", ResourceID: "prod/pod/billing/p-1"},
	}}

	reconcileResolvedFindings(context.Background(), svc, reg, []asset.Asset{pod}, nil, false)

	ids := make([]string, len(svc.resolved))
	for i, f := range svc.resolved {
		ids[i] = f.ID
	}
	require.ElementsMatch(t, []string{"no-check-id", "unregistered-check", "wrong-asset-type"}, ids,
		"the gate must not change any path where it cannot prove the check went blind")
}

// A pod check's finding rolled up onto its Deployment is never evaluated
// against the Deployment asset itself. When the Deployment changed but none of
// its pods did, no pod was checked, so the finding's absence proves nothing and
// it must stay open; when an owned pod was checked and is clean, it resolves.
func TestReconcileResolvedFindings_WorkloadRollupNeedsACheckedPod(t *testing.T) {
	reg := checks.Default()
	deployment := asset.Asset{
		ID: "prod/deployment/billing/api", Type: "k8s_deployment", Provider: asset.ProviderKubernetes, Region: "prod",
		Metadata: map[string]string{"namespace": "billing", "available_replicas": "2"},
	}
	rolled := finding.Finding{
		ID: "rolled", Source: "cspm", CheckID: "k8s-container-runs-as-root",
		ResourceID: deployment.ID, ResourceType: "k8s_deployment",
	}
	cleanPod := asset.Asset{
		ID: "prod/pod/billing/api-1", Type: "k8s_pod", Provider: asset.ProviderKubernetes, Region: "prod",
		Metadata: map[string]string{
			"namespace": "billing", "phase": "Running", "run_as_root": "false",
			"owner_kind": "Deployment", "owner_name": "api",
		},
	}
	blindPod := cleanPod
	blindPod.Metadata = map[string]string{"namespace": "billing", "phase": "Running", "owner_kind": "Deployment", "owner_name": "api"}

	for _, tt := range []struct {
		name        string
		targets     []asset.Asset
		wantResolve bool
	}{
		{"deployment changed, no pod checked", []asset.Asset{deployment}, false},
		{"owned pod checked and clean", []asset.Asset{deployment, cleanPod}, true},
		{"owned pod checked but unreadable", []asset.Asset{deployment, blindPod}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			svc := &fakeLifecycler{stored: []finding.Finding{rolled}}
			reconcileResolvedFindings(context.Background(), svc, reg, tt.targets, nil, false)
			if tt.wantResolve {
				require.Len(t, svc.resolved, 1)
			} else {
				require.Empty(t, svc.resolved)
			}
		})
	}
}

// recordCheckEvaluability is best-effort observability on a sync's hot path: a
// nil Metrics (metrics disabled) or an empty collection must never panic.
func TestRecordCheckEvaluabilityNilSafe(t *testing.T) {
	require.NotPanics(t, func() {
		recordCheckEvaluability(nil, "conn-1", checks.Default(), []asset.Asset{{ID: "a"}})
		recordCheckEvaluability(obs.New(), "conn-1", nil, []asset.Asset{{ID: "a"}})
		recordCheckEvaluability(obs.New(), "conn-1", checks.Default(), nil)
	})
}

// recordDeletionSignal sits on the same hot path and is observe-only: it must
// never panic, and must never be the thing that fails a sync.
func TestRecordDeletionSignalNilSafe(t *testing.T) {
	res := collect.Result{}
	res.MarkComplete("eu-west-1/ec2:instances", []string{"ec2_instance"}, 4)
	require.NotPanics(t, func() {
		recordDeletionSignal(nil, "conn-1", res, 3, true, time.Now())
		recordDeletionSignal(obs.New(), "", res, 3, true, time.Now())
		recordDeletionSignal(obs.New(), "conn-1", collect.Result{}, 0, false, time.Now())
	})
}

// A sweep that never loaded the stored hashes has not measured anything, so it
// must publish no candidate count at all. Publishing the zero would read as
// "nothing to forget here", which is precisely the false comfort this signal
// exists to remove — the connector's stored set may be full of dead ids nobody
// looked for.
func TestRecordDeletionSignal_UnknownCandidatesPublishNoZero(t *testing.T) {
	m := obs.New()
	res := collect.Result{Partial: true}
	res.MarkComplete("eu-west-1/ec2:instances", []string{"ec2_instance"}, 12)

	recordDeletionSignal(m, "conn-1", res, 0, false, time.Now())

	require.Equal(t, 0, testutil.CollectAndCount(m.Registry(), "graph_sync_deletion_candidates"),
		"an unmeasured sweep must not publish a candidate count")
	require.Equal(t, 1, testutil.CollectAndCount(m.Registry(), "graph_sync_scope_last_complete_timestamp_seconds"),
		"the collector still ran, so its proven enumerations are still stamped")
}

// TestReconcileResolvedFindings_BatchesAtReconcileBatch is the anti-regression
// guard on the N+1: reconcileBatch was 100, which meant one whole-table
// ClickHouse scan per 100 assets — a very high call volume reading a large
// multiple of the table's actual size in bytes over a day — because
// ByResourceIDs cannot prune on resource_id. It also
// pins that every target is covered exactly once — a batching bug that dropped
// or duplicated a window would silently under- or over-resolve.
func TestReconcileResolvedFindings_BatchesAtReconcileBatch(t *testing.T) {
	for _, n := range []int{1, reconcileBatch - 1, reconcileBatch, reconcileBatch + 1, 2*reconcileBatch + 7} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			targets := make([]asset.Asset, n)
			for i := range targets {
				targets[i] = asset.Asset{ID: "i-" + strconv.Itoa(i)}
			}
			svc := &fakeLifecycler{}

			reconcileResolvedFindings(context.Background(), svc, nil, targets, nil, false)

			wantCalls := (n + reconcileBatch - 1) / reconcileBatch
			require.Len(t, svc.calls, wantCalls,
				"%d targets at reconcileBatch=%d should take %d reads", n, reconcileBatch, wantCalls)

			seen := map[string]int{}
			for _, call := range svc.calls {
				require.LessOrEqual(t, len(call), reconcileBatch, "a batch exceeded reconcileBatch")
				for _, id := range call {
					seen[id]++
				}
			}
			require.Len(t, seen, n, "every target must appear in exactly one batch")
			for id, count := range seen {
				require.Equal(t, 1, count, "%s appeared in %d batches", id, count)
			}
		})
	}
}

// TestReconcileResolvedFindings_ReadFailureResolvesNothing pins the fail-closed
// safety property: resolution is monotone in evidence, so a failed read is NOT
// evidence that a finding stopped reproducing. A batch whose read fails must
// leave its findings OPEN. Getting this backwards would mass-resolve live
// findings on any ClickHouse blip.
func TestReconcileResolvedFindings_ReadFailureResolvesNothing(t *testing.T) {
	targets := []asset.Asset{{ID: "i-1"}, {ID: "i-2"}}
	svc := &fakeLifecycler{
		readErr: errors.New("clickhouse: context deadline exceeded"),
		stored: []finding.Finding{
			{ID: "would-resolve", Source: "cspm", ResourceID: "i-1"},
			{ID: "would-resolve2", Source: "cspm", ResourceID: "i-2"},
		},
	}

	reconcileResolvedFindings(context.Background(), svc, nil, targets, nil, false)

	require.Empty(t, svc.resolved, "a failed read must resolve nothing — absence of a read is not evidence")
	require.Empty(t, svc.reasons)
}

func TestDeliveredCounts_PerRegionAndGlobal(t *testing.T) {
	assets := []asset.Asset{
		{ID: "i-1", Type: "ec2_instance", Region: "eu-west-1"},
		{ID: "i-2", Type: "ec2_instance", Region: "eu-west-1"},
		{ID: "i-3", Type: "ec2_instance", Region: "us-east-1"},
		{ID: "g-1", Type: "gce_instance"},
	}
	counts := deliveredCounts(assets)

	require.Equal(t, 2, counts[deliveredKey{region: "eu-west-1", typ: "ec2_instance"}])
	require.Equal(t, 1, counts[deliveredKey{region: "us-east-1", typ: "ec2_instance"}])
	require.Equal(t, 3, counts[deliveredKey{typ: "ec2_instance"}],
		"the global (empty-region) key must total every region, for non-RegionScoped families' claims")
	require.Equal(t, 1, counts[deliveredKey{typ: "gce_instance"}])
}

// TestCheckDelivered_MismatchAndPassthrough is the regression guard for the
// delivery-mismatch fix: a scope whose declared Count exceeds what actually reached
// res.Assets must fail the check, a scope that delivered at least as much as
// declared must pass, and a scope forget.ParseScope does not recognise as
// enforceable must pass through unchanged (it never reaches a decision either
// way, so the check must not manufacture a false alarm for it).
func TestCheckDelivered_MismatchAndPassthrough(t *testing.T) {
	delivered := map[deliveredKey]int{
		{region: "eu-west-1", typ: "ec2_instance"}: 3,
		{typ: "gce_instance"}:                      10,
	}

	require.True(t, checkDelivered(
		collect.ScopeEnumeration{Scope: "eu-west-1/ec2:instances", Types: []string{"ec2_instance"}, Count: 3},
		delivered), "declared == delivered must pass")

	require.False(t, checkDelivered(
		collect.ScopeEnumeration{Scope: "eu-west-1/ec2:instances", Types: []string{"ec2_instance"}, Count: 5},
		delivered), "declared 5 but only 3 delivered must fail — the claim/payload divergence this check exists to catch")

	require.True(t, checkDelivered(
		collect.ScopeEnumeration{Scope: "global/compute.instances", Types: []string{"gce_instance"}, Count: 10},
		delivered), "non-RegionScoped family must be checked against the global total, not a per-region count")

	require.True(t, checkDelivered(
		collect.ScopeEnumeration{Scope: "eu-west-1/ec2:snapshots", Types: []string{"snapshot"}, Count: 999},
		delivered), "a family forget does not audit must pass through unchecked")
}

// TestEvaluateForget_DropsDeliveryMismatchNotConnectorPartial is the
// regression guard for a failure where graph_forget_would_forget
// stayed at zero even while graph_forget_shadow_candidates climbed, and the
// partial_sweep refusal reason dominated — a connector-wide res.Partial from ONE
// unrelated failing family was refusing every audited scope's decision in the
// same sweep, even scopes that individually proved complete.
//
// Asserts both halves of the fix: (1) res.Partial=true no longer reaches
// forget.Sweep.Partial at all — a scope that delivered what it declared must
// still be handed to Evaluate even when some OTHER family failed elsewhere in
// the same connector's sweep; (2) a scope whose declared count is NOT backed
// by what actually reached res.Assets is dropped before Evaluate ever sees it,
// and increments the delivery_mismatch refusal counter.
func TestEvaluateForget_DropsDeliveryMismatchNotConnectorPartial(t *testing.T) {
	res := collect.Result{
		Partial: true, // some unrelated family failed elsewhere this sweep
		Assets: []asset.Asset{
			{ID: "i-1", Type: "ec2_instance", Region: "eu-west-1"},
			{ID: "i-2", Type: "ec2_instance", Region: "eu-west-1"},
			// us-east-1 declares 5 but only 1 is actually here.
			{ID: "i-3", Type: "ec2_instance", Region: "us-east-1"},
		},
	}
	res.MarkComplete("eu-west-1/ec2:instances", []string{"ec2_instance"}, 2)
	res.MarkComplete("us-east-1/ec2:instances", []string{"ec2_instance"}, 5)

	f := &fakeScopeForgetter{}
	m := obs.New()
	evaluateForget(context.Background(), f, m, "conn-1", res, time.Now())

	// forget.Sweep has no Partial field — res.Partial=true above proves
	// nothing stops the eu-west-1 scope from reaching Evaluate despite it.
	require.Len(t, f.sw.Scope, 1, "only the scope that delivered what it declared must reach Evaluate")
	require.Equal(t, "eu-west-1/ec2:instances", f.sw.Scope[0].Scope)

	want := `
		# HELP graph_forget_refusals_total Scope evaluations refused, by reason (relative_cap, absolute_cap, enumeration_shrank, unconfirmed, population_too_small, edge_truncated, edge_health_unknown, not_enforceable, delivery_mismatch). Low cardinality on purpose: this is the series that says WHICH guard is doing the work, and a permanently dominant reason is either the correct answer for this estate or a threshold that needs calibration. delivery_mismatch is not a Decide() refusal — it fires in the caller (jobs.evaluateForget), before a scope is even handed to Decide, when a collector declared a scope complete but the assets it claimed never reached collect.Result.Assets (the claim/payload divergence a panic between MarkComplete and the assets append can produce).
		# TYPE graph_forget_refusals_total counter
		graph_forget_refusals_total{refusal="delivery_mismatch"} 1
	`
	require.NoError(t, testutil.GatherAndCompare(m.Registry(), strings.NewReader(want), "graph_forget_refusals_total"),
		"the us-east-1 scope's delivery mismatch must increment the delivery_mismatch refusal counter exactly once")
}

// TestReconcileResolvedFindings_PartialWithholdsNonRegistryFindings pins the
// CIEM auto-resolve hole: after a partial collection (an IAM family failed),
// the CIEM engine emits nothing for a principal it could not see, and its rule
// IDs are not registry checks, so checkCouldConclude used to answer true and
// close every such finding as fixed. Registry checks still resolve on evidence.
func TestReconcileResolvedFindings_PartialWithholdsNonRegistryFindings(t *testing.T) {
	reg := checks.Default()
	bucket := asset.Asset{
		ID: "b-1", Type: "s3_bucket", Provider: asset.ProviderAWS,
		Metadata: map[string]string{"encryption": "AES256", "versioning": "enabled", "logging": "enabled"},
	}
	role := asset.Asset{ID: "arn:aws:iam::1:role/deployer", Type: "iam_role", Provider: asset.ProviderAWS}
	stored := []finding.Finding{
		{ID: "log", Source: "cspm", CheckID: "aws-s3-access-logging-disabled", ResourceID: "b-1"},
		{ID: "ciem", Source: "cspm", Type: "ciem_privesc", CheckID: "aws-privesc-passrole-lambda", ResourceID: role.ID},
		{ID: "iac", Source: "iac_terraform", CheckID: "tf-aws-s3-public", ResourceID: "b-1"},
	}

	svc := &fakeLifecycler{stored: stored}
	reconcileResolvedFindings(context.Background(), svc, reg, []asset.Asset{bucket, role}, nil, true)
	ids := make([]string, len(svc.resolved))
	for i, f := range svc.resolved {
		ids[i] = f.ID
	}
	require.Equal(t, []string{"log"}, ids, "only the registry check may resolve after a partial collection")

	svc = &fakeLifecycler{stored: stored}
	role.Metadata = map[string]string{"policies": "[]", ciem.MetaPrivilegeTier: ciem.TierStandard, ciem.MetaAWSOrganizationComplete: "true"}
	reconcileResolvedFindings(context.Background(), svc, reg, []asset.Asset{bucket, role}, nil, false)
	require.Len(t, svc.resolved, 3, "a complete collection still resolves CIEM/IaC absences")
}
