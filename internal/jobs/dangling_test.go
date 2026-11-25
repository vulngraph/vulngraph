package jobs

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/obs"
)

// fakeDanglingFindings is an in-memory finding store with faithful source
// filtering, resolved-exclusion, and keyset pagination (matching the CH repo's
// detected_at DESC, id DESC order), so the worker's real paging loop is exercised.
type fakeDanglingFindings struct {
	// seenFilters records every List filter, so a test can pin the QUERY SHAPE a
	// sweep asks for, not only the rows it happened to resolve.
	seenFilters []finding.Filter
	all         []finding.Finding
	resolved    map[string]bool
	// capture
	resolvedIDs  []string
	resolveCalls int
	listCalls    int
	// reasons records the ResolutionReason each finding was resolved WITH, so a
	// test can assert the sweep declared the right one — a resolution with the
	// wrong reason is exactly as harmful to the junk-rate metric as no resolution.
	reasons map[string]finding.ResolutionReason
}

func newFakeDanglingFindings(fs ...finding.Finding) *fakeDanglingFindings {
	return &fakeDanglingFindings{all: fs, resolved: map[string]bool{}}
}

func (f *fakeDanglingFindings) List(_ context.Context, filter finding.Filter) ([]finding.Finding, error) {
	f.listCalls++

	// Filter: source, check_id, and (unless IncludeResolved) exclude resolved.
	var open []finding.Finding
	for _, fnd := range f.all {
		if filter.Source != "" && fnd.Source != filter.Source {
			continue
		}
		if filter.CheckID != "" && fnd.CheckID != filter.CheckID {
			continue
		}
		if !filter.IncludeResolved && f.resolved[fnd.ID] {
			continue
		}
		open = append(open, fnd)
	}
	f.seenFilters = append(f.seenFilters, filter)
	// DetectedBefore, honoured like the repo's HAVING clause. A fake that ignored
	// this would leave the lifecycle sweep's cutoff untestable.
	if !filter.DetectedBefore.IsZero() {
		var kept []finding.Finding
		for _, fnd := range open {
			if !fnd.DetectedAt.After(filter.DetectedBefore) {
				kept = append(kept, fnd)
			}
		}
		open = kept
	}
	// Order by detected_at, id — DESC by default, ASC under OldestFirst, matching
	// the repo. Hard-coding DESC here would let a revert of OldestFirst break no
	// test, even though oldest-first paging is what lets the sweep reach a backlog
	// deeper than one tick's scan ceiling.
	sort.Slice(open, func(i, j int) bool {
		if !open[i].DetectedAt.Equal(open[j].DetectedAt) {
			if filter.OldestFirst {
				return open[i].DetectedAt.Before(open[j].DetectedAt)
			}
			return open[i].DetectedAt.After(open[j].DetectedAt)
		}
		if filter.OldestFirst {
			return open[i].ID < open[j].ID
		}
		return open[i].ID > open[j].ID
	})
	// Resume after the cursor (matched by re-encoding, since the token is opaque).
	if filter.Cursor != "" {
		start := 0
		for i, fnd := range open {
			if finding.EncodeCursor(fnd, false) == filter.Cursor {
				start = i + 1
				break
			}
		}
		open = open[start:]
	}
	limit := filter.Limit
	if limit <= 0 || limit > len(open) {
		limit = len(open)
	}
	return open[:limit], nil
}

func (f *fakeDanglingFindings) Resolve(_ context.Context, findings []finding.Finding, reason finding.ResolutionReason) error {
	f.resolveCalls++
	if f.reasons == nil {
		f.reasons = map[string]finding.ResolutionReason{}
	}
	for _, fnd := range findings {
		if !f.resolved[fnd.ID] {
			f.resolved[fnd.ID] = true
			f.resolvedIDs = append(f.resolvedIDs, fnd.ID)
		}
		// Recorded, not ignored: which reason a sweep declares is the whole point of
		// the resolution taxonomy, so a test can assert it rather than only that
		// something resolved.
		f.reasons[fnd.ID] = reason
	}
	return nil
}

// fakeAssetExistence reports which ids are live, and serves asset metadata
// (for the stale-state sweep) by id.
type fakeAssetExistence struct {
	highWater time.Time
	live      map[string]bool
	assets    map[string]asset.Asset
}

func newFakeAssetExistence(liveIDs ...string) *fakeAssetExistence {
	m := make(map[string]bool, len(liveIDs))
	assets := make(map[string]asset.Asset, len(liveIDs))
	for _, id := range liveIDs {
		m[id] = true
		// LastSeen now: the k8s lifecycle sweep judges liveness by last_seen, not by
		// row presence (asset rows are never deleted), so a "live" fake asset must
		// carry a current timestamp or it reads as gone.
		assets[id] = asset.Asset{ID: id, LastSeen: time.Now()}
	}
	return &fakeAssetExistence{live: m, assets: assets}
}

// withState sets metadata["state"] on an existing (or new) fake asset, for
// stale-state sweep tests.
func (f *fakeAssetExistence) withState(id, state string) *fakeAssetExistence {
	a := f.assets[id]
	a.ID = id
	if a.Metadata == nil {
		a.Metadata = map[string]string{}
	}
	a.Metadata["state"] = state
	f.assets[id] = a
	f.live[id] = true
	return f
}

func (f *fakeAssetExistence) ExistingIDs(_ context.Context, ids []string) ([]string, error) {
	var out []string
	for _, id := range ids {
		if f.live[id] {
			out = append(out, id)
		}
	}
	return out, nil
}

// LiveIDs is the ephemeral-liveness gate (asset.EphemeralLivenessCond in the real
// repo). The fake models both halves of it: an id it does not return is gone,
// whether the row is absent OR its last_seen has fallen behind the type's
// high-water mark by more than the grace window.
//
// A fake asset with a ZERO LastSeen counts as live: those belong to tests about
// something else entirely (namespace metadata, budget fairness) that never model
// collection time, and treating "unset" as "ancient" would make every one of them
// assert on staleness by accident.
func (f *fakeAssetExistence) LiveIDs(_ context.Context, ids []string) ([]string, error) {
	highWater := f.highWater
	if highWater.IsZero() {
		highWater = time.Now()
	}
	cutoff := highWater.Add(-resourceGoneGrace)

	var out []string
	for _, id := range ids {
		if !f.live[id] {
			continue
		}
		if seen := f.assets[id].LastSeen; !seen.IsZero() && seen.Before(cutoff) {
			continue
		}
		out = append(out, id)
	}
	return out, nil
}

// TypeHighWater mirrors ProviderHighWater's default: a currently-collecting type,
// so the fail-safe (no assets of the type at all → resolve nothing) doesn't
// silently short-circuit tests that aren't about it. Set highWater to exercise it.
func (f *fakeAssetExistence) TypeHighWater(context.Context, string) (time.Time, error) {
	if f.highWater.IsZero() {
		return time.Now(), nil
	}
	return f.highWater, nil
}

func (f *fakeAssetExistence) ProviderHighWater(context.Context, string) (time.Time, error) {
	// Tests that do not care about staleness get a currently-collecting provider,
	// so the sweep's fail-safe (a frozen high-water mark halts resolution) does
	// not silently short-circuit them. Set highWater explicitly to exercise it.
	if f.highWater.IsZero() {
		return time.Now(), nil
	}
	return f.highWater, nil
}

func (f *fakeAssetExistence) ByIDs(_ context.Context, ids []string) ([]asset.Asset, error) {
	var out []asset.Asset
	for _, id := range ids {
		if a, ok := f.assets[id]; ok {
			out = append(out, a)
		}
	}
	return out, nil
}

// gdFinding builds a joinable GuardDuty finding (ec2_instance) for the given
// resource, with a distinct detected_at so pagination order is deterministic.
func gdFinding(id, resourceID string, ageSecs int) finding.Finding {
	return finding.Finding{
		ID:           id,
		Source:       "aws_guardduty",
		ResourceType: "ec2_instance",
		ResourceID:   resourceID,
		DetectedAt:   time.Unix(1_700_000_000, 0).Add(time.Duration(ageSecs) * time.Second),
	}
}

func runDangling(t *testing.T, findings *fakeDanglingFindings, assets *fakeAssetExistence) {
	t.Helper()
	w := &DanglingSweepWorker{findings: findings, assets: assets}
	err := w.Work(context.Background(), &river.Job[DanglingSweepArgs]{Args: DanglingSweepArgs{}})
	require.NoError(t, err)
}

func TestDanglingSweep_ResolvesOnlyOrphans(t *testing.T) {
	findings := newFakeDanglingFindings(
		gdFinding("f-live", "i-live", 3),
		gdFinding("f-gone1", "i-gone1", 2),
		gdFinding("f-gone2", "i-gone2", 1),
	)
	assets := newFakeAssetExistence("i-live") // only i-live still exists

	runDangling(t, findings, assets)

	require.ElementsMatch(t, []string{"f-gone1", "f-gone2"}, findings.resolvedIDs,
		"only findings whose resource has no asset row are resolved")
	require.False(t, findings.resolved["f-live"], "a finding on a live resource is never resolved")
	// The reason matters as much as the resolution: this sweep closes findings
	// because the RESOURCE went away, which is the junk signal. Mislabelling it
	// "fixed" would credit the check with remediation that never happened.
	require.Equal(t, finding.ReasonResourceGone, findings.reasons["f-gone1"])
	require.Equal(t, finding.ReasonResourceGone, findings.reasons["f-gone2"])
}

func TestDanglingSweep_ExcludesNonJoinableSourceAndType(t *testing.T) {
	findings := newFakeDanglingFindings(
		// Orphan, but source is not in danglingJoinSpecs → must NOT be resolved.
		finding.Finding{ID: "f-scc", Source: "gcp_scc", ResourceType: "gce_instance", ResourceID: "proj/gone", DetectedAt: time.Unix(1_700_000_000, 0)},
		// Orphan, joinable source but resource_type carries a NAME not an id (iam_user
		// asset ids are ARNs) → excluded, must NOT be resolved.
		finding.Finding{ID: "f-iam", Source: "aws_guardduty", ResourceType: "iam_user", ResourceID: "attacker", DetectedAt: time.Unix(1_700_000_010, 0)},
		// Orphan, joinable source but empty resource_id → skipped.
		finding.Finding{ID: "f-empty", Source: "aws_guardduty", ResourceType: "ec2_instance", ResourceID: "", DetectedAt: time.Unix(1_700_000_020, 0)},
		// Orphan, fully joinable → the only one resolved.
		gdFinding("f-gone", "i-gone", 5),
	)
	assets := newFakeAssetExistence() // nothing is live

	runDangling(t, findings, assets)

	require.Equal(t, []string{"f-gone"}, findings.resolvedIDs,
		"only joinable (source, resource_type) findings with a non-empty id are resolved")
}

func TestDanglingSweep_RespectsResolveCap(t *testing.T) {
	// More orphans than the per-tick cap: exactly the dangling phase's reserved
	// share is resolved.
	total := danglingResolveMax + 150
	fs := make([]finding.Finding, 0, total)
	for i := 0; i < total; i++ {
		id := "f" + strconv.Itoa(i)
		fs = append(fs, gdFinding(id, "i-gone"+strconv.Itoa(i), i))
	}
	findings := newFakeDanglingFindings(fs...)
	assets := newFakeAssetExistence() // all gone

	runDangling(t, findings, assets)

	// The dangling (existence-check) phase gets a RESERVED share of the budget,
	// not the whole pool — otherwise a large backlog here would starve the
	// other phases every tick (see Work()'s comment).
	require.Len(t, findings.resolvedIDs, danglingResolveMax*danglingBudgetPct/100,
		"the existence-check phase resolves at most its reserved share of the per-tick budget")
}

func TestDanglingSweep_NoFindings(t *testing.T) {
	findings := newFakeDanglingFindings()
	runDangling(t, findings, newFakeAssetExistence())
	require.Empty(t, findings.resolvedIDs)
	require.Zero(t, findings.resolveCalls, "no orphans means no resolve call")
}

// cspmEC2Finding builds a joinable CSPM finding (ec2_instance) for the given
// resource, mirroring gdFinding for the stale-state sweep (source "cspm", not
// "aws_guardduty").
func cspmEC2Finding(id, resourceID string, ageSecs int) finding.Finding {
	return finding.Finding{
		ID:           id,
		Source:       "cspm",
		CheckID:      "aws-ec2-public-ip", // one of staleStateSpecs' allowlisted checkIDs
		ResourceType: "ec2_instance",
		ResourceID:   resourceID,
		DetectedAt:   time.Unix(1_700_000_000, 0).Add(time.Duration(ageSecs) * time.Second),
	}
}

// The stale-state sweep resolves EC2 findings whose asset row still exists but
// is terminated/shutting-down — the case the sync-time deletion diff misses
// when the resource's content hash was never cached (orphaned EC2 findings can
// outlive their instances, unreachable via the existence check alone since the
// asset row lingers).
func TestDanglingSweep_ResolvesStaleStateEC2Findings(t *testing.T) {
	findings := newFakeDanglingFindings(
		cspmEC2Finding("f-running", "i-running", 4),
		cspmEC2Finding("f-terminated", "i-terminated", 3),
		cspmEC2Finding("f-shutting-down", "i-shutting", 2),
		cspmEC2Finding("f-stopped", "i-stopped", 1),
	)
	assets := newFakeAssetExistence().
		withState("i-running", "running").
		withState("i-terminated", "terminated").
		withState("i-shutting", "shutting-down").
		withState("i-stopped", "stopped")

	runDangling(t, findings, assets)

	require.ElementsMatch(t, []string{"f-terminated", "f-shutting-down"}, findings.resolvedIDs,
		"only terminated/shutting-down instances resolve their findings")
	require.False(t, findings.resolved["f-running"])
	require.False(t, findings.resolved["f-stopped"], "a stopped (not terminated) instance's findings stay open")
}

// A huge existence-check (dangling) backlog must NOT starve the stale-state
// phase of its own budget — with a shared first-come pool, a large
// GuardDuty-dangling orphan backlog consumes the whole resolve budget before the
// EC2 stale-state phase ever runs (stale_state_scanned stays 0). Each phase
// gets a reserved share.
func TestDanglingSweep_LargeDanglingBacklogDoesNotStarveStaleState(t *testing.T) {
	total := danglingResolveMax * 3 // far more orphans than even the whole budget
	fs := make([]finding.Finding, 0, total+1)
	for i := 0; i < total; i++ {
		fs = append(fs, gdFinding("f"+strconv.Itoa(i), "i-gone"+strconv.Itoa(i), i))
	}
	fs = append(fs, cspmEC2Finding("f-terminated", "i-terminated", total+1))
	findings := newFakeDanglingFindings(fs...)
	assets := newFakeAssetExistence().withState("i-terminated", "terminated") // all GuardDuty ids stay "gone"

	runDangling(t, findings, assets)

	require.True(t, findings.resolved["f-terminated"],
		"the stale-state phase must resolve its finding even against a huge dangling backlog")
	require.Len(t, findings.resolvedIDs, danglingResolveMax*danglingBudgetPct/100+1,
		"dangling phase capped at its reserved share; stale-state still got its one finding")
}

// A huge existence-check (dangling) backlog must equally not starve the
// k8s pod lifecycle phase — same failure mode as the stale-state case above,
// checked against the third phase.
func TestDanglingSweep_LargeDanglingBacklogDoesNotStarveK8sLifecycle(t *testing.T) {
	total := danglingResolveMax * 3
	fs := make([]finding.Finding, 0, total+1)
	for i := 0; i < total; i++ {
		fs = append(fs, gdFinding("f"+strconv.Itoa(i), "i-gone"+strconv.Itoa(i), i))
	}
	fs = append(fs, k8sPodFinding("f-churned", "pod-churned", total+1))
	findings := newFakeDanglingFindings(fs...)
	assets := newFakeAssetExistence() // all GuardDuty ids AND pod-churned stay "gone"

	runDangling(t, findings, assets)

	require.True(t, findings.resolved["f-churned"],
		"the k8s lifecycle phase must resolve its finding even against a huge dangling backlog")
}

// A non-ec2_instance CSPM finding, or one with no matching asset row at all,
// must never be resolved by the stale-state sweep (only existence-checked
// sources may resolve on absence; see danglingJoinSpecs).
func TestDanglingSweep_StaleStateExcludesNonMatchingTypeAndMissingAsset(t *testing.T) {
	findings := newFakeDanglingFindings(
		finding.Finding{ID: "f-bucket", Source: "cspm", ResourceType: "s3_bucket", ResourceID: "b1", DetectedAt: time.Unix(1_700_000_010, 0)},
		cspmEC2Finding("f-no-asset", "i-missing", 1),
	)
	assets := newFakeAssetExistence().withState("b1", "terminated") // wrong type; must not match

	runDangling(t, findings, assets)

	require.Empty(t, findings.resolvedIDs,
		"a non-ec2_instance type and a finding with no matching asset row are both left alone")
}

// k8sPodFinding builds a joinable k8s pod lifecycle finding (k8s_pod) for the
// given pod resource, mirroring gdFinding/cspmEC2Finding for the k8s pod
// lifecycle sweep (checkID "k8s-container-runs-as-root").
func k8sPodFinding(id, resourceID string, ageSecs int) finding.Finding {
	return finding.Finding{
		ID:           id,
		Source:       "cspm",
		CheckID:      "k8s-container-runs-as-root",
		ResourceType: "k8s_pod",
		ResourceID:   resourceID,
		DetectedAt:   time.Unix(1_700_000_000, 0).Add(time.Duration(ageSecs) * time.Second),
	}
}

func gceInstanceFinding(id, resourceID string, ageSecs int) finding.Finding {
	return finding.Finding{
		ID:           id,
		Source:       "cspm",
		CheckID:      "gcp-gce-no-oslogin",
		ResourceType: "gce_instance",
		ResourceID:   resourceID,
		DetectedAt:   time.Unix(1_700_000_000, 0).Add(time.Duration(ageSecs) * time.Second),
	}
}

// GCE instances churn the same way k8s pods do — managed instance groups and
// autoscaler node pools replace them under new names, and scheduled CI jobs create
// one-shot VMs — so the lifecycle sweep must cover them too.
//
// Findings from per-instance checks such as gcp-gce-no-oslogin can sit on
// assets already stale for days, whose instances have actually been deleted.
// The existence-based specs never match them because the asset ROW still
// exists — stale, not absent.
func TestDanglingSweep_StaleGCEInstanceIsResolved(t *testing.T) {
	now := time.Now()
	findings := newFakeDanglingFindings(
		gceInstanceFinding("f-gce-stale", "gce-stale", 1),
		gceInstanceFinding("f-gce-fresh", "gce-fresh", 2),
	)
	assets := newFakeAssetExistence("gce-stale", "gce-fresh")
	assets.highWater = now
	// The asset ROW is present for both. Only last_seen distinguishes the torn-down instance from the live one.
	assets.assets["gce-stale"] = asset.Asset{ID: "gce-stale", LastSeen: now.Add(-30 * 24 * time.Hour)}
	assets.assets["gce-fresh"] = asset.Asset{ID: "gce-fresh", LastSeen: now}

	runDangling(t, findings, assets)

	require.True(t, findings.resolved["f-gce-stale"],
		"a GCE instance not seen since well before the high-water mark is gone — the row lingering is not evidence it exists")
	require.Equal(t, finding.ReasonResourceGone, findings.reasons["f-gce-stale"],
		"ephemeral-instance churn is the junk signal these two checks exist to be measured by")
	require.False(t, findings.resolved["f-gce-fresh"],
		"a currently-collected instance must never be resolved")
}

// The same fail-safe as the k8s path, on the GCP anchor: if GCP collection stops,
// its high-water mark freezes, the cutoff stops advancing, and nothing is judged
// gone. Without the per-provider anchor a GCP outage would mass-resolve real
// findings.
func TestDanglingSweep_FrozenGCPHighWaterResolvesNoGCE(t *testing.T) {
	frozen := time.Now().Add(-30 * 24 * time.Hour)
	findings := newFakeDanglingFindings(gceInstanceFinding("f-gce-any", "gce-any", 1))
	assets := newFakeAssetExistence("gce-any")
	assets.highWater = frozen
	assets.assets["gce-any"] = asset.Asset{ID: "gce-any", LastSeen: frozen}

	runDangling(t, findings, assets)

	require.Empty(t, findings.resolvedIDs,
		"a GCP collector outage must never be mistaken for mass instance deletion")
}

// The k8s pod lifecycle sweep resolves k8s-container-runs-as-root /
// k8s-privileged-container findings on pods that have been replaced by a
// rolling deployment (no asset row at all for the old pod name). Such findings
// are invisible to the sync-time reconcile because the check re-fires against the NEW pod's asset and never
// revisits the old one.
func TestDanglingSweep_ResolvesChurnedK8sPodFindings(t *testing.T) {
	findings := newFakeDanglingFindings(
		k8sPodFinding("f-live", "pod-live", 3),
		k8sPodFinding("f-churned1", "pod-churned1", 2),
		finding.Finding{ID: "f-privesc-churned", Source: "cspm", CheckID: "k8s-privileged-container",
			ResourceType: "k8s_pod", ResourceID: "pod-churned2", DetectedAt: time.Unix(1_700_000_001, 0)},
	)
	assets := newFakeAssetExistence("pod-live") // only pod-live still exists

	runDangling(t, findings, assets)

	require.ElementsMatch(t, []string{"f-churned1", "f-privesc-churned"}, findings.resolvedIDs,
		"both allowlisted checkIDs resolve findings on pods with no asset row")
	require.False(t, findings.resolved["f-live"], "a finding on a pod that still exists is never resolved")
}

// The join-key SAFETY discipline still holds for the ephemeral sweep: only the
// spec's resource_type, with a non-empty resource_id, may be resolved on absence.
// What is NO LONGER excluded is a pod check outside a hand-picked pair — the
// ephemeral sweep owns the whole k8s_pod type, which is the point of it.
func TestDanglingSweep_EphemeralSweepExcludesWrongTypeAndEmptyResourceID(t *testing.T) {
	findings := newFakeDanglingFindings(
		// A pod check outside the original hand-picked pair, on a dead pod. It
		// must resolve.
		finding.Finding{ID: "f-other-check", Source: "cspm", CheckID: "k8s-image-latest-tag",
			ResourceType: "k8s_pod", ResourceID: "pod-gone1", DetectedAt: time.Unix(1_700_000_000, 0)},
		// Swept check but resource_type is not k8s_pod → excluded: the id is not
		// known to be an asset id for that type.
		finding.Finding{ID: "f-wrong-type", Source: "cspm", CheckID: "k8s-container-runs-as-root",
			ResourceType: "k8s_service", ResourceID: "svc-gone", DetectedAt: time.Unix(1_700_000_010, 0)},
		// Swept check, k8s_pod, but empty resource_id → skipped.
		finding.Finding{ID: "f-empty", Source: "cspm", CheckID: "k8s-container-runs-as-root",
			ResourceType: "k8s_pod", ResourceID: "", DetectedAt: time.Unix(1_700_000_020, 0)},
		k8sPodFinding("f-gone", "pod-gone2", 5),
	)
	assets := newFakeAssetExistence() // nothing is live

	runDangling(t, findings, assets)

	require.ElementsMatch(t, []string{"f-other-check", "f-gone"}, findings.resolvedIDs,
		"every k8s_pod check is swept; a wrong type and an empty resource_id are not")
	require.Equal(t, finding.ReasonResourceGone, findings.reasons["f-other-check"])
}

// Every swept check must actually be reachable by the sweep, and the sweep must
// only ever be pointed at types where absence really means deletion.
func TestEphemeralLivenessSpecs(t *testing.T) {
	ephemeral := map[string]bool{}
	for _, t := range asset.EphemeralTypes {
		ephemeral[t] = true
	}

	seen := map[string]bool{}
	for _, spec := range ephemeralLivenessSpecs {
		require.Truef(t, ephemeral[spec.resourceType],
			"%s is not in asset.EphemeralTypes: for a non-ephemeral type, 'not collected recently' "+
				"means a slow or broken collector, not a deleted resource — resolving on that basis "+
				"closes findings on live infrastructure", spec.resourceType)
		require.NotEmpty(t, spec.phase, "a spec with no obs phase label is invisible")
		require.NotEmpty(t, spec.checkIDs, "a spec with no checks sweeps nothing")
		for _, id := range spec.checkIDs {
			require.Falsef(t, seen[id], "check %q listed twice — it would be swept twice per tick", id)
			seen[id] = true
		}
	}
}

// Every check the ephemeral sweep claims is a live registry check on k8s_pod.
// The pod checks
// left off are listed here, so adding a k8s_pod check forces a decision on
// whether its resource_id precondition has been verified.
func TestEphemeralLivenessPodChecksAreLive(t *testing.T) {
	notYetVerified := map[string]bool{
		"k8s-dangerous-capabilities": true, "k8s-host-network-pod": true, "k8s-host-pid-pod": true,
		"k8s-host-ipc-pod": true, "k8s-pod-host-path-volume": true, "k8s-container-host-port": true,
		"k8s-windows-host-process": true, "k8s-container-added-capabilities": true, "k8s-container-net-raw": true,
		"k8s-pod-seccomp-unrestricted": true, "k8s-pod-apparmor-unconfined": true,
		"k8s-container-writable-root-fs": true, "k8s-container-allow-privilege-escalation": true,
		"k8s-pod-secret-in-env": true, "k8s-workload-default-namespace": true,
	}
	reg := checks.Default()
	listed := map[string]bool{}
	for _, spec := range ephemeralLivenessSpecs {
		for _, id := range spec.checkIDs {
			listed[id] = true
			c, ok := reg.ByID(id)
			require.Truef(t, ok, "%s is not a registered check", id)
			require.Equalf(t, spec.resourceType, c.AssetType, "%s does not emit on %s", id, spec.resourceType)
			require.Falsef(t, notYetVerified[id], "%s is both swept and listed as not yet verified", id)
		}
	}
	for _, c := range reg.All() {
		if c.AssetType == "k8s_pod" {
			require.Truef(t, listed[c.ID] || notYetVerified[c.ID],
				"k8s_pod check %s is neither in ephemeralLivenessSpecs nor in notYetVerified", c.ID)
		}
	}
}

// The failure this sweep exists to prevent is PARTIAL coverage: if only some of
// the checks emitting pod findings are swept, the rest are invisible. Any check
// that names a k8s_pod resource type in a sibling spec must be covered here.
func TestEphemeralLivenessCoversEveryK8sPodSpecElsewhere(t *testing.T) {
	covered := map[string]bool{}
	for _, spec := range ephemeralLivenessSpecs {
		for _, id := range spec.checkIDs {
			covered[id] = true
		}
	}
	for _, spec := range resourceLifecycleSpecs {
		if spec.resourceType == "k8s_pod" {
			require.Truef(t, covered[spec.checkID],
				"%s sweeps k8s_pod by check id but is not in ephemeralLivenessSpecs — "+
					"that split leaves most pod findings on corpses", spec.checkID)
		}
	}
	// staleStateSpecs is deliberately NOT required to be a subset. It answers a
	// different question (is this LIVE pod in an exempt system namespace?), and
	// the resource_id == asset.ID precondition this sweep resolves on is not
	// verified for all of its checks (see ephemeralLivenessSpecs). That every
	// check the ephemeral sweep claims is a live registry check is
	// TestEphemeralLivenessPodChecksAreLive.
}

// The GCE lifecycle phase must cover EVERY check that fires per gce_instance,
// for the same reason the pod sweep had to: partial coverage is what leaves
// corpses standing. A check left out keeps every finding it raised on a
// torn-down instance open, however far that asset falls past the staleness
// cutoff.
func TestGCELifecycleCoversEveryPerInstanceCheck(t *testing.T) {
	covered := map[string]bool{}
	for _, spec := range resourceLifecycleSpecs {
		if spec.resourceType == "gce_instance" {
			require.Equal(t, asset.ProviderGCP, spec.provider,
				"the cutoff must be anchored to GCP's own high-water mark, never wall-clock")
			require.Equal(t, sweepPhaseGCELifecycle, spec.phase)
			covered[spec.checkID] = true
		}
	}
	for _, id := range []string{
		"gcp-gce-no-oslogin", "gcp-gce-project-ssh-keys",
		"gcp-gce-public-ip", "gcp-gce-default-sa",
	} {
		require.Truef(t, covered[id], "%s fires per GCE instance and churns with it", id)
	}
}

// The frozen-high-water-mark property, at the sweep level: with the type's high-water mark FROZEN
// (a stopped collector), a pod whose last_seen sits just behind that frozen mark
// must survive — even though wall-clock says it is ancient. Under a wall-clock
// cutoff every one of these resolves at once, which is how a collection outage
// turns into mass resolution of live findings.
func TestDanglingSweep_FrozenHighWaterProtectsPodsBehindIt(t *testing.T) {
	frozen := time.Now().Add(-45 * 24 * time.Hour) // collection stopped 45 days ago
	findings := newFakeDanglingFindings(
		k8sPodFinding("f-just-behind", "pod-just-behind", 1),
		k8sPodFinding("f-far-behind", "pod-far-behind", 2),
	)
	assets := newFakeAssetExistence("pod-just-behind", "pod-far-behind")
	assets.highWater = frozen
	// Both are ~45 days stale by wall-clock. Only their position relative to the
	// FROZEN mark decides.
	assets.assets["pod-just-behind"] = asset.Asset{ID: "pod-just-behind", LastSeen: frozen.Add(-1 * time.Hour)}
	assets.assets["pod-far-behind"] = asset.Asset{ID: "pod-far-behind", LastSeen: frozen.Add(-30 * 24 * time.Hour)}

	runDangling(t, findings, assets)

	require.False(t, findings.resolved["f-just-behind"],
		"a pod inside the grace window of a FROZEN high-water mark is not gone — the collector is")
	require.True(t, findings.resolved["f-far-behind"],
		"a pod 30 days behind even the frozen mark really was deleted before collection stopped")
}

// The ephemeral phase must not be able to take the whole tick. A full
// danglingResolveMax of its own would take the worst-case tick from one
// danglingResolveMax of resolutions to three times that.
func TestSweepBudgetSharesAreOneTickTotal(t *testing.T) {
	require.Equal(t, 100,
		danglingBudgetPct+staleBudgetPct+ephemeralBudgetPct+
			lifecycleBudgetFor(100),
		"the four standing phases must sum to exactly one danglingResolveMax per tick")
	require.Positive(t, lifecycleBudgetFor(danglingResolveMax),
		"the GCE lifecycle phase must keep a nonzero share, or it silently stops draining")
}

// k8s-host-network-pod findings in an excluded system namespace are stale-state
// resolved via the SAME mechanism as the EC2 terminated-instance sweep — a
// namespace predicate instead of a lifecycle-state one, proving isStale
// generalizes cleanly to both. Such findings get stuck because a
// namespace-exclusion-list change inside a check's logic is invisible to the
// check-ID-based registry backfill.
func TestDanglingSweep_ResolvesHostNetworkPodInSystemNamespace(t *testing.T) {
	findings := newFakeDanglingFindings(
		finding.Finding{ID: "f-system", Source: "cspm", CheckID: "k8s-host-network-pod", ResourceType: "k8s_pod", ResourceID: "pod-1", DetectedAt: time.Unix(1_700_000_003, 0)},
		finding.Finding{ID: "f-user", Source: "cspm", CheckID: "k8s-host-network-pod", ResourceType: "k8s_pod", ResourceID: "pod-2", DetectedAt: time.Unix(1_700_000_002, 0)},
	)
	assets := newFakeAssetExistence()
	assets.assets["pod-1"] = asset.Asset{ID: "pod-1", Metadata: map[string]string{"namespace": "kube-system"}}
	assets.live["pod-1"] = true
	assets.assets["pod-2"] = asset.Asset{ID: "pod-2", Metadata: map[string]string{"namespace": "default"}}
	assets.live["pod-2"] = true

	runDangling(t, findings, assets)

	require.True(t, findings.resolved["f-system"], "a system-namespace host-network finding resolves")
	require.False(t, findings.resolved["f-user"], "a user-namespace host-network finding stays open — it may be a real issue")
}

// k8s-privileged-container and k8s-dangerous-capabilities exempt system
// namespaces via the same isK8sSystemPod predicate as host-network, so their
// pre-exemption orphans on system-namespace pods (CNI/CSI/runtime-security
// agents, privileged by necessity) must resolve the same way; only
// application-namespace ones stay open.
func TestDanglingSweep_ResolvesPrivilegedContainerInSystemNamespace(t *testing.T) {
	findings := newFakeDanglingFindings(
		finding.Finding{ID: "priv-sys", Source: "cspm", CheckID: "k8s-privileged-container", ResourceType: "k8s_pod", ResourceID: "pod-1", DetectedAt: time.Unix(1_700_000_003, 0)},
		finding.Finding{ID: "caps-sys", Source: "cspm", CheckID: "k8s-dangerous-capabilities", ResourceType: "k8s_pod", ResourceID: "pod-3", DetectedAt: time.Unix(1_700_000_003, 0)},
		finding.Finding{ID: "priv-user", Source: "cspm", CheckID: "k8s-privileged-container", ResourceType: "k8s_pod", ResourceID: "pod-2", DetectedAt: time.Unix(1_700_000_002, 0)},
	)
	assets := newFakeAssetExistence()
	assets.assets["pod-1"] = asset.Asset{ID: "pod-1", Metadata: map[string]string{"namespace": "kube-system"}}
	assets.live["pod-1"] = true
	assets.assets["pod-3"] = asset.Asset{ID: "pod-3", Metadata: map[string]string{"namespace": "calico-system"}}
	assets.live["pod-3"] = true
	assets.assets["pod-2"] = asset.Asset{ID: "pod-2", Metadata: map[string]string{"namespace": "payments"}}
	assets.live["pod-2"] = true

	runDangling(t, findings, assets)

	require.True(t, findings.resolved["priv-sys"], "kube-system privileged-container finding resolves (privileged by necessity)")
	require.True(t, findings.resolved["caps-sys"], "calico-system dangerous-capabilities finding resolves")
	require.False(t, findings.resolved["priv-user"], "an application-namespace privileged container stays open — a real risk")
}

// A pod whose asset ROW still exists but whose last_seen has fallen behind the
// provider's high-water mark is gone, and its findings must resolve.
//
// This is the case that matters most: asset rows are never deleted from the
// ReplacingMergeTree, so a row-presence check (ExistingIDs) reports every
// churned pod as live — k8s_lifecycle_scanned stays high while
// k8s_lifecycle_resolved sits at zero, and findings on pods that no longer exist
// are unresolvable regardless of how far the sweep pages.
func TestDanglingSweep_ResolvesFindingsOnStaleButPresentPodAsset(t *testing.T) {
	now := time.Now()
	findings := newFakeDanglingFindings(
		k8sPodFinding("f-stale", "pod-stale", 1),
		k8sPodFinding("f-fresh", "pod-fresh", 2),
	)
	assets := newFakeAssetExistence("pod-stale", "pod-fresh")
	assets.highWater = now
	// The row is present for both; only last_seen differs.
	assets.assets["pod-stale"] = asset.Asset{ID: "pod-stale", LastSeen: now.Add(-30 * 24 * time.Hour)}
	assets.assets["pod-fresh"] = asset.Asset{ID: "pod-fresh", LastSeen: now}

	runDangling(t, findings, assets)

	require.True(t, findings.resolved["f-stale"],
		"a pod not seen since well before the high-water mark is gone, row or no row")
	require.False(t, findings.resolved["f-fresh"],
		"a currently-collected pod is never resolved")
}

// A pod missed by only a tick or two is inside the grace window and must survive.
func TestDanglingSweep_PodInsideGraceWindowIsNotResolved(t *testing.T) {
	now := time.Now()
	findings := newFakeDanglingFindings(k8sPodFinding("f-recent", "pod-recent", 1))
	assets := newFakeAssetExistence("pod-recent")
	assets.highWater = now
	assets.assets["pod-recent"] = asset.Asset{ID: "pod-recent", LastSeen: now.Add(-resourceGoneGrace / 2)}

	runDangling(t, findings, assets)

	require.False(t, findings.resolved["f-recent"],
		"within the grace window a missed collection tick must not look like deletion")
}

// The fail-safe: if Kubernetes collection has stopped, the high-water mark freezes
// and NOTHING may be resolved — otherwise a broken collector would mass-resolve
// the whole estate, silently clearing real findings.
func TestDanglingSweep_FrozenHighWaterResolvesNothing(t *testing.T) {
	frozen := time.Now().Add(-30 * 24 * time.Hour)
	findings := newFakeDanglingFindings(k8sPodFinding("f-any", "pod-any", 1))
	assets := newFakeAssetExistence("pod-any")
	assets.highWater = frozen
	// Last seen at the same moment collection stopped — not stale relative to it.
	assets.assets["pod-any"] = asset.Asset{ID: "pod-any", LastSeen: frozen}

	runDangling(t, findings, assets)

	require.Empty(t, findings.resolvedIDs,
		"a collector outage must never be mistaken for mass resource deletion")
}

// lifecycleSpecCheckIDs is derived from the spec list itself, not hardcoded, so
// the filter assertions below only ever match the resource-lifecycle sweep's
// queries — the other phases issue filters of their own shape, and naming one of
// their IDs here would assert the query shape of the wrong sweep.
var lifecycleSpecCheckIDs = func() map[string]bool {
	m := map[string]bool{}
	for _, spec := range resourceLifecycleSpecs {
		m[spec.checkID] = true
	}
	return m
}()

// The resource lifecycle sweep must ASK for the oldest findings, bounded by a
// cutoff. That query shape is what lets a backlog deeper than one tick's
// danglingScanMax scan ceiling ever be reached: with the default newest-first
// order and a cursor that restarts every tick, the sweep re-examines the
// freshest findings forever — all on live resources — and resolves nothing: a
// full tick's worth scanned, none resolved.
//
// Asserted on the filter rather than on a corpus larger than danglingScanMax so
// the test stays fast; reverting either `OldestFirst: true` or
// `DetectedBefore: cutoff` in sweepResourceLifecycle fails it.
func TestDanglingSweep_ResourceLifecycleAsksOldestFirstWithCutoff(t *testing.T) {
	now := time.Now()
	assets := newFakeAssetExistence("pod-live")
	assets.highWater = now
	findings := newFakeDanglingFindings(k8sPodFinding("f1", "pod-live", 1))

	runDangling(t, findings, assets)

	var checked int
	for _, f := range findings.seenFilters {
		if !lifecycleSpecCheckIDs[f.CheckID] {
			continue
		}
		checked++
		require.True(t, f.OldestFirst,
			"the lifecycle sweep must page oldest-first to reach the backlog")
		require.False(t, f.DetectedBefore.IsZero(),
			"it must bound candidates by the staleness cutoff")
		require.True(t, f.DetectedBefore.Before(now),
			"the cutoff must sit behind the provider high-water mark")
	}
	require.Positive(t, checked, "the lifecycle phase must have run at all")
}

// Ordering is honoured end to end: given a mixed corpus, the oldest orphan is
// resolved even when fresher findings on a live pod sort ahead of it by default.
func TestDanglingSweep_ResolvesOldestOrphanAheadOfFresherLiveFindings(t *testing.T) {
	now := time.Now()
	assets := newFakeAssetExistence("pod-live")
	assets.highWater = now

	var seed []finding.Finding
	for i := 0; i < 10; i++ {
		seed = append(seed, finding.Finding{
			ID: "fresh-" + strconv.Itoa(i), Source: "cspm",
			CheckID: "k8s-container-runs-as-root", ResourceType: "k8s_pod",
			ResourceID: "pod-live", DetectedAt: now.Add(time.Duration(i) * time.Second),
		})
	}
	seed = append(seed, finding.Finding{
		ID: "ancient-orphan", Source: "cspm",
		CheckID: "k8s-container-runs-as-root", ResourceType: "k8s_pod",
		ResourceID: "pod-long-gone", DetectedAt: now.Add(-90 * 24 * time.Hour),
	})
	findings := newFakeDanglingFindings(seed...)

	runDangling(t, findings, assets)

	require.Equal(t, []string{"ancient-orphan"}, findings.resolvedIDs,
		"the oldest orphan resolves; nothing on the live pod does")
}

// TestDanglingSweep_SourceSweepAsksOldestFirst is the same guard as
// TestDanglingSweep_ResourceLifecycleAsksOldestFirstWithCutoff, for
// sweepSource — the existence-check sweep covering aws_guardduty, the biggest
// single orphan source. A per-tick-reset newest-first cursor means a
// source whose live/near-head volume alone exceeds the per-tick budget can
// never advance into its own deeper backlog.
func TestDanglingSweep_SourceSweepAsksOldestFirst(t *testing.T) {
	findings := newFakeDanglingFindings(gdFinding("f1", "i-live", 1))
	assets := newFakeAssetExistence("i-live")

	runDangling(t, findings, assets)

	var checked int
	for _, f := range findings.seenFilters {
		if f.Source != "aws_guardduty" {
			continue
		}
		checked++
		require.True(t, f.OldestFirst, "the source sweep must page oldest-first to reach the backlog")
	}
	require.Positive(t, checked, "the source sweep must have run at all")
}

// End to end: a huge live-resource backlog near the head must not stop the
// source sweep from reaching an ancient orphan sitting behind it.
func TestDanglingSweep_SourceSweepResolvesOldestOrphanBehindLiveBacklog(t *testing.T) {
	var seed []finding.Finding
	for i := 0; i < 10; i++ {
		seed = append(seed, gdFinding("fresh-"+strconv.Itoa(i), "i-live", i))
	}
	seed = append(seed, finding.Finding{
		ID: "ancient-orphan", Source: "aws_guardduty", ResourceType: "ec2_instance",
		ResourceID: "i-long-gone", DetectedAt: time.Unix(1_600_000_000, 0),
	})
	findings := newFakeDanglingFindings(seed...)
	assets := newFakeAssetExistence("i-live")

	runDangling(t, findings, assets)

	require.Equal(t, []string{"ancient-orphan"}, findings.resolvedIDs,
		"the oldest orphan resolves; nothing on the live instance does")
}

// TestDanglingSweep_StaleStateSweepAsksOldestFirst is the same guard as
// TestDanglingSweep_SourceSweepAsksOldestFirst, for sweepStaleState.
func TestDanglingSweep_StaleStateSweepAsksOldestFirst(t *testing.T) {
	findings := newFakeDanglingFindings(cspmEC2Finding("f1", "i-live", 1))
	assets := newFakeAssetExistence("i-live")

	runDangling(t, findings, assets)

	var checked int
	for _, f := range findings.seenFilters {
		if f.CheckID != "aws-ec2-public-ip" {
			continue
		}
		checked++
		require.True(t, f.OldestFirst, "the stale-state sweep must page oldest-first to reach the backlog")
	}
	require.Positive(t, checked, "the stale-state sweep must have run at all")
}

// Every spec in a phase must get budget. Handing the first spec the WHOLE phase
// budget lets a spec with a deep backlog starve every spec after it permanently:
// the phase's resolved count lands exactly at the phase budget, with the first
// check draining nearly all of it while the second check — same dead pods,
// second in the list — drains almost nothing.
func TestDanglingSweep_FirstSpecCannotStarveTheSecond(t *testing.T) {
	now := time.Now()
	assets := newFakeAssetExistence() // no live assets: every pod below is gone
	assets.highWater = now
	old := now.Add(-30 * 24 * time.Hour)

	// The FIRST spec's backlog alone must exceed the whole phase budget — that is
	// the condition under which a "take everything remaining" loop starves the
	// second spec completely. With a smaller backlog the bug hides, because
	// spec one runs out of orphans before it runs out of budget.
	perCheck := lifecycleBudgetFor(danglingResolveMax) + 200
	var seed []finding.Finding
	for i := 0; i < perCheck; i++ {
		seed = append(seed,
			finding.Finding{ID: "root-" + strconv.Itoa(i), Source: "cspm",
				CheckID: "k8s-container-runs-as-root", ResourceType: "k8s_pod",
				ResourceID: "gone-root-" + strconv.Itoa(i),
				DetectedAt: old.Add(time.Duration(i) * time.Second)},
			finding.Finding{ID: "privesc-" + strconv.Itoa(i), Source: "cspm",
				CheckID: "k8s-privileged-container", ResourceType: "k8s_pod",
				ResourceID: "gone-privesc-" + strconv.Itoa(i),
				DetectedAt: old.Add(time.Duration(i) * time.Second)})
	}
	findings := newFakeDanglingFindings(seed...)

	runDangling(t, findings, assets)

	var root, privesc int
	for _, id := range findings.resolvedIDs {
		if strings.HasPrefix(id, "root-") {
			root++
		}
		if strings.HasPrefix(id, "privesc-") {
			privesc++
		}
	}
	require.Positive(t, root, "the first spec must still drain")
	require.Positive(t, privesc,
		"the second spec must get budget too — the first must not consume the phase")
}

// fairShare redistributes: a spec that drains early donates its unused share to
// those after it, and no spec is ever handed a zero budget while budget remains
// (a zero would silently skip it).
func TestFairShare(t *testing.T) {
	// 4 specs, nothing spent: an even split.
	require.Equal(t, 25, fairShare(100, 0, 0, 4))
	// Third of four, 60 already spent: 40 left over 2 remaining specs.
	require.Equal(t, 20, fairShare(100, 60, 2, 4))
	// Last spec gets everything still unspent.
	require.Equal(t, 10, fairShare(100, 90, 3, 4))
	// Budget exhausted → 0, the caller's stop signal.
	require.Equal(t, 0, fairShare(100, 100, 1, 4))
	require.Equal(t, 0, fairShare(100, 120, 1, 4))
	// Tiny remainder still yields work rather than a silent skip.
	require.Equal(t, 1, fairShare(100, 99, 0, 4))
}

// gatherMetric finds one Prometheus metric family by name in a registry's
// current scrape, so a test can assert on counter/gauge VALUES without the
// obs package exposing its unexported vecs.
func gatherMetric(t *testing.T, reg *prometheus.Registry, name string) []*dto.Metric {
	t.Helper()
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf.GetMetric()
		}
	}
	return nil
}

func labelValue(m *dto.Metric, name string) string {
	for _, lp := range m.GetLabel() {
		if lp.GetName() == name {
			return lp.GetValue()
		}
	}
	return ""
}

// TestDanglingSweep_RecordsScannedEvenWhenResolvedIsZero pins the exact
// failure mode this instrumentation exists to catch: a phase that scans a
// backlog but resolves nothing must still show up as "scanned" — otherwise a
// sweep reporting "resolved: 0" against a large backlog has no metric
// distinguishing "nothing to do" from "stuck". A test
// that only checked resolvedIDs (as every other test in this file does) would
// still pass if recordSweepPhase were deleted entirely — this one would not.
func TestDanglingSweep_RecordsScannedEvenWhenResolvedIsZero(t *testing.T) {
	now := time.Now()
	findings := newFakeDanglingFindings(k8sPodFinding("f-live", "pod-live", 1))
	assets := newFakeAssetExistence("pod-live")
	assets.highWater = now

	m := obs.New()
	w := &DanglingSweepWorker{findings: findings, assets: assets, metrics: m}
	require.NoError(t, w.Work(context.Background(), &river.Job[DanglingSweepArgs]{Args: DanglingSweepArgs{}}))
	require.Empty(t, findings.resolvedIDs, "the live pod's finding must not resolve")

	scanned := gatherMetric(t, m.Registry(), "graph_sweep_outcomes_total")
	var sawScanned bool
	for _, sample := range scanned {
		if labelValue(sample, "phase") != sweepPhaseK8sLifecycle {
			continue
		}
		switch labelValue(sample, "outcome") {
		case "scanned":
			sawScanned = true
			require.Equal(t, float64(1), sample.GetCounter().GetValue())
		case "resolved":
			t.Fatalf("resolved=0 must be a no-op (no sample), got sample %v", sample)
		}
	}
	require.True(t, sawScanned, "a scanned finding with nothing resolved must still be recorded")
}

// TestDanglingSweep_RecordsResolvedAndLastResolvedGauge covers the opposite
// case: when a phase does resolve findings, both the outcome counter and the
// last-resolved gauge (the piece that lets an alert distinguish a currently-
// healthy phase from one that has gone stale) must advance.
func TestDanglingSweep_RecordsResolvedAndLastResolvedGauge(t *testing.T) {
	findings := newFakeDanglingFindings(
		gdFinding("f-gone1", "i-gone1", 2),
		gdFinding("f-gone2", "i-gone2", 1),
	)
	assets := newFakeAssetExistence() // nothing live: both are orphans

	m := obs.New()
	w := &DanglingSweepWorker{findings: findings, assets: assets, metrics: m}
	before := time.Now().Unix()
	require.NoError(t, w.Work(context.Background(), &river.Job[DanglingSweepArgs]{Args: DanglingSweepArgs{}}))
	after := time.Now().Unix()

	require.Len(t, findings.resolvedIDs, 2)

	outcomes := gatherMetric(t, m.Registry(), "graph_sweep_outcomes_total")
	var sawResolved bool
	for _, sample := range outcomes {
		if labelValue(sample, "phase") != sweepPhaseDangling || labelValue(sample, "outcome") != "resolved" {
			continue
		}
		sawResolved = true
		require.Equal(t, float64(2), sample.GetCounter().GetValue())
	}
	require.True(t, sawResolved, "a phase that resolves findings must record the resolved outcome")

	lastResolved := gatherMetric(t, m.Registry(), "graph_sweep_last_resolved_timestamp_seconds")
	var sawGauge bool
	for _, sample := range lastResolved {
		if labelValue(sample, "phase") != sweepPhaseDangling {
			continue
		}
		sawGauge = true
		v := sample.GetGauge().GetValue()
		require.GreaterOrEqual(t, v, float64(before))
		require.LessOrEqual(t, v, float64(after))
	}
	require.True(t, sawGauge, "a phase that resolves findings must stamp the last-resolved gauge")
}

// Fail-safe: with no assets of the ephemeral type at all there is no high-water
// mark to anchor to, so NOTHING may be judged gone. Without this guard an empty,
// wiped, or newly-provisioned assets table reads as "every pod was deleted" and
// resolves the entire corpus in one tick.
func TestDanglingSweep_EphemeralSweepResolvesNothingWithoutAHighWaterMark(t *testing.T) {
	findings := newFakeDanglingFindings(
		k8sPodFinding("f-pod", "pod-gone", 1),
		finding.Finding{ID: "f-latest", Source: "cspm", CheckID: "k8s-image-latest-tag",
			ResourceType: "k8s_pod", ResourceID: "pod-gone2", DetectedAt: time.Unix(1_700_000_000, 0)},
	)
	assets := &noHighWaterAssets{fakeAssetExistence: newFakeAssetExistence()}

	w := &DanglingSweepWorker{findings: findings, assets: assets}
	require.NoError(t, w.Work(context.Background(), &river.Job[DanglingSweepArgs]{Args: DanglingSweepArgs{}}))

	require.Empty(t, findings.resolvedIDs,
		"a collector that has produced no assets at all must never look like mass deletion")
}

// TestDanglingSweepInsertOptsCapsRetries pins MaxAttempts against River's
// library default of 25, which an InsertOpts setting only Queue silently
// inherits — the same guard as TestCorrelateInsertOptsCapsRetries and
// TestEnrichSweepInsertOptsCapsRetries: if sweepStaleState times out on ClickHouse during a routine
// post-restart boot storm, with no cap it keeps retrying and re-running the
// entire monolithic sweep from scratch.
func TestDanglingSweepInsertOptsCapsRetries(t *testing.T) {
	opts := DanglingSweepArgs{}.InsertOpts()
	require.Equal(t, 2, opts.MaxAttempts,
		"a failing dangling sweep must surface after one retry, not grind for ~25 attempts")
	require.Equal(t, queueDangling, opts.Queue)
}

// TestDanglingSweepNextRetryLandsOutsideAttempt1sLikelyContentionWindow pins
// NextRetry's delay to the documented 20-45s band and confirms its floor
// clears the ClickHouse contention window batchReadTimeout's own
// doc comment measures — the gap this override exists to widen. (River's own
// default, ~1s after attempt 1's first failure, is far tighter than that
// window and is not what this override is sized against — see NextRetry's
// doc comment.)
func TestDanglingSweepNextRetryLandsOutsideAttempt1sLikelyContentionWindow(t *testing.T) {
	w := DanglingSweepWorker{}
	job := &river.Job[DanglingSweepArgs]{}

	before := time.Now()
	for i := 0; i < 200; i++ { // sample rand.N's range, not just one draw
		next := w.NextRetry(job)
		delay := next.Sub(before)
		require.GreaterOrEqual(t, delay, danglingRetryMinDelay,
			"NextRetry must never schedule sooner than danglingRetryMinDelay")
		require.Less(t, delay, danglingRetryMaxDelay+time.Second, // +1s slack for time.Now() drift across the loop
			"NextRetry must never schedule at or past danglingRetryMaxDelay")
	}
	require.GreaterOrEqual(t, danglingRetryMinDelay, 20*time.Second,
		"the floor of this override's range must clear the documented ClickHouse "+
			"contention window (batchReadTimeout's own doc comment) — that window, not any "+
			"particular River default, is what this override is sized against")
}

// TestDanglingSweepWorstCasePageBudgetFitsJobTimeout pins the arithmetic
// finding.BatchReadTimeout's doc comment relies on: DanglingSweepWorker.Timeout
// (5 minutes) must comfortably absorb the realistic contention case. A change
// to danglingPageSize, danglingScanMax, DanglingSweepWorker.Timeout, or
// finding.BatchReadTimeout invalidates this arithmetic and must re-derive it,
// not just make the test pass again.
func TestDanglingSweepWorstCasePageBudgetFitsJobTimeout(t *testing.T) {
	// One finding.List() call is bounded by exactly ONE finding.BatchReadTimeout
	// window, not two: List's phase-one key select creates a qCtx with
	// context.WithTimeout(ctx, batchReadTimeout), then passes that SAME qCtx
	// into ByIDs, whose own context.WithTimeout(qCtx, batchReadTimeout) cannot
	// extend a child context's deadline past its already-set parent deadline
	// (confirmed empirically — see finding/repo.go's List doc comment). So the
	// pathological one-target worst case is 125 pages * 60s = 125 minutes, not
	// 250 — vastly exceeding the 5-minute Timeout either way, which is expected
	// and fine: Timeout's own ctx cancellation (not batchReadTimeout) is what
	// bounds that case. Not asserted directly here: an inequality against a
	// quantity this far past the bound it's compared to has near-zero
	// discriminating power (it holds across an enormous range of wrong
	// constants, so a wrong premise such as "2 calls per List()" would pass
	// undetected). maxPagesPerTarget and the headroom
	// check below are the two assertions that actually pin something a bad
	// edit could violate.
	maxPagesPerTarget := danglingScanMax / danglingPageSize
	require.Equal(t, 125, maxPagesPerTarget)

	timeout := DanglingSweepWorker{}.Timeout(&river.Job[DanglingSweepArgs]{})

	// The realistic case: a handful of calls landing in a contention window long
	// enough to hit BatchReadTimeout in one tick, everything else at normal (100ms-1s) cost.
	// 4 fully-timed-out calls at the ceiling must still leave real headroom
	// inside the 5-minute Timeout for the rest of the tick's normal-cost calls.
	const assumedContendedCallsPerTick = 4
	realisticContentionCost := time.Duration(assumedContendedCallsPerTick) * finding.BatchReadTimeout
	headroom := timeout - realisticContentionCost
	require.GreaterOrEqual(t, headroom, time.Minute,
		"a realistic number of contended calls in one tick must still leave at least a minute "+
			"of the job Timeout for the rest of the tick's normal-cost calls")
}

// noHighWaterAssets is a store that knows the type but has never collected it.
type noHighWaterAssets struct {
	*fakeAssetExistence
}

func (noHighWaterAssets) TypeHighWater(context.Context, string) (time.Time, error) {
	return time.Time{}, nil
}
