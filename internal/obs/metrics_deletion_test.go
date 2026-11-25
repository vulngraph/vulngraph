package obs

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestObserveScopeCompletions(t *testing.T) {
	m := New()
	m.ObserveScopeCompletions("aws-1", []ScopeCompletion{
		{Scope: "eu-west-1/ec2:instances", Count: 21000},
		{Scope: "us-east-1/ec2:instances", Count: 0},
	}, 1720000000)

	require.Equal(t, 1720000000.0,
		testutil.ToFloat64(m.deletion.scopeComplete.WithLabelValues("aws-1", "eu-west-1/ec2:instances")))
	require.Equal(t, 21000.0,
		testutil.ToFloat64(m.deletion.scopeEnumerated.WithLabelValues("aws-1", "eu-west-1/ec2:instances")))
	// A complete listing that found nothing is a real reading, not a missing one.
	require.Equal(t, 1720000000.0,
		testutil.ToFloat64(m.deletion.scopeComplete.WithLabelValues("aws-1", "us-east-1/ec2:instances")))
	require.Equal(t, 0.0,
		testutil.ToFloat64(m.deletion.scopeEnumerated.WithLabelValues("aws-1", "us-east-1/ec2:instances")))
}

// The gauge answers "how long since this scope could be trusted", so a scope
// that fails on a later sweep must KEEP its old timestamp and go stale. Zeroing
// or deleting it would answer nothing — and a scope going quiet for weeks is
// the exact case this has to make visible.
func TestObserveScopeCompletions_FailedScopeGoesStaleNotAbsent(t *testing.T) {
	m := New()
	m.ObserveScopeCompletions("aws-1", []ScopeCompletion{{Scope: "eu-west-1/ec2:instances", Count: 5}}, 1000)
	// Next sweep: only the sibling scope completed.
	m.ObserveScopeCompletions("aws-1", []ScopeCompletion{{Scope: "eu-west-1/ec2:subnets", Count: 2}}, 2000)

	require.Equal(t, 1000.0,
		testutil.ToFloat64(m.deletion.scopeComplete.WithLabelValues("aws-1", "eu-west-1/ec2:instances")),
		"a scope that did not complete keeps its previous watermark and ages")
	require.Equal(t, 2000.0,
		testutil.ToFloat64(m.deletion.scopeComplete.WithLabelValues("aws-1", "eu-west-1/ec2:subnets")))
}

func TestObserveDeletionCandidates_SplitsOnSweepCompleteness(t *testing.T) {
	m := New()

	// The common state: a best-effort family failed somewhere, so the
	// candidates are refused rather than acted on.
	m.ObserveDeletionCandidates("aws-1", 5000, false)
	require.Equal(t, 5000.0, testutil.ToFloat64(m.deletion.candidates.WithLabelValues("aws-1", "partial")))
	require.Equal(t, 0.0, testutil.ToFloat64(m.deletion.candidates.WithLabelValues("aws-1", "complete")))

	// A later clean sweep must not leave the refused reading behind.
	m.ObserveDeletionCandidates("aws-1", 7, true)
	require.Equal(t, 0.0, testutil.ToFloat64(m.deletion.candidates.WithLabelValues("aws-1", "partial")))
	require.Equal(t, 7.0, testutil.ToFloat64(m.deletion.candidates.WithLabelValues("aws-1", "complete")))
}

func TestDeletionObserversAreNilSafe(t *testing.T) {
	var m *Metrics
	require.NotPanics(t, func() {
		m.ObserveScopeCompletions("aws-1", []ScopeCompletion{{Scope: "s", Count: 1}}, 1)
		m.ObserveDeletionCandidates("aws-1", 1, true)
	})
	// An unattributable reading is dropped rather than published under "".
	real := New()
	real.ObserveScopeCompletions("", []ScopeCompletion{{Scope: "s", Count: 1}}, 1)
	real.ObserveScopeCompletions("aws-1", []ScopeCompletion{{Scope: "", Count: 1}}, 1)
	real.ObserveDeletionCandidates("", 1, true)
	require.Equal(t, 0, testutil.CollectAndCount(real.Registry(), "graph_sync_scope_last_complete_timestamp_seconds"))
	require.Equal(t, 0, testutil.CollectAndCount(real.Registry(), "graph_sync_deletion_candidates"))
}

// TestObserveForgetVerdict_WouldEnforceTracksScopingNotWouldForget pins that
// graph_forget_would_forget reads the same regardless of enforceScoped (it is
// Decide()'s own verdict, not gated by FORGET_ENFORCE_TYPES), while
// graph_forget_would_enforce is zero unless enforceScoped is true — the
// series that lets an operator read "would forget, but this type is not in
// the enforce scope" straight off Prometheus.
func TestObserveForgetVerdict_WouldEnforceTracksScopingNotWouldForget(t *testing.T) {
	m := New()

	m.ObserveForgetVerdict("aws-1", "us-east-1/ec2:security-groups", "security_group", "", 5, 5, true)
	m.ObserveForgetVerdict("aws-1", "us-east-1/ec2:vpcs", "vpc", "", 5, 5, false)

	require.Equal(t, 5.0, testutil.ToFloat64(
		m.deletion.wouldForget.WithLabelValues("aws-1", "us-east-1/ec2:security-groups", "security_group")))
	require.Equal(t, 5.0, testutil.ToFloat64(
		m.deletion.wouldForget.WithLabelValues("aws-1", "us-east-1/ec2:vpcs", "vpc")),
		"would_forget must not depend on enforceScoped")

	require.Equal(t, 5.0, testutil.ToFloat64(
		m.deletion.wouldEnforce.WithLabelValues("aws-1", "us-east-1/ec2:security-groups", "security_group")),
		"enforce-scoped type: would_enforce mirrors would_forget")
	require.Equal(t, 0.0, testutil.ToFloat64(
		m.deletion.wouldEnforce.WithLabelValues("aws-1", "us-east-1/ec2:vpcs", "vpc")),
		"non-scoped type: would_enforce stays 0 even though it would_forget")
}

// TestObserveForgetVerdict_RefusedScopePublishesZero covers the ordinary case
// (a refusal) alongside the enforceScoped parameter, proving the "confirmed and
// forgettable both published, even at zero" contract holds with it.
func TestObserveForgetVerdict_RefusedScopePublishesZero(t *testing.T) {
	m := New()
	m.ObserveForgetVerdict("aws-1", "eu-west-1/ec2:instances", "ec2_instance", "unconfirmed", 42, 0, false)

	require.Equal(t, 42.0, testutil.ToFloat64(
		m.deletion.shadowCandidates.WithLabelValues("aws-1", "eu-west-1/ec2:instances", "ec2_instance")))
	require.Equal(t, 0.0, testutil.ToFloat64(
		m.deletion.wouldForget.WithLabelValues("aws-1", "eu-west-1/ec2:instances", "ec2_instance")))
	require.Equal(t, 0.0, testutil.ToFloat64(
		m.deletion.wouldEnforce.WithLabelValues("aws-1", "eu-west-1/ec2:instances", "ec2_instance")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.deletion.refusals.WithLabelValues("unconfirmed")))
}
