package enrich

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/checks"
)

// A ceiling keyed on a check ID that no longer exists is silently inert, and the
// failure is invisible: the map still has an entry, the test above still passes,
// and nothing reads the ID. That is exactly what happened when gcp-sa-key-old and
// gcp-sa-key-unused were collapsed into gcp-sa-user-managed-key — the ceiling kept
// capping two dead IDs while the survivor inherited their whole population and
// became page-eligible. Bind the map to the registry so a check rename or collapse
// fails here instead.
func TestHygieneCeilingChecksAreRegistered(t *testing.T) {
	registered := map[string]bool{}
	for id := range checks.Default().IDs() {
		registered[id] = true
	}
	for checkID := range hygieneOptimizationChecks {
		require.True(t, registered[checkID],
			"hygiene ceiling caps %q, which is not a registered check — the cap is inert", checkID)
	}
}

func TestHygieneCeiling(t *testing.T) {
	for checkID := range hygieneOptimizationChecks {
		f, applied, err := HygieneCeiling{}.Evaluate(context.Background(),
			finding.Finding{CheckID: checkID})
		require.NoError(t, err)
		require.True(t, applied, checkID)
		require.Equal(t, ThresholdPage, f.Ceiling, checkID)
		require.NotEmpty(t, f.Detail, checkID)
	}

	// A check not on the list is untouched.
	_, applied, err := HygieneCeiling{}.Evaluate(context.Background(),
		finding.Finding{CheckID: "aws-iam-root-active-key"})
	require.NoError(t, err)
	require.False(t, applied)

	// The boundary of the list, in both directions: a leaked private key is a
	// confirmed incident and must keep its route to the page band, while its
	// rotation/idleness siblings on the same resource type must not — the AWS and
	// GCP halves of the same claim have to be capped alike.
	_, applied, err = HygieneCeiling{}.Evaluate(context.Background(),
		finding.Finding{CheckID: "gcp-sa-key-exposed"})
	require.NoError(t, err)
	require.False(t, applied, "an exposed key is an incident, not hygiene")

	// The AWS and GCP halves of the same claim have to be capped alike. GCP now
	// states it in one graded check rather than two, so both AWS rotation/idleness
	// checks pair against that single survivor.
	_, gcp, err := HygieneCeiling{}.Evaluate(context.Background(),
		finding.Finding{CheckID: "gcp-sa-user-managed-key"})
	require.NoError(t, err)
	for _, awsID := range []string{"aws-iam-access-key-old", "aws-iam-user-unused-access-key"} {
		_, aws, err := HygieneCeiling{}.Evaluate(context.Background(), finding.Finding{CheckID: awsID})
		require.NoError(t, err)
		require.Equal(t, aws, gcp, "%s and its GCP mirror are the same finding on two providers", awsID)
	}
}

// End-to-end through the scorer, using a representative factor breakdown for
// an aws-iam-overprivileged-role finding: the combined
// attack-paths, base-severity, blast-radius, cross-cluster, identity-hygiene,
// and toxic-combo factors alone land in the page band. The hygiene ceiling
// must keep the same finding out of page even though the resource-context
// signal is real.
func TestHygieneCeiling_KeepsOverprivilegedRoleOutOfPageBand(t *testing.T) {
	ceiling, applied, err := HygieneCeiling{}.Evaluate(context.Background(),
		finding.Finding{CheckID: "aws-iam-overprivileged-role"})
	require.NoError(t, err)
	require.True(t, applied)

	s := Aggregate([]Factor{
		ceiling,
		{Source: sourceAttackPaths, Points: 20},
		{Source: sourceBaseSeverity, Points: 30},
		{Source: sourceBlastRadius, Points: 4},
		{Source: sourceCrossCluster, Points: 12},
		{Source: sourceIdentityHygiene, Points: 6},
		{Source: sourceToxicCombo, Points: 20, Floor: ThresholdPipeline},
	})
	require.Less(t, int(s.Value), ThresholdPage, "hygiene ceiling must hold the score below the page band")
	require.NotEqual(t, BandPage, s.Band)
}

// A genuinely pager-worthy check (root active key) must still reach page band —
// the ceiling only applies to the checks explicitly listed.
func TestHygieneCeiling_DoesNotAffectCriticalFloor(t *testing.T) {
	floor, _, _ := CriticalFloor{}.Evaluate(context.Background(),
		finding.Finding{CheckID: "aws-iam-root-active-key"})
	s := Aggregate([]Factor{floor, {Source: sourceBaseSeverity, Points: 2}})
	require.GreaterOrEqual(t, int(s.Value), ThresholdPage)
	require.Equal(t, BandPage, s.Band)
}

// If a ceiling-capped check somehow also carries a KEV/CriticalFloor page
// floor, the floor wins — a ceiling must never suppress a "this always pages"
// assertion from another source.
func TestAggregate_CeilingCannotBreachPageFloor(t *testing.T) {
	s := Aggregate([]Factor{
		{Source: sourceHygieneCeiling, Ceiling: ThresholdPage},
		{Source: sourceKEV, Points: 30, Floor: ThresholdPage},
	})
	require.GreaterOrEqual(t, int(s.Value), ThresholdPage)
	require.Equal(t, BandPage, s.Band)
}
