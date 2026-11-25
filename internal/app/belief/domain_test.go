package belief

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestBelief_Validate(t *testing.T) {
	valid := Belief{
		FindingID: "f1", ResourceID: "r1", Claim: "controlled: SSO-gated, not urgent",
		Severity: finding.SeverityLow, Confidence: ConfidenceHigh, Status: StatusConfirmed,
		Evidence: []Evidence{{Clause: "assumption gated by IdP federation", Source: "trust_entry", Fact: "federated"}},
	}
	require.NoError(t, valid.Validate())

	noClaim := valid
	noClaim.Claim = ""
	require.ErrorIs(t, noClaim.Validate(), ErrNoClaim)

	ungrounded := valid
	ungrounded.Evidence = []Evidence{{Clause: "seems fine", Source: "", Fact: ""}}
	require.ErrorIs(t, ungrounded.Validate(), ErrUngrounded)

	noEvidence := valid
	noEvidence.Evidence = nil
	require.ErrorIs(t, noEvidence.Validate(), ErrUngrounded)
}

func TestEffective(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)
	adj := func(created, checked time.Time) Belief {
		return Belief{Provenance: ProvenanceAdjudicator, CreatedAt: created, CheckedAt: checked}
	}
	det := func(created time.Time) Belief {
		return Belief{Provenance: ProvenanceDeterministic, CreatedAt: created}
	}
	other := Belief{Provenance: "legacy", CreatedAt: t0}

	for _, tc := range []struct {
		name string
		in   []Belief
		want string // "" = not found
	}{
		{name: "none"},
		{name: "deterministic only", in: []Belief{det(t0)}, want: ProvenanceDeterministic},
		{name: "adjudicator only", in: []Belief{adj(t0, time.Time{})}, want: ProvenanceAdjudicator},
		{name: "adjudicator newer wins", in: []Belief{det(t0), adj(t0.Add(time.Hour), time.Time{})}, want: ProvenanceAdjudicator},
		{name: "tie goes to adjudicator", in: []Belief{adj(t0, time.Time{}), det(t0)}, want: ProvenanceAdjudicator},
		{name: "newer deterministic beats a stale verdict", in: []Belief{adj(t0, time.Time{}), det(t0.Add(time.Hour))}, want: ProvenanceDeterministic},
		{name: "verdict re-checked after the deterministic re-form wins",
			in: []Belief{adj(t0, t0.Add(2*time.Hour)), det(t0.Add(time.Hour))}, want: ProvenanceAdjudicator},
		{name: "verdict checked before the deterministic re-form loses",
			in: []Belief{adj(t0, t0.Add(time.Hour)), det(t0.Add(2 * time.Hour))}, want: ProvenanceDeterministic},
		{name: "unknown provenance is only a fallback", in: []Belief{other, det(t0.Add(-time.Hour))}, want: ProvenanceDeterministic},
		{name: "unknown provenance alone", in: []Belief{other}, want: "legacy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Effective(tc.in)
			require.Equal(t, tc.want != "", ok)
			require.Equal(t, tc.want, got.Provenance)
		})
	}
}

func TestBelief_LastChecked(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)
	require.Equal(t, t0, Belief{CreatedAt: t0}.LastChecked(), "never checked → created")
	require.Equal(t, t0.Add(time.Hour), Belief{CreatedAt: t0, CheckedAt: t0.Add(time.Hour)}.LastChecked())
	require.Equal(t, t0, Belief{CreatedAt: t0, CheckedAt: t0.Add(-time.Hour)}.LastChecked(),
		"a checked_at before created_at never moves it backwards")
}
