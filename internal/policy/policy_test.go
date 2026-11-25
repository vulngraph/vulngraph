package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecide(t *testing.T) {
	tests := []struct {
		name string
		in   Input
		want Decision
	}{
		{
			name: "observe is read-only, so it needs no approval",
			in:   Input{ActionClass: "observe", ConfidenceBand: "insufficient"},
			want: Decision{AllowAuto: true},
		},
		{
			name: "high confidence remediation still needs approval",
			in:   Input{ActionClass: "remediate", ConfidenceBand: "high"},
			want: Decision{NeedsApproval: true},
		},
		{
			name: "medium confidence needs approval",
			in:   Input{ActionClass: "modify", ConfidenceBand: "medium"},
			want: Decision{NeedsApproval: true},
		},
		{
			name: "low confidence escalates",
			in:   Input{ActionClass: "remediate", ConfidenceBand: "low"},
			want: Decision{Escalate: true},
		},
		{
			name: "insufficient confidence escalates",
			in:   Input{ActionClass: "modify", ConfidenceBand: "insufficient"},
			want: Decision{Escalate: true},
		},
		{
			name: "destroy at high confidence needs approval",
			in:   Input{ActionClass: "destroy", ConfidenceBand: "high"},
			want: Decision{NeedsApproval: true},
		},
		{
			name: "isolate at high confidence needs approval",
			in:   Input{ActionClass: "isolate", ConfidenceBand: "high"},
			want: Decision{NeedsApproval: true},
		},
		{
			name: "destroy at low confidence escalates",
			in:   Input{ActionClass: "destroy", ConfidenceBand: "low"},
			want: Decision{Escalate: true},
		},
		{
			name: "an action class the policy has never heard of needs approval",
			in:   Input{ActionClass: "rotate", ConfidenceBand: "high"},
			want: Decision{NeedsApproval: true},
		},
		{
			name: "an unknown action class at low confidence escalates",
			in:   Input{ActionClass: "rotate", ConfidenceBand: "low"},
			want: Decision{Escalate: true},
		},
		{
			name: "an empty action class is state-changing",
			in:   Input{ActionClass: "", ConfidenceBand: "high"},
			want: Decision{NeedsApproval: true},
		},
		{
			name: "observe matches exactly: a capitalised class is state-changing",
			in:   Input{ActionClass: "Observe", ConfidenceBand: "high"},
			want: Decision{NeedsApproval: true},
		},
		{
			name: "observe matches exactly: trailing space is state-changing",
			in:   Input{ActionClass: "observe ", ConfidenceBand: "insufficient"},
			want: Decision{Escalate: true},
		},
		{
			name: "an empty band needs approval",
			in:   Input{ActionClass: "remediate", ConfidenceBand: ""},
			want: Decision{NeedsApproval: true},
		},
		{
			name: "an unknown band needs approval",
			in:   Input{ActionClass: "remediate", ConfidenceBand: "very_high"},
			want: Decision{NeedsApproval: true},
		},
		{
			name: "observe at high confidence is still just observed",
			in:   Input{ActionClass: "observe", ConfidenceBand: "high"},
			want: Decision{AllowAuto: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, Decide(tt.in))
		})
	}
}

// TestGate_EvaluateIsDecide pins the respond.Gate adapter to Decide over the
// whole sampled input space.
func TestGate_EvaluateIsDecide(t *testing.T) {
	for _, c := range gateClasses {
		for _, b := range gateBands {
			in := Input{ActionClass: c, ConfidenceBand: b}
			got, err := Gate{}.Evaluate(context.Background(), in)
			require.NoError(t, err)
			require.Equal(t, Decide(in), got, "class=%q band=%q", c, b)
		}
	}
}

// gateClasses covers every class the planner emits plus values it does not:
// empty, unknown, and near-misses of "observe". Autonomy keyed on anything but
// the exact observe class would show up on one of these.
var gateClasses = []string{"observe", "remediate", "modify", "isolate", "destroy", "", "rotate", "Observe", "observe "}

var gateBands = []string{"high", "very_high", "medium", "low", "insufficient", ""}

func TestGate_ExactlyOneOutcome(t *testing.T) {
	for _, c := range gateClasses {
		for _, b := range gateBands {
			d := Decide(Input{ActionClass: c, ConfidenceBand: b})
			n := 0
			for _, v := range []bool{d.AllowAuto, d.NeedsApproval, d.Escalate} {
				if v {
					n++
				}
			}
			require.Equal(t, 1, n, "class=%q band=%q => %+v", c, b, d)
		}
	}
}

// TestGate_NoStateChangingInputIsAutonomous is ADR 087 asserted over the input
// space: however confident the planner is, no action other than a read-only
// observe is ever allowed to proceed without a human.
func TestGate_NoStateChangingInputIsAutonomous(t *testing.T) {
	for _, c := range gateClasses {
		for _, b := range gateBands {
			d := Decide(Input{ActionClass: c, ConfidenceBand: b})
			if c == "observe" {
				require.Truef(t, d.AllowAuto, "observe is read-only and must not wait for a human (band=%q)", b)
				continue
			}
			require.Falsef(t, d.AllowAuto,
				"class=%q band=%q was allowed to run without a human — Vulngraph never executes a "+
					"state-changing action on its own (ADR 087)", c, b)
		}
	}
}
