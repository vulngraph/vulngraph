// Package policy is the action gate of the decision pipeline. It decides how a
// proposed action reaches a human: parked for approval, or escalated because
// there is no basis to trust it. Vulngraph never executes a state-changing
// action on its own (ADR 087), so the only thing the gate lets proceed without
// a human is the read-only observe class, which changes nothing.
package policy

import "context"

// Action classes and confidence bands the gate reads. The planner emits the
// classes; any value it does not know is treated as state-changing.
const (
	classObserve     = "observe"
	bandLow          = "low"
	bandInsufficient = "insufficient"
)

// Input is the gating decision's input.
//
// The gate grants autonomy only to the read-only observe class (ADR 087), so
// it weighs no evidence about the estate: blast radius and the rest are shown
// to the human who approves, not consulted here. An EVIDENCE field (one the
// gate reasons about, as opposed to the action being proposed) added later must
// be paired with a `<Field>Known` bool whose safe value is the zero value — a
// Go zero value is indistinguishable from a measurement, and a failure to
// measure must never read as the safest possible evidence.
// TestAutoExecuteGateRequiresKnownEvidence enforces that pairing, and that
// Decide grants AllowAuto only on the observe class.
type Input struct {
	ActionClass    string
	ConfidenceBand string
}

// Decision is the gate's verdict. Exactly one of the three is true, and
// AllowAuto is only ever true for a read-only observe action.
type Decision struct {
	AllowAuto     bool
	NeedsApproval bool
	Escalate      bool
}

// Decide gates one proposed action. A read-only observe action may proceed
// without a human; a state-changing one is escalated on low or insufficient
// confidence and parked for approval otherwise. Matching is exact, so an
// unknown or misspelt class is state-changing.
func Decide(in Input) Decision {
	switch {
	case in.ActionClass == classObserve:
		return Decision{AllowAuto: true}
	case in.ConfidenceBand == bandLow, in.ConfidenceBand == bandInsufficient:
		return Decision{Escalate: true}
	default:
		return Decision{NeedsApproval: true}
	}
}

// Gate is Decide behind the respond.Gate interface.
type Gate struct{}

// Evaluate gates one proposed action. It never fails; the error return is
// part of respond.Gate.
func (Gate) Evaluate(_ context.Context, in Input) (Decision, error) {
	return Decide(in), nil
}
