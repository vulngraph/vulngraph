// Package policy stores the single-row approval-queue display policy. Per
// action class it can hide a class from the govern approval queue (guidance
// only, unless the item is urgent) or label it parked. For a class with no
// per-class rule, the suggest threshold sets whether its queue card is
// labelled parked or escalated. It does not change
// respond.Decide's gate outcome and does not block execution. Nothing here
// executes anything (ADR 087).
package policy

import (
	"errors"
	"time"
)

// ActionMode is how the approval queue displays a class of action.
type ActionMode string

const (
	ModeJIT      ActionMode = "jit"      // requires approval: parked for a human, runs only after a yes
	ModeDisabled ActionMode = "disabled" // hidden from the approval queue unless urgent (display only; does not block execution)
)

// ValidMode reports whether m is a mode the policy may store.
func ValidMode(m ActionMode) bool {
	return m == ModeJIT || m == ModeDisabled
}

// Policy is the single remediation policy row stored as "default".
type Policy struct {
	ID               string
	SuggestThreshold int
	ActionRules      map[string]ActionMode
	UpdatedAt        time.Time
	UpdatedBy        string
}

// The audit action the service writes to audit_events for a policy change,
// target_type AuditTargetPolicy and target_id "default".
const (
	AuditActionUpdate = "policy.update" // details: before, after
	AuditTargetPolicy = "approval_policy"
)

var (
	ErrNotFound     = errors.New("policy: not found")
	ErrBadThreshold = errors.New("policy: suggest_threshold must be between 0 and 100")
	ErrBadMode      = errors.New("policy: action rule mode must be jit or disabled")
)
