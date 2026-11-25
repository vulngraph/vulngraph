// Package awspolicy holds small AWS IAM policy-document helpers, free of
// infrastructure dependencies, shared by multiple layers (collectors,
// correlators, the CIEM trust evaluator) that each need to reason about
// explicit-deny and condition semantics without importing one another.
package awspolicy

import (
	"encoding/json"
	"strings"
)

// HasUnconditionalDenyAll reports whether a raw IAM policy document JSON
// contains an unconditional Deny statement covering every action and every
// resource (Effect: Deny, Action: "*", Resource: "*"). Tolerant of AWS's
// Statement-as-object-or-array and Action/Resource-as-string-or-array
// polymorphism.
//
// Deliberately conservative in two ways, both chosen because a false
// "yes, denied" would wrongly suppress a real dangerous-permission signal —
// the unsafe direction for a security-relevant detector:
//  1. Only a literal "*" on both Action and Resource counts.
//     NotAction/NotResource-based denies are not handled.
//  2. A Deny statement carrying a Condition is never treated as an
//     unconditional deny-all — AWS only applies deny-wins when the condition
//     actually holds (e.g. "Deny *:* unless MFA present" only blocks
//     non-MFA sessions, not everything).
//
// Callers are responsible for excluding trust (assume-role) policy documents
// before calling this — a trust policy governs who may assume a principal,
// not what the principal may do, so a Deny there must never be treated as
// neutralizing an identity/boundary/SCP grant.
func HasUnconditionalDenyAll(doc string) bool {
	if doc == "" {
		return false
	}
	var p struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(doc), &p) != nil {
		return false
	}
	type stmt struct {
		Effect    string          `json:"Effect"`
		Action    json.RawMessage `json:"Action"`
		Resource  json.RawMessage `json:"Resource"`
		Condition json.RawMessage `json:"Condition"`
	}
	var stmts []stmt
	if json.Unmarshal(p.Statement, &stmts) != nil {
		var one stmt
		if json.Unmarshal(p.Statement, &one) != nil {
			return false
		}
		stmts = []stmt{one}
	}
	for _, s := range stmts {
		if !strings.EqualFold(s.Effect, "Deny") {
			continue
		}
		if len(s.Condition) > 0 {
			continue // conditional deny is not an unconditional deny-all
		}
		if hasStar(s.Action) && hasStar(s.Resource) {
			return true
		}
	}
	return false
}

// hasStar reports whether a JSON Action/Resource field (string or array of
// strings) contains a literal "*" entry.
func hasStar(raw json.RawMessage) bool {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return single == "*"
	}
	var arr []string
	if json.Unmarshal(raw, &arr) == nil {
		for _, a := range arr {
			if a == "*" {
				return true
			}
		}
	}
	return false
}
