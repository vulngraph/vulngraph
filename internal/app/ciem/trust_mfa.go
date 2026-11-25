package ciem

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/awspolicy"
)

type mfaStates uint8

const (
	mfaAbsent mfaStates = 1 << iota
	mfaFalse
	mfaTrue
	allMFAStates    = mfaAbsent | mfaFalse | mfaTrue
	mfaConditionKey = "aws:multifactorauthpresent"
)

// possibleMFAStates over-approximates the requests an Allow can admit. Unknown
// predicates cannot establish protection; known MFA predicates still constrain
// the result because different condition keys and operators are ANDed.
func (s trustStatement) possibleMFAStates() mfaStates {
	states := allMFAStates
	for op, kvs := range s.conditions() {
		for key, val := range kvs {
			if strings.EqualFold(key, mfaConditionKey) {
				if matches, ok := mfaConditionStates(op, val); ok {
					states &= matches
				}
			}
		}
	}
	return states
}

// deniedMFAStates includes only states denied regardless of other request
// context. A Deny with another condition key may not apply, so it cannot prove
// universal MFA enforcement. Separate Deny statements can jointly cover absent
// and present-false; a single Null:true statement covers only absent.
func (s trustStatement) deniedMFAStates() mfaStates {
	conditions := s.conditions()
	if conditions == nil && awspolicy.HasCondition(s.Condition) {
		return 0
	}
	states := allMFAStates
	for op, kvs := range conditions {
		if len(kvs) == 0 {
			return 0
		}
		for key, val := range kvs {
			matches, ok := mfaConditionStates(op, val)
			if !strings.EqualFold(key, mfaConditionKey) || !ok {
				return 0
			}
			states &= matches
		}
	}
	return states
}

// AWS distinguishes an absent MFA key (for example a long-term access key),
// present-false, and present-true. Values within one predicate are ORed.
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-multifactorauthpresent
func mfaConditionStates(op string, value any) (mfaStates, bool) {
	op = strings.ToLower(op)
	if op != "bool" && op != "boolifexists" && op != "null" {
		return 0, false
	}
	valuesToCheck, isList := value.([]any)
	if !isList {
		valuesToCheck = []any{value}
	}
	for _, v := range valuesToCheck {
		switch v.(type) {
		case string, bool:
		default:
			return 0, false
		}
	}
	values := anyStrings(value)
	if len(values) == 0 {
		return 0, false
	}
	var states mfaStates
	for _, v := range values {
		switch strings.ToLower(v) {
		case "true":
			if op == "null" {
				states |= mfaAbsent
			} else {
				states |= mfaTrue
			}
		case "false":
			if op == "null" {
				states |= mfaFalse | mfaTrue
			} else {
				states |= mfaFalse
			}
		default:
			return 0, false
		}
	}
	if op == "boolifexists" {
		states |= mfaAbsent
	}
	return states, true
}
