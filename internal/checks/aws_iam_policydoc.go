package checks

// aws_iam_policydoc.go — reads the policy documents the AWS collector stores
// in a principal's `policies` metadata (a JSON list of {name, type, managed,
// document}) for the inline-policy and role-trust checks.
//
// `policies` is written only when every policy of the principal was read, so
// its absence is an unread principal, never "no policies".

import (
	"encoding/json"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// iamPolicyEntry is one element of the `policies` metadata.
type iamPolicyEntry struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // identity | trust | boundary | scp
	Managed  bool   `json:"managed"`
	Document string `json:"document"`
}

// iamStatement is one policy statement with its fields left raw, so each check
// decides how strictly to read a field that IAM allows to be a string or a list.
type iamStatement map[string]json.RawMessage

// iamPolicies parses the principal's `policies` metadata; ok is false when the
// key is absent or unreadable.
func iamPolicies(a asset.Asset) (entries []iamPolicyEntry, ok bool) {
	raw, present := a.Metadata["policies"]
	if !present || json.Unmarshal([]byte(raw), &entries) != nil {
		return nil, false
	}
	return entries, true
}

// iamStatements parses a policy document's Statement (one object or a list).
// An element that is not an object is returned as a nil statement so the
// caller can tell the document departs from the expected shape. ok is false
// when the document does not parse or has no statements.
func iamStatements(doc string) (stmts []iamStatement, ok bool) {
	var d struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(doc), &d) != nil || len(d.Statement) == 0 {
		return nil, false
	}
	var rawList []json.RawMessage
	if json.Unmarshal(d.Statement, &rawList) != nil {
		rawList = []json.RawMessage{d.Statement}
	}
	for _, r := range rawList {
		var s iamStatement
		if json.Unmarshal(r, &s) != nil {
			s = nil
		}
		stmts = append(stmts, s)
	}
	return stmts, len(stmts) > 0
}

// has reports whether the key is present, whatever its value.
func (s iamStatement) has(key string) bool { return len(s[key]) > 0 }

// text returns a string field, "" when absent or not a string.
func (s iamStatement) text(key string) string {
	var v string
	if json.Unmarshal(s[key], &v) != nil {
		return ""
	}
	return v
}

// list returns a field that IAM writes as a string or a list of strings;
// elements that are not strings are dropped.
func (s iamStatement) list(key string) []string {
	return jsonStringList(s[key])
}

// object returns a field as a JSON object; ok is false when it is absent or
// another JSON type.
func (s iamStatement) object(key string) (map[string]json.RawMessage, bool) {
	var v map[string]json.RawMessage
	if json.Unmarshal(s[key], &v) != nil || v == nil {
		return nil, false
	}
	return v, true
}

func jsonStringList(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []any
	if json.Unmarshal(raw, &many) != nil {
		return nil
	}
	var out []string
	for _, e := range many {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// iamEffect is a statement's Effect, trimmed and lowercased as the inline-policy
// checks read it.
func (s iamStatement) iamEffect() string {
	return strings.ToLower(strings.TrimSpace(s.text("Effect")))
}

// iamGlob reports whether an IAM wildcard pattern names value: `*` is any run
// of characters, `?` exactly one, everything else literal, case-insensitive.
func iamGlob(pattern, value string) bool {
	p := []rune(strings.ToLower(strings.TrimSpace(pattern)))
	v := []rune(strings.ToLower(value))
	pi, vi := 0, 0
	star, resume := -1, 0
	for vi < len(v) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == v[vi]):
			pi++
			vi++
		case pi < len(p) && p[pi] == '*':
			star, resume = pi, vi
			pi++
		case star >= 0:
			resume++
			vi = resume
			pi = star + 1
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

func anyGlob(patterns []string, value string) bool {
	for _, p := range patterns {
		if iamGlob(p, value) {
			return true
		}
	}
	return false
}
