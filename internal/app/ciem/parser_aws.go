package ciem

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/vulngraph/vulngraph/internal/awspolicy"
)

type awsPolicyDocument struct {
	Version   string                    `json:"Version"`
	Statement jsonStatementOrStatements `json:"Statement"`
}

// jsonStatementOrStatements handles both single-statement and array forms.
type jsonStatementOrStatements []awsStatement

func (s *jsonStatementOrStatements) UnmarshalJSON(data []byte) error {
	var arr []awsStatement
	if err := json.Unmarshal(data, &arr); err == nil {
		*s = arr
		return nil
	}
	var single awsStatement
	if err := json.Unmarshal(data, &single); err != nil {
		return fmt.Errorf("statement must be object or array: %w", err)
	}
	*s = []awsStatement{single}
	return nil
}

type awsStatement struct {
	Effect      string                `json:"Effect"`
	Action      stringOrSlice         `json:"Action"`
	NotAction   stringOrSlice         `json:"NotAction"`
	Resource    stringOrSlice         `json:"Resource"`
	NotResource stringOrSlice         `json:"NotResource"`
	Condition   map[string]condValues `json:"Condition"`
}

type condValues map[string]scalarOrSlice

type stringOrSlice []string

func (s *stringOrSlice) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = []string{single}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return fmt.Errorf("field must be string or []string: %w", err)
	}
	*s = arr
	return nil
}

// scalarOrSlice decodes a Condition value the same way AWS itself accepts one:
// a single string/number/boolean, or an array mixing any of those — e.g. some
// AWS managed policies use unquoted booleans ("Null": {"aws:ResourceTag/X":
// false}) that a map[string]stringOrSlice could never decode. A decode failure
// here would fail the whole policy's unmarshal and abort evaluation for every
// other policy on the same principal (evaluator.go's error path treats any
// non-boundary/SCP parse failure as fatal), so this must accept every shape
// AWS accepts. Every value is normalized to its string form since that's the
// only shape downstream Conditions/policy evaluation consumes.
type scalarOrSlice []string

func (s *scalarOrSlice) UnmarshalJSON(data []byte) error {
	var scalar any
	if err := json.Unmarshal(data, &scalar); err == nil {
		if str, ok := scalarToString(scalar); ok {
			*s = []string{str}
			return nil
		}
	}
	var arr []any
	if err := json.Unmarshal(data, &arr); err != nil {
		return fmt.Errorf("condition value must be a scalar or array of scalars: %w", err)
	}
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		str, ok := scalarToString(v)
		if !ok {
			return fmt.Errorf("condition value array element must be string, number, or boolean, got %T", v)
		}
		out = append(out, str)
	}
	*s = out
	return nil
}

// scalarToString stringifies a decoded JSON scalar (string/bool/float64 — the
// only concrete types encoding/json produces for an `any` target) and reports
// whether v was scalar at all; a slice/map decodes to non-scalar Go types and
// returns false so the caller falls through to the array-of-scalars path.
func scalarToString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		if t {
			return "true", true
		}
		return "false", true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	default:
		return "", false
	}
}

// ParseAWSPolicy parses an AWS IAM policy JSON document into PermissionStatements.
// Handles URL-encoded documents (as returned by GetPolicyVersion) and both
// string and []string forms for Action/Resource fields.
func ParseAWSPolicy(doc string) ([]PermissionStatement, error) {
	if doc == "" {
		return nil, nil
	}
	doc = awspolicy.NormalizeDocument(doc)

	var policy awsPolicyDocument
	if err := json.Unmarshal([]byte(doc), &policy); err != nil {
		return nil, fmt.Errorf("ParseAWSPolicy: %w", err)
	}

	out := make([]PermissionStatement, 0, len(policy.Statement))
	for _, stmt := range policy.Statement {
		ps := PermissionStatement{
			Effect:       stmt.Effect,
			Actions:      normalizeSlice(stmt.Action),
			NotActions:   normalizeSlice(stmt.NotAction),
			Resources:    normalizeSlice(stmt.Resource),
			NotResources: normalizeSlice(stmt.NotResource),
		}
		if stmt.Condition != nil {
			ps.Conditions = make(map[string]map[string][]string, len(stmt.Condition))
			for op, kvs := range stmt.Condition {
				ps.Conditions[op] = make(map[string][]string, len(kvs))
				for key, vals := range kvs {
					ps.Conditions[op][key] = []string(vals)
				}
			}
		}
		out = append(out, ps)
	}
	return out, nil
}

func normalizeSlice(s stringOrSlice) []string {
	if len(s) == 0 {
		return nil
	}
	return []string(s)
}
