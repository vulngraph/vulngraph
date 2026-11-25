package ciem

import "testing"

// TestParseAWSPolicy_BooleanCondition reproduces AWS's own condition shape —
// AmazonGuardDutyServiceRolePolicy (and many others) use an unquoted boolean
// value on the Null operator, e.g. "Null": {"aws:ResourceTag/X": false} — which
// the prior map[string]stringOrSlice decode type couldn't handle: it accepted
// only a JSON string or []string, never a bare boolean. That decode failure on
// one statement's condition failed the whole array-level Statement unmarshal,
// which then fell back to a single-object unmarshal that also failed (the raw
// JSON is actually an array), surfacing a misleading top-level "statement must
// be object or array" error and aborting effective-permission evaluation for
// every other policy on the same principal.
func TestParseAWSPolicy_BooleanCondition(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": "s3:GetObject",
				"Resource": "*",
				"Condition": {
					"Null": {
						"aws:ResourceTag/GuardDutyManaged": false
					}
				}
			}
		]
	}`

	stmts, err := ParseAWSPolicy(doc)
	if err != nil {
		t.Fatalf("ParseAWSPolicy: %v", err)
	}
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}
	got := stmts[0].Conditions["Null"]["aws:ResourceTag/GuardDutyManaged"]
	want := []string{"false"}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("Conditions[Null][aws:ResourceTag/GuardDutyManaged] = %v, want %v", got, want)
	}
}

// TestParseAWSPolicy_NumericCondition covers the other scalar AWS allows on a
// condition value — a bare number, e.g. NumericLessThan on a request size.
func TestParseAWSPolicy_NumericCondition(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": {
			"Effect": "Deny",
			"Action": "s3:PutObject",
			"Resource": "*",
			"Condition": {
				"NumericGreaterThan": {
					"s3:max-keys": 100
				}
			}
		}
	}`

	stmts, err := ParseAWSPolicy(doc)
	if err != nil {
		t.Fatalf("ParseAWSPolicy: %v", err)
	}
	got := stmts[0].Conditions["NumericGreaterThan"]["s3:max-keys"]
	if len(got) != 1 || got[0] != "100" {
		t.Fatalf("Conditions[NumericGreaterThan][s3:max-keys] = %v, want [100]", got)
	}
}

// TestParseAWSPolicy_MixedArrayCondition covers a condition value given as an
// array mixing scalar types, which AWS also permits.
func TestParseAWSPolicy_MixedArrayCondition(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": {
			"Effect": "Allow",
			"Action": "ec2:RunInstances",
			"Resource": "*",
			"Condition": {
				"StringEquals": {
					"aws:RequestTag/Enabled": [true, "manual"]
				}
			}
		}
	}`

	stmts, err := ParseAWSPolicy(doc)
	if err != nil {
		t.Fatalf("ParseAWSPolicy: %v", err)
	}
	got := stmts[0].Conditions["StringEquals"]["aws:RequestTag/Enabled"]
	want := []string{"true", "manual"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Conditions[StringEquals][aws:RequestTag/Enabled] = %v, want %v", got, want)
	}
}

// TestParseAWSPolicy_StringCondition is the pre-existing, always-worked shape —
// guards against a regression in the common case while fixing the scalar gap.
func TestParseAWSPolicy_StringCondition(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": {
			"Effect": "Allow",
			"Action": ["s3:GetObject", "s3:ListBucket"],
			"Resource": "*",
			"Condition": {
				"StringEquals": {
					"aws:PrincipalTag/team": "platform"
				}
			}
		}
	}`

	stmts, err := ParseAWSPolicy(doc)
	if err != nil {
		t.Fatalf("ParseAWSPolicy: %v", err)
	}
	if len(stmts[0].Actions) != 2 {
		t.Fatalf("expected 2 actions, got %v", stmts[0].Actions)
	}
	got := stmts[0].Conditions["StringEquals"]["aws:PrincipalTag/team"]
	if len(got) != 1 || got[0] != "platform" {
		t.Fatalf("Conditions[StringEquals][aws:PrincipalTag/team] = %v, want [platform]", got)
	}
}
