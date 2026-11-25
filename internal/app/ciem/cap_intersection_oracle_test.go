package ciem

import (
	"encoding/json"
	"slices"
	"testing"
)

// Enumerate concrete IAM request coordinates without using the production glob,
// statement-expansion or intersection helpers to derive expected answers.
// AWS identity and boundary allows must both admit the same action/resource.
func TestBoundaryIntersectionFiniteOracle(t *testing.T) {
	actions := []string{"iam:GetRole", "iam:PassRole"}
	resources := []string{"arn:aws:iam::111122223333:role/A", "arn:aws:iam::111122223333:role/B"}
	selectValues := func(values []string, mask int) []string {
		var selected []string
		for i, v := range values {
			if mask&(1<<i) != 0 {
				selected = append(selected, v)
			}
		}
		return selected
	}
	encode := func(statements []map[string]any) string {
		t.Helper()
		b, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statements})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	cases := 0
	for actionMask := 1; actionMask < 4; actionMask++ {
		for resourceMask := 1; resourceMask < 4; resourceMask++ {
			identityActions, identityResources := selectValues(actions, actionMask), selectValues(resources, resourceMask)
			if actionMask == 3 {
				identityActions = []string{"iam:*"}
			}
			if resourceMask == 3 {
				identityResources = []string{"*"}
			}
			identity := encode([]map[string]any{{"Effect": EffectAllow, "Action": identityActions, "Resource": identityResources}})
			for capMask := 0; capMask < 16; capMask++ {
				for _, grouped := range []bool{false, true} {
					var statements []map[string]any
					for ai, action := range actions {
						var allowedResources []string
						for ri, resource := range resources {
							if capMask&(1<<(ai*2+ri)) == 0 {
								continue
							}
							if grouped {
								allowedResources = append(allowedResources, resource)
							} else {
								statements = append(statements, map[string]any{"Effect": EffectAllow, "Action": action, "Resource": resource})
							}
						}
						if len(allowedResources) > 0 {
							statements = append(statements, map[string]any{"Effect": EffectAllow, "Action": action, "Resource": allowedResources})
						}
					}
					if capMask == 0 {
						// A valid, present boundary with no Allow grants nothing.
						statements = []map[string]any{{"Effect": EffectDeny, "Action": "*", "Resource": "*"}}
					}
					for _, reversed := range []bool{false, true} {
						ordered := slices.Clone(statements)
						if reversed {
							slices.Reverse(ordered)
						}
						perms, err := EvaluateEffectivePermissions(Principal{Provider: "aws", Policies: []Policy{
							{Name: "identity", Type: PolicyIdentity, Document: identity},
							{Name: "boundary", Type: PolicyBoundary, Document: encode(ordered)},
						}})
						if err != nil {
							t.Fatal(err)
						}
						for ai, action := range actions {
							got := AllowedResourceScopes(perms, action)
							for ri, resource := range resources {
								want := actionMask&(1<<ai) != 0 && resourceMask&(1<<ri) != 0 && capMask&(1<<(ai*2+ri)) != 0
								if slices.Contains(got, resource) != want {
									t.Fatalf("identity action mask=%d resource mask=%d cap=%d grouped=%t reversed=%t; %s on %s: want=%t scopes=%v", actionMask, resourceMask, capMask, grouped, reversed, action, resource, want, got)
								}
							}
						}
						cases++
					}
				}
			}
		}
	}
	t.Logf("%d identity/boundary representations, %d concrete action/resource answers", cases, cases*4)
}
