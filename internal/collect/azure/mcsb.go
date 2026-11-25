package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

// mcsbAssignmentName is the policy assignment Defender for Cloud creates for
// the Microsoft cloud security benchmark on every subscription it manages.
const mcsbAssignmentName = "SecurityCenterBuiltIn"

// mcsbDisabledPolicies reads CIS 8.1.10/8.1.11: which non-deprecated policies
// of the benchmark assignment a person set to Disabled, through an effect
// parameter or a policyEffect override. Policy defaults are Microsoft's, not
// the customer's, so only the assignment's own choices are read.
//
// Cost: the assignment, its initiative, and one built-in definition per
// disabled policy (to tell a deprecated policy from a live one) — normally
// a handful of GETs.
func mcsbDisabledPolicies(ctx context.Context, cred azcore.TokenCredential, subscriptionID string) (map[string]string, error) {
	assignments, err := armpolicy.NewAssignmentsClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("mcsbDisabledPolicies: %w", err)
	}
	a, err := assignments.Get(ctx, "/subscriptions/"+subscriptionID, mcsbAssignmentName, nil)
	if err != nil {
		return nil, fmt.Errorf("mcsbDisabledPolicies: assignment: %w", err)
	}
	if a.Properties == nil || a.Properties.PolicyDefinitionID == nil {
		return nil, fmt.Errorf("mcsbDisabledPolicies: assignment has no initiative")
	}
	sets, err := armpolicy.NewSetDefinitionsClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("mcsbDisabledPolicies: %w", err)
	}
	initiative, err := sets.GetBuiltIn(ctx, lastSegment(*a.Properties.PolicyDefinitionID), nil)
	if err != nil {
		return nil, fmt.Errorf("mcsbDisabledPolicies: initiative: %w", err)
	}
	defs, err := armpolicy.NewDefinitionsClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("mcsbDisabledPolicies: %w", err)
	}
	var names []string
	for _, defID := range disabledDefinitions(a.Properties, initiative.Properties) {
		d, err := defs.GetBuiltIn(ctx, lastSegment(defID), nil)
		if err != nil {
			return nil, fmt.Errorf("mcsbDisabledPolicies: definition %s: %w", defID, err)
		}
		if d.Properties == nil || deprecatedPolicy(d.Properties) {
			continue
		}
		names = append(names, strVal(d.Properties.DisplayName))
	}
	return map[string]string{"mcsb_disabled_policies": joinNames(names)}, nil
}

// disabledDefinitions returns the policy definition IDs of the initiative that
// the assignment disables: a definition whose parameters reference an
// assignment parameter set to "Disabled", or one a policyEffect override sets
// to Disabled by reference ID.
func disabledDefinitions(a *armpolicy.AssignmentProperties, initiative *armpolicy.SetDefinitionProperties) []string {
	if initiative == nil {
		return nil
	}
	var disabledParams []string
	for name, v := range a.Parameters {
		if v != nil && isDisabled(v.Value) {
			disabledParams = append(disabledParams, name)
		}
	}
	overridden := set()
	for _, o := range a.Overrides {
		if o == nil || o.Kind == nil || *o.Kind != armpolicy.OverrideKindPolicyEffect || o.Value == nil || !strings.EqualFold(*o.Value, "Disabled") {
			continue
		}
		for _, s := range o.Selectors {
			if s == nil || s.Kind == nil || *s.Kind != armpolicy.SelectorKindPolicyDefinitionReferenceID {
				continue
			}
			for _, ref := range s.In {
				if ref != nil {
					overridden[*ref] = struct{}{}
				}
			}
		}
	}
	out := set()
	for _, ref := range initiative.PolicyDefinitions {
		if ref == nil || ref.PolicyDefinitionID == nil {
			continue
		}
		if ref.PolicyDefinitionReferenceID != nil {
			if _, ok := overridden[*ref.PolicyDefinitionReferenceID]; ok {
				out[*ref.PolicyDefinitionID] = struct{}{}
				continue
			}
		}
		for _, v := range ref.Parameters {
			expr, ok := v.Value.(string)
			if !ok {
				continue
			}
			for _, p := range disabledParams {
				if strings.Contains(expr, "parameters('"+p+"')") {
					out[*ref.PolicyDefinitionID] = struct{}{}
				}
			}
		}
	}
	return sortedKeys(out)
}

func isDisabled(v any) bool {
	s, ok := v.(string)
	return ok && strings.EqualFold(s, "Disabled")
}

// deprecatedPolicy: Azure marks retired built-ins with metadata.deprecated and
// a "[Deprecated]" display-name prefix.
func deprecatedPolicy(p *armpolicy.DefinitionProperties) bool {
	if m, ok := p.Metadata.(map[string]any); ok {
		if d, ok := m["deprecated"].(bool); ok && d {
			return true
		}
	}
	return strings.HasPrefix(strVal(p.DisplayName), "[Deprecated]")
}

func lastSegment(id string) string {
	return id[strings.LastIndex(id, "/")+1:]
}
