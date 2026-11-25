package aws

import (
	"context"
	"encoding/json"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/awspolicy"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// policyDoc is one policy attached to a principal, stored in the asset metadata
// as JSON. The CIEM analyzer parses these to compute effective permissions.
type policyDoc struct {
	Name       string `json:"name"`
	Type       string `json:"type"` // identity | trust | boundary | scp
	Managed    bool   `json:"managed"`
	Document   string `json:"document"` // raw JSON policy document
	Incomplete bool   `json:"incomplete,omitempty"`
}

// policyNameFromARN returns the policy name (the segment after "policy/") from a
// policy ARN, falling back to the whole ARN if it has no such segment.
func policyNameFromARN(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 && i+1 < len(arn) {
		return arn[i+1:]
	}
	return arn
}

// isAdminish requires a proven unrestricted wildcard grant. Missing documents,
// conditions, widening approximations and observed restrictions cannot establish
// admin authority, even when a policy is named AdministratorAccess.
func isAdminish(ctx context.Context, principal string, policies []policyDoc) bool {
	return ciemPermissionsGrantWildcard(ctx, principal, policies)
}

func ciemPermissionsGrantWildcard(ctx context.Context, principal string, policies []policyDoc) bool {
	var ciemPolicies []ciem.Policy
	for _, p := range policies {
		if p.Type == "trust" {
			continue
		}
		ciemPolicies = append(ciemPolicies, ciem.Policy{
			Name: p.Name, Type: p.Type, Document: p.Document, IsManaged: p.Managed, Incomplete: p.Incomplete,
		})
	}
	if names := ciem.NotActionAllowPolicies(ciemPolicies); len(names) > 0 {
		log.FromContext(ctx).Debug().Str("principal", principal).Strs("policies", names).
			Msg("aws iam: NotAction Allow treated as Allow * (conservative over-approximation)")
	}
	perms, err := ciem.EffectivePermissionsForPolicies(ciemPolicies)
	if err != nil {
		return false
	}
	unrestricted := false
	for _, p := range perms {
		if p.Effect == "Deny" {
			return false
		}
		if !p.Approximate && len(p.NotActions) == 0 && len(p.NotResources) == 0 &&
			p.Action == "*" && p.Resource == "*" {
			unrestricted = true
		}
	}
	return unrestricted
}

// grantsWildcardAction tolerantly parses an IAM policy document and reports
// whether it has an Allow statement granting Action "*". Handles Statement as
// object-or-array and Action as string-or-array (the usual AWS polymorphism).
func grantsWildcardAction(doc string) bool {
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
		Effect string          `json:"Effect"`
		Action json.RawMessage `json:"Action"`
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
		if !strings.EqualFold(s.Effect, "Allow") {
			continue
		}
		if jsonHasStar(s.Action) {
			return true
		}
	}
	return false
}

func jsonHasStar(raw json.RawMessage) bool {
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

// managedPolicyCache fetches AWS-managed/customer-managed policy documents once
// per collection (a policy attached to many principals is fetched once).
type managedPolicyCache struct {
	client policyDocAPI
	docs   map[string]string
}

// policyDocAPI is the IAM surface a managed-policy document read needs.
type policyDocAPI interface {
	GetPolicy(context.Context, *iam.GetPolicyInput, ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

func newManagedPolicyCache(c policyDocAPI) *managedPolicyCache {
	return &managedPolicyCache{client: c, docs: map[string]string{}}
}

// document returns a managed policy's default-version document. ok is false
// when it could not be read. Failures are NOT cached: caching "" on one
// throttle would blank the policy for every other principal it is attached to
// for the rest of the sweep, and a blank document reads as "grants nothing".
func (m *managedPolicyCache) document(ctx context.Context, policyARN string) (string, bool) {
	if policyARN == "" {
		return "", false
	}
	if d, ok := m.docs[policyARN]; ok {
		return d, true
	}
	pol, err := m.client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: &policyARN})
	if err != nil || pol == nil || pol.Policy == nil || pol.Policy.DefaultVersionId == nil {
		return "", false
	}
	ver, err := m.client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: &policyARN, VersionId: pol.Policy.DefaultVersionId,
	})
	if err != nil || ver == nil || ver.PolicyVersion == nil {
		return "", false
	}
	doc := decodePolicyDocument(awssdk.ToString(ver.PolicyVersion.Document))
	m.docs[policyARN] = doc
	return doc, true
}

// decodePolicyDocument normalizes the API's encoded document before storage.
// Plain JSON and malformed inputs stay unchanged; downstream parsers validate
// the policy and can safely normalize again without decoding literal text.
func decodePolicyDocument(doc string) string {
	return awspolicy.NormalizeDocument(doc)
}

func encodePolicies(docs []policyDoc) string {
	if len(docs) == 0 {
		return "[]"
	}
	b, err := json.Marshal(docs)
	if err != nil {
		return "[]"
	}
	return string(b)
}
