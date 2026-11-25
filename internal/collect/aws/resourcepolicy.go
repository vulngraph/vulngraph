package aws

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/awspolicy"
)

// This file holds the deny-aware resource-policy grading shared by every AWS
// resource-based-policy collector (Lambda function policies, KMS key
// policies, SQS/SNS queue/topic policies, ECR repository policies, Secrets
// Manager resource policies, S3 bucket policies and the rest): Effect
// matters, Statement is object-or-array, a Deny only neutralizes the actions
// it names, and each caller supplies the "actions that actually confer access
// to this resource".

// resourcePolicyStatement is one statement of any AWS resource-based policy,
// keeping the polymorphic fields as raw JSON for tolerant parsing.
type resourcePolicyStatement struct {
	Effect       string          `json:"Effect"`
	Action       json.RawMessage `json:"Action"`
	NotAction    json.RawMessage `json:"NotAction"`
	Principal    json.RawMessage `json:"Principal"`
	NotPrincipal json.RawMessage `json:"NotPrincipal"`
	Resource     json.RawMessage `json:"Resource"`
	Condition    json.RawMessage `json:"Condition"`
}

// reachesAnyone reports whether the statement's principal set is open-ended:
// a wildcard Principal, or a NotPrincipal, which applies the statement to
// every principal except the ones it lists — anonymous callers included. A
// wildcard NotPrincipal excludes everyone, so it reaches no one.
func (s resourcePolicyStatement) reachesAnyone() bool {
	if resourcePolicyIsWildcardPrincipal(s.Principal) {
		return true
	}
	return len(s.NotPrincipal) > 0 && string(s.NotPrincipal) != "null" &&
		!resourcePolicyIsWildcardPrincipal(s.NotPrincipal)
}

// coversAction reports whether the statement applies to a concrete
// (lowercased) action: its Action names it, or it carries NotAction, which
// applies the statement to every action except the ones it lists.
func (s resourcePolicyStatement) coversAction(action string) bool {
	covers := func(p string) bool { return resourcePolicyActionPatternCovers(p, action) }
	if len(s.Action) == 0 && len(s.NotAction) > 0 {
		return !slices.ContainsFunc(resourcePolicyActionPatterns(s.NotAction), covers)
	}
	return slices.ContainsFunc(resourcePolicyActionPatterns(s.Action), covers)
}

// grantedActions returns which of the candidate (lowercased) sensitive
// actions the statement applies to.
func (s resourcePolicyStatement) grantedActions(candidates []string) []string {
	var out []string
	for _, action := range candidates {
		if s.coversAction(action) {
			out = append(out, action)
		}
	}
	return out
}

// resourcePolicyStatements parses a resource policy's Statement(s), tolerant
// of the single-object-or-array polymorphism AWS allows. Declaring Statement
// as an array alone would fail the whole unmarshal on a single-object policy
// (the common shape for a Lambda function with one AddPermission grant) and
// silently clear a genuinely public resource.
func resourcePolicyStatements(doc string) []resourcePolicyStatement {
	if doc == "" {
		return nil
	}
	var p struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(doc), &p) != nil || len(p.Statement) == 0 {
		return nil
	}
	var arr []resourcePolicyStatement
	if json.Unmarshal(p.Statement, &arr) == nil {
		return arr
	}
	var one resourcePolicyStatement
	if json.Unmarshal(p.Statement, &one) == nil {
		return []resourcePolicyStatement{one}
	}
	return nil
}

// resourcePolicyActionPatterns returns a statement's Action patterns,
// lowercased. An absent Action yields "*" (an Action-less statement is
// invalid IAM, so err toward the broad reading rather than silently
// clearing).
func resourcePolicyActionPatterns(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return []string{"*"}
	}
	lower := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, a := range in {
			out = append(out, strings.ToLower(a))
		}
		return out
	}
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return lower([]string{single})
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return lower(list)
	}
	return []string{"*"}
}

// resourcePolicyActionPatternCovers reports whether an IAM action pattern
// covers a concrete (lowercased) action name.
func resourcePolicyActionPatternCovers(pattern, action string) bool {
	if pattern == "*" || pattern == action {
		return true
	}
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(action, prefix)
	}
	return false
}

// resourcePolicyIsWildcardPrincipal reports whether a policy Principal JSON
// value is "*" or contains an AWS key whose value is "*".
func resourcePolicyIsWildcardPrincipal(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s == "*"
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return false
	}
	awsVal, ok := obj["AWS"]
	if !ok {
		return false
	}
	var single string
	if json.Unmarshal(awsVal, &single) == nil {
		return single == "*"
	}
	var list []string
	if json.Unmarshal(awsVal, &list) == nil {
		for _, v := range list {
			if v == "*" {
				return true
			}
		}
	}
	return false
}

// resourceActionDenied reports whether an unconditional Deny that reaches
// anyone (reachesAnyone: a wildcard Principal, or a NotPrincipal, which denies
// every principal it does not list) covers the given action anywhere in the
// statement set.
func resourceActionDenied(statements []resourcePolicyStatement, action string) bool {
	for _, stmt := range statements {
		if strings.EqualFold(stmt.Effect, "Deny") && !awspolicy.HasCondition(stmt.Condition) &&
			stmt.reachesAnyone() && stmt.coversAction(action) {
			return true
		}
	}
	return false
}

// publicResourceAccess grades a resource-based policy document deny-aware
// against a caller-supplied list of lowercased "actions that actually confer
// meaningful access to this resource" (e.g. kms:decrypt, sqs:receivemessage).
// Returns asset.PublicAccessConfirmed if an open-ended principal set
// (reachesAnyone) is granted one of those actions under no condition that
// pins the caller (awspolicy.RestrictsCaller) and no sibling Deny covers
// it, or
// asset.PublicAccessNone if the document exists but grants nothing sensitive
// to the public, or the document is empty/absent — an OBSERVATION that the
// policy was read and confers no public access, distinct from never having
// read it at all. A public grant of an action NOT in sensitiveActions (e.g.
// kms:DescribeKey) is deliberately not graded public: metadata disclosure is
// not the same as data/decrypt access.
//
// A condition only on transport or client shape (aws:SecureTransport,
// aws:UserAgent) still admits anyone on the internet, so it does not shield.
func publicResourceAccess(doc string, sensitiveActions []string) string {
	statements := resourcePolicyStatements(doc)
	if len(statements) == 0 {
		return asset.PublicAccessNone
	}
	for _, stmt := range statements {
		if !strings.EqualFold(stmt.Effect, "Allow") || !stmt.reachesAnyone() || awspolicy.RestrictsCaller(stmt.Condition) {
			continue
		}
		granted := stmt.grantedActions(sensitiveActions)
		if len(granted) == 0 {
			continue
		}
		for _, action := range granted {
			if !resourceActionDenied(statements, action) {
				return asset.PublicAccessConfirmed
			}
		}
	}
	return asset.PublicAccessNone
}

// resourcePolicyMetadata returns the "public_access" grading (possibly "")
// and the encoded policyDoc-array JSON (ciem.PolicyResource-typed, matching
// the {name,type,document} shape encodePolicies/iam.go uses for
// identity/trust/boundary policies) for one resource-based policy document.
// docName is stored as the policyDoc.Name (e.g. the key ID or ARN) so a
// later reader can tell which resource's policy this is.
//
// An empty doc yields "", "". Every call site gates this on its API call
// having SUCCEEDED, so doc=="" only means "asked, nothing to grant" — except
// ECR's GetRepositoryPolicy, which answers a missing policy with a typed
// error instead of an empty success, so ECR needs its own handling at the
// call site (see services.go collectECRRepos).
func resourcePolicyMetadata(doc, docName string, sensitiveActions []string) (publicAccess, policiesJSON string) {
	if doc == "" {
		return asset.PublicAccessNone, ""
	}
	return publicResourceAccess(doc, sensitiveActions), encodePolicies([]policyDoc{{
		Name:     docName,
		Type:     ciem.PolicyResource,
		Document: doc,
	}})
}
