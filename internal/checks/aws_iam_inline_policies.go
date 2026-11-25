package checks

// aws_iam_inline_policies.go — inline policies (written directly on a user,
// group or role) that grant full CloudTrail access or the AWS Marketplace
// Subscribe action on every resource. Only inline policies are read; the
// managed policies a principal carries are reported on the policy itself.

import (
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

const (
	cloudTrailService      = "cloudtrail"
	marketplaceSubscribeID = "aws-marketplace:subscribe"
	inlineEvidenceKey      = "inline_policies"
)

func awsIAMInlinePolicyChecks() []Check {
	return []Check{
		awsIAMUserInlineCloudTrailFullAccess,
		awsIAMGroupInlineCloudTrailFullAccess,
		awsIAMRoleInlineCloudTrailFullAccess,
		awsIAMUserInlineMarketplaceSubscribe,
		awsIAMGroupInlineMarketplaceSubscribe,
		awsIAMRoleInlineMarketplaceSubscribe,
	}
}

// inlineCloudTrailProbe and inlineMarketplaceProbe are `policies` values that
// make their check fire. Evaluable tries them for an absent key, so a principal
// whose policies were not read is not taken for one that was read and clean.
const (
	inlineCloudTrailProbe  = `[{"name":"p","type":"identity","managed":false,"document":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"cloudtrail:*\",\"Resource\":\"*\"}]}"}]`
	inlineMarketplaceProbe = `[{"name":"p","type":"identity","managed":false,"document":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"aws-marketplace:Subscribe\",\"Resource\":\"*\"}]}"}]`

	cloudTrailDescription  = "An inline policy on this principal allows every CloudTrail action (cloudtrail:*) on all resources and no statement in the same policy denies any of them. The holder can stop, delete or reconfigure the trails, event data stores and channels that record account activity, which erases the evidence an investigation depends on. A deny of any single cloudtrail action in the same policy takes the policy out of scope."
	marketplaceDescription = "An inline policy on this principal allows aws-marketplace:Subscribe on all resources and no unconditional deny on all resources cancels it. The holder can subscribe the account to any paid Marketplace product, which commits spend and can bring third-party software into the account without a procurement review."
)

// inlinePolicyNames returns the names of the principal's inline policies that
// satisfy grants. ok is false when `policies` was not read.
func inlinePolicyNames(a asset.Asset, grants func([]iamStatement) bool) (names []string, ok bool) {
	entries, ok := iamPolicies(a)
	if !ok {
		return nil, false
	}
	for _, e := range entries {
		if e.Type != "identity" || e.Managed {
			continue
		}
		if stmts, parsed := iamStatements(e.Document); parsed && grants(stmts) {
			names = append(names, e.Name)
		}
	}
	return names, true
}

func inlineCloudTrailFull(a asset.Asset) bool {
	names, _ := inlinePolicyNames(a, func(s []iamStatement) bool { return grantsFullService(s, cloudTrailService) })
	return len(names) > 0
}

func inlineMarketplaceSubscribe(a asset.Asset) bool {
	names, _ := inlinePolicyNames(a, grantsMarketplaceSubscribe)
	return len(names) > 0
}

func inlineCloudTrailEvidence(a asset.Asset) map[string]string {
	names, _ := inlinePolicyNames(a, func(s []iamStatement) bool { return grantsFullService(s, cloudTrailService) })
	return map[string]string{inlineEvidenceKey: strings.Join(names, ",")}
}

func inlineMarketplaceEvidence(a asset.Asset) map[string]string {
	names, _ := inlinePolicyNames(a, grantsMarketplaceSubscribe)
	return map[string]string{inlineEvidenceKey: strings.Join(names, ",")}
}

func hasAllResources(s iamStatement) bool { return slices.Contains(s.list("Resource"), "*") }

// touchesService reports whether an action pattern can name an action of the
// service: its service part globs to the service name.
func touchesService(pattern, service string) bool {
	svc, _, _ := strings.Cut(pattern, ":")
	return iamGlob(svc, service)
}

// coversService reports whether an action pattern names every action of the
// service, which is what the literal action "service:*" is matched against. A
// pattern with `?` is never read as covering, since it names single characters.
func coversService(pattern, service string) bool {
	return !strings.Contains(pattern, "?") && iamGlob(pattern, service+":*")
}

// allowsFullService reports whether one Allow statement grants every action of
// the service: an Action pattern that covers it, or a NotAction whose
// exclusions leave the service untouched.
func allowsFullService(s iamStatement, service string) bool {
	for _, p := range s.list("Action") {
		if coversService(p, service) {
			return true
		}
	}
	if !s.has("NotAction") {
		return false
	}
	for _, p := range s.list("NotAction") {
		if touchesService(p, service) {
			return false
		}
	}
	return true
}

// deniesPartOfService reports whether a Deny statement removes at least one
// action of the service, whatever its Resource or Condition.
func deniesPartOfService(s iamStatement, service string) bool {
	for _, p := range s.list("Action") {
		if touchesService(p, service) {
			return true
		}
	}
	if !s.has("NotAction") {
		return false
	}
	for _, p := range s.list("NotAction") {
		if coversService(p, service) {
			return false
		}
	}
	return true
}

// grantsFullService reports whether the policy allows every action of the
// service on Resource "*" with no statement denying any part of it.
func grantsFullService(stmts []iamStatement, service string) bool {
	granted := false
	for _, s := range stmts {
		switch s.iamEffect() {
		case "allow":
			granted = granted || (hasAllResources(s) && allowsFullService(s, service))
		case "deny":
			if deniesPartOfService(s, service) {
				return false
			}
		}
	}
	return granted
}

// statementNamesAction reports whether a statement's Action or NotAction
// reaches the concrete (lowercased) action.
func statementNamesAction(s iamStatement, action string) bool {
	if anyGlob(s.list("Action"), action) {
		return true
	}
	return s.has("NotAction") && !anyGlob(s.list("NotAction"), action)
}

// grantsMarketplaceSubscribe reports whether the policy allows
// aws-marketplace:Subscribe on Resource "*" and no unconditional Deny on
// Resource "*" removes it. A conditional Deny is not counted: whether its
// condition holds depends on the request.
func grantsMarketplaceSubscribe(stmts []iamStatement) bool {
	allowed, denied := false, false
	for _, s := range stmts {
		if !hasAllResources(s) || !statementNamesAction(s, marketplaceSubscribeID) {
			continue
		}
		switch s.iamEffect() {
		case "allow":
			allowed = true
		case "deny":
			denied = denied || !s.has("Condition")
		}
	}
	return allowed && !denied
}

var awsIAMUserInlineCloudTrailFullAccess = Check{
	ID:          "aws-iam-user-inline-cloudtrail-full-access",
	Title:       "IAM user inline policy allows every CloudTrail action",
	Description: cloudTrailDescription,
	Remediation: "Console: IAM → Users → the user → Permissions → remove the inline policy that allows cloudtrail:*, or edit it to the specific cloudtrail actions needed. CLI: `aws iam delete-user-policy --user-name NAME --policy-name POLICY` after attaching a scoped replacement.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_user",
	Violates:    inlineCloudTrailFull,
	EvidenceFor: inlineCloudTrailEvidence,
	TableProbes: []string{inlineCloudTrailProbe},
}

var awsIAMGroupInlineCloudTrailFullAccess = Check{
	ID:          "aws-iam-group-inline-cloudtrail-full-access",
	Title:       "IAM group inline policy allows every CloudTrail action",
	Description: cloudTrailDescription,
	Remediation: "Console: IAM → User groups → the group → Permissions → remove the inline policy that allows cloudtrail:*, or edit it to the specific cloudtrail actions needed. CLI: `aws iam delete-group-policy --group-name NAME --policy-name POLICY` after attaching a scoped replacement.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_group",
	Violates:    inlineCloudTrailFull,
	EvidenceFor: inlineCloudTrailEvidence,
	TableProbes: []string{inlineCloudTrailProbe},
}

var awsIAMRoleInlineCloudTrailFullAccess = Check{
	ID:          "aws-iam-role-inline-cloudtrail-full-access",
	Title:       "IAM role inline policy allows every CloudTrail action",
	Description: cloudTrailDescription,
	Remediation: "Console: IAM → Roles → the role → Permissions → remove the inline policy that allows cloudtrail:*, or edit it to the specific cloudtrail actions needed. CLI: `aws iam delete-role-policy --role-name NAME --policy-name POLICY` after attaching a scoped replacement.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_role",
	Violates:    inlineCloudTrailFull,
	EvidenceFor: inlineCloudTrailEvidence,
	TableProbes: []string{inlineCloudTrailProbe},
}

var awsIAMUserInlineMarketplaceSubscribe = Check{
	ID:          "aws-iam-user-inline-marketplace-subscribe-all",
	Title:       "IAM user inline policy allows aws-marketplace:Subscribe on all resources",
	Description: marketplaceDescription,
	Remediation: "Console: IAM → Users → the user → Permissions → edit the inline policy so aws-marketplace:Subscribe is limited to named products, or remove it. CLI: `aws iam put-user-policy --user-name NAME --policy-name POLICY --policy-document file://scoped.json`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_user",
	Violates:    inlineMarketplaceSubscribe,
	EvidenceFor: inlineMarketplaceEvidence,
	TableProbes: []string{inlineMarketplaceProbe},
}

var awsIAMGroupInlineMarketplaceSubscribe = Check{
	ID:          "aws-iam-group-inline-marketplace-subscribe-all",
	Title:       "IAM group inline policy allows aws-marketplace:Subscribe on all resources",
	Description: marketplaceDescription,
	Remediation: "Console: IAM → User groups → the group → Permissions → edit the inline policy so aws-marketplace:Subscribe is limited to named products, or remove it. CLI: `aws iam put-group-policy --group-name NAME --policy-name POLICY --policy-document file://scoped.json`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_group",
	Violates:    inlineMarketplaceSubscribe,
	EvidenceFor: inlineMarketplaceEvidence,
	TableProbes: []string{inlineMarketplaceProbe},
}

var awsIAMRoleInlineMarketplaceSubscribe = Check{
	ID:          "aws-iam-role-inline-marketplace-subscribe-all",
	Title:       "IAM role inline policy allows aws-marketplace:Subscribe on all resources",
	Description: marketplaceDescription,
	Remediation: "Console: IAM → Roles → the role → Permissions → edit the inline policy so aws-marketplace:Subscribe is limited to named products, or remove it. CLI: `aws iam put-role-policy --role-name NAME --policy-name POLICY --policy-document file://scoped.json`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_role",
	Violates:    inlineMarketplaceSubscribe,
	EvidenceFor: inlineMarketplaceEvidence,
	TableProbes: []string{inlineMarketplaceProbe},
}
