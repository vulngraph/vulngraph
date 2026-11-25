package checks

// aws_iam_role_trust.go — role trust-policy checks: a ReadOnlyAccess role that
// trusts another account, and service roles whose trust lets an AWS service
// act for a resource in any account (the cross-service confused deputy).
//
// Both read the trust document and the attached managed policy names from the
// role's `policies` metadata; a role whose policies were not all read is not
// evaluated.

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

const (
	readOnlyAccessPolicyName = "ReadOnlyAccess"

	roleTrustProbe = `[{"name":"r-trust","type":"trust","managed":false,"document":"{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ecs-tasks.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"}]`

	unpinnedTrustProbe = `[{"name":"r-trust","type":"trust","managed":false,"document":"{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\",\"Condition\":{\"StringLike\":{\"aws:SourceAccount\":\"1234*\"}}}]}"}]`

	readOnlyProbe = `[{"name":"ReadOnlyAccess","type":"identity","managed":true,"document":""},{"name":"r-trust","type":"trust","managed":false,"document":"{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"sts:AssumeRole\"}]}"}]`
)

func awsIAMRoleTrustChecks() []Check {
	return []Check{
		awsIAMRoleCrossAccountReadOnly,
		awsIAMRoleServiceConfusedDeputy,
		awsIAMRoleServiceTrustUnpinnedSource,
	}
}

// roleTrust returns the role's trust statements and attached policies. ok is
// false when `policies` was not read or carries no readable trust document.
func roleTrust(a asset.Asset) (stmts []iamStatement, entries []iamPolicyEntry, ok bool) {
	entries, ok = iamPolicies(a)
	if !ok {
		return nil, nil, false
	}
	for _, e := range entries {
		if e.Type == "trust" {
			s, parsed := iamStatements(e.Document)
			return s, entries, parsed
		}
	}
	return nil, nil, false
}

func isServiceLinkedRole(a asset.Asset) bool { return strings.Contains(a.ID, "aws-service-role") }

// isServiceRole reports whether every trust statement is an Allow of
// sts:AssumeRole (or sts:* / *) to a Service principal and nothing else, the
// roles an AWS service assumes on the account's behalf.
func isServiceRole(stmts []iamStatement) bool {
	for _, s := range stmts {
		if s.text("Effect") != "Allow" || !mentionsAssumeRole(s) {
			return false
		}
		principal, ok := s.object("Principal")
		if !ok || len(principal) != 1 {
			return false
		}
		if _, onlyService := principal["Service"]; !onlyService {
			return false
		}
	}
	return len(stmts) > 0
}

// mentionsAssumeRole reads the Action the way the role classifier does: a list
// must contain one of the three spellings, a bare string only needs to mention
// one.
func mentionsAssumeRole(s iamStatement) bool {
	spellings := []string{"sts:AssumeRole", "sts:*", "*"}
	if bare := s.text("Action"); bare != "" {
		return slices.ContainsFunc(spellings, func(sp string) bool { return strings.Contains(bare, sp) })
	}
	return slices.ContainsFunc(s.list("Action"), func(act string) bool { return slices.Contains(spellings, act) })
}

// ── cross-account ReadOnlyAccess ─────────────────────────────────────────────

func crossAccountReadOnly(a asset.Asset) bool {
	stmts, entries, ok := roleTrust(a)
	if !ok || a.AccountID == "" || isServiceRole(stmts) {
		return false
	}
	attached := false
	for _, e := range entries {
		attached = attached || (e.Type == "identity" && e.Managed && e.Name == readOnlyAccessPolicyName)
	}
	if !attached {
		return false
	}
	for _, s := range stmts {
		if s.text("Effect") != "Allow" {
			continue
		}
		principal, isObject := s.object("Principal")
		if !isObject {
			continue
		}
		for _, p := range jsonStringList(principal["AWS"]) {
			if !strings.Contains(p, a.AccountID) || p == "*" {
				return true
			}
		}
	}
	return false
}

var awsIAMRoleCrossAccountReadOnly = Check{
	ID:          "aws-iam-role-cross-account-readonlyaccess",
	Title:       "IAM role gives another account read-only access through ReadOnlyAccess",
	Description: "This role has the AWS-managed ReadOnlyAccess policy attached and its trust policy lets a principal outside this account, or any principal, assume it. ReadOnlyAccess reads the metadata and often the data of nearly every service, so the trusted account can inventory and exfiltrate far more than a narrowly scoped audit role would allow. Service roles are not evaluated: their trust belongs to the service.",
	Remediation: "Console: IAM → Roles → the role → Trust relationships → Edit trust policy, and remove principals you do not recognise; replace ReadOnlyAccess with a policy for just the services the third party needs (Permissions → Remove, then Add permissions). CLI: `aws iam update-assume-role-policy --role-name NAME --policy-document file://trust.json` and `aws iam detach-role-policy --role-name NAME --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_role",
	Violates:    crossAccountReadOnly,
	TableProbes: []string{readOnlyProbe},
}

// ── cross-service confused deputy ────────────────────────────────────────────

// serviceDeputyExempt are the services that only assume a role for a resource
// in the account that owns it (an instance profile, a function execution role,
// a Secrets Manager rotation, an EKS cluster role), so their trust needs no
// source condition.
var serviceDeputyExempt = []string{"secretsmanager.amazonaws.com", "eks.amazonaws.com", "ec2.amazonaws.com", "lambda.amazonaws.com"}

// serviceTrustUnconstrained reports whether an Allow statement lets an AWS
// service, acting for any account, assume the role: a service principal that
// is "*" or ends in .amazonaws.com or .amazon.com, an assume-role action, and
// no condition that names an account, ARN, organisation, network or private
// source address.
func serviceTrustUnconstrained(s iamStatement) bool {
	if s.text("Effect") != "Allow" {
		return false
	}
	principal, ok := s.object("Principal")
	if !ok {
		return false
	}
	services := jsonStringList(principal["Service"])
	crossService := slices.ContainsFunc(services, func(svc string) bool {
		return svc == "*" || strings.HasSuffix(svc, ".amazonaws.com") || strings.HasSuffix(svc, ".amazon.com")
	})
	if !crossService || slices.ContainsFunc(services, func(svc string) bool { return slices.Contains(serviceDeputyExempt, svc) }) {
		return false
	}
	if !grantsAssumeRoleLiteral(s) {
		return false
	}
	cond, ok := parseCondition(s)
	if !ok {
		return false
	}
	return len(cond) == 0 || !conditionConfinesSource(cond)
}

// grantsAssumeRoleLiteral is true when the Action is "*" or lists sts:AssumeRole
// or sts:*, spelled exactly.
func grantsAssumeRoleLiteral(s iamStatement) bool {
	return slices.ContainsFunc(s.list("Action"), func(act string) bool {
		return act == "*" || act == "sts:AssumeRole" || act == "sts:*"
	})
}

func confusedDeputyRisk(a asset.Asset) bool {
	stmts, _, ok := roleTrust(a)
	if !ok || !isServiceRole(stmts) || isServiceLinkedRole(a) {
		return false
	}
	return slices.ContainsFunc(stmts, serviceTrustUnconstrained)
}

var awsIAMRoleServiceConfusedDeputy = Check{
	ID:          "aws-iam-role-service-confused-deputy",
	Title:       "IAM service role trust does not guard against a cross-service confused deputy",
	Description: "This role is assumed by an AWS service principal and its trust policy has no condition naming your account (aws:SourceAccount, aws:SourceArn, an organisation key, or a source network). Another customer's resource that uses the same service can then induce the service to assume this role, the confused-deputy problem. Service-linked roles, whose trust AWS manages, and the Secrets Manager, EKS, EC2 and Lambda principals, which only assume a role for a resource in the owning account, are not reported.",
	Remediation: "Console: IAM → Roles → the role → Trust relationships → Edit trust policy, and add a Condition such as StringEquals aws:SourceAccount with your account ID (and aws:SourceArn where the service sends one). CLI: `aws iam update-assume-role-policy --role-name NAME --policy-document file://trust-with-condition.json`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_role",
	Violates:    confusedDeputyRisk,
	TableProbes: []string{roleTrustProbe},
}

// ── service trust whose condition pins no source ─────────────────────────────

func unpinnedServiceTrust(a asset.Asset) bool {
	stmts, _, ok := roleTrust(a)
	if !ok || isServiceLinkedRole(a) {
		return false
	}
	for _, s := range stmts {
		if s.text("Effect") == "Allow" && s.has("NotAction") {
			return false
		}
	}
	plain := isPlainServiceTrust(stmts)
	for _, s := range stmts {
		if s == nil || s.text("Effect") != "Allow" || !grantsAssumeRolePattern(s) || !trustsServicePrincipal(s) {
			continue
		}
		cond, _ := parseCondition(s)
		if (plain && !hasEnforcedCondition(cond)) || preventsConfusedDeputy(cond) {
			continue
		}
		return true
	}
	return false
}

// grantsAssumeRolePattern is true when an Action pattern names sts:AssumeRole
// itself (sts:*, sts:Assume* and the like), not the wider assume-role family.
func grantsAssumeRolePattern(s iamStatement) bool {
	return anyGlob(s.list("Action"), "sts:AssumeRole")
}

// trustsServicePrincipal is true for a statement that trusts any AWS service
// principal, alongside others or not, or trusts every principal ("*").
func trustsServicePrincipal(s iamStatement) bool {
	var everyone string
	if json.Unmarshal(s["Principal"], &everyone) == nil {
		return everyone == "*"
	}
	principal, ok := s.object("Principal")
	if !ok {
		return false
	}
	return slices.ContainsFunc(jsonStringList(principal["Service"]), func(svc string) bool { return svc != "" })
}

// isPlainServiceTrust is true when every statement is an Allow of assume-role
// to a Service principal and nothing else. A policy that departs from it (a
// Deny, another action, a non-service principal) is outside what the
// confused-deputy check evaluates, so this check takes its statements in.
func isPlainServiceTrust(stmts []iamStatement) bool {
	for _, s := range stmts {
		if s == nil || s.text("Effect") != "Allow" || !grantsAssumeRolePattern(s) {
			return false
		}
		principal, ok := s.object("Principal")
		if !ok || len(principal) != 1 {
			return false
		}
		if _, onlyService := principal["Service"]; !onlyService {
			return false
		}
	}
	return true
}

var awsIAMRoleServiceTrustUnpinnedSource = Check{
	ID:          "aws-iam-role-service-trust-unpinned-source",
	Title:       "IAM role trusts an AWS service without pinning the request source to your account",
	Description: "This role's trust policy lets an AWS service principal assume it, and the conditions on that statement do not pin the request to a literal account: no aws:SourceAccount of 12-digit account IDs, no aws:SourceArn whose account field is literal, and no organisation key (aws:SourceOrgID or aws:SourceOrgPaths). A wildcard such as 1234* or an operator that matches when the key is absent (ForAllValues, IfExists) pins nothing, so another customer's resource can still make the service assume the role. A statement with no condition at all is reported by aws-iam-role-service-confused-deputy instead. A role whose trust uses NotAction is not evaluated.",
	Remediation: "Console: IAM → Roles → the role → Trust relationships → Edit trust policy, and set StringEquals aws:SourceAccount to your 12-digit account ID (add aws:SourceArn with the resource ARN where the service supports it). CLI: `aws iam update-assume-role-policy --role-name NAME --policy-document file://trust-pinned.json`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_role",
	Violates:    unpinnedServiceTrust,
	TableProbes: []string{unpinnedTrustProbe},
}
