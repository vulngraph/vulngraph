package enrich

import (
	"context"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

const sourcePrincipalClass = "principal_class"

// PrincipalClass applies human-user and non-production naming hints to IAM
// escalation findings. Familiar managed/deployment role names are neutral:
// names cannot establish benign intent, effective controls, or absence of risk.
// InternetReach separately scores observed paths without a name-based hard cap.
type PrincipalClass struct{}

func (PrincipalClass) Name() string { return sourcePrincipalClass }

func (PrincipalClass) Evaluate(_ context.Context, f finding.Finding) (Factor, bool, error) {
	if !isPrivesc(f) {
		return Factor{}, false, nil
	}
	switch classifyPrincipal(f.ResourceID) {
	case principalExpectedRole:
		return Factor{}, false, nil
	case principalHumanUser:
		return Factor{
			Source: sourcePrincipalClass,
			Points: 15,
			Floor:  ThresholdHigh,
			Detail: "human user with self-escalation capability",
		}, true, nil
	case principalNonProd:
		return Factor{
			Source: sourcePrincipalClass,
			Points: -10,
			Detail: "non-production principal (test/staging)",
		}, true, nil
	default:
		return Factor{}, false, nil
	}
}

// isPrivesc reports whether a finding is a genuine IAM/CIEM privilege-escalation
// finding, identified by provenance (check_id), not free text. Every CIEM privesc
// technique lands with a check_id of the form aws-privesc-NN / gcp-privesc-NN /
// azure-privesc-NN (internal/app/ciem privesc_*.go), so a "privesc" check_id
// substring is the exact, evidence-backed predicate.
//
// Not a Title-contains-"privilege escalation" match: that would sweep in the k8s
// pod-misconfig check k8s-container-allow-privilege-escalation ("Container allows
// privilege escalation") plus CVE titles mentioning privilege escalation,
// routing them through the IAM-privesc machinery (PrincipalClass, the must-fix
// exploitable branch) built for IAM escalation paths those findings never have.
// k8s findings instead get a real reachability-grounded signal
// (IsNetworkReachableResource gate) rather than a title accident.
func isPrivesc(f finding.Finding) bool {
	return strings.Contains(strings.ToLower(f.CheckID), "privesc")
}

type principalClass int

const (
	principalUnknown principalClass = iota
	principalExpectedRole
	principalHumanUser
	principalNonProd
)

// expectedRolePatterns are case-insensitive substrings that mark a principal as
// commonly managed or used for deployment. They carry no scoring weight.
// Derived from common naming conventions
// (AWS-managed access roles, SSO permission sets, service-linked roles, IaC/CI
// deploy roles, and workload execution roles).
var expectedRolePatterns = []string{
	// ── AWS ─────────────────────────────────────────────────────────────────
	// NB: SSO permission-set roles (AWSReservedSSO_*) are deliberately NOT here.
	// The SSO graph owns that call via IdentityHygiene's SSOResolver:
	// an SSO permission set that grants admin is a real admin path and must NOT be
	// blanket-suppressed by name. Non-admin SSO roles still demote via their SAML
	// federated_trust metadata in IdentityHygiene.
	"organizationaccountaccessrole",
	"aws-service-role", // service-linked roles
	"service-role/",
	"cdk-",     // CDK bootstrap/deploy roles
	"stackset", // CloudFormation StackSet exec roles
	"stacksets-exec",
	"-exec-role",     // generic execution roles
	"executionrole",  // LambdaExecutionRole, etc.
	"github-actions", // CI deploy roles
	"terraformdeployer",
	"-ecs-role", // ECS task/exec roles
	"-ecs-task",
	"spot-fleet-tagging-role",
	"quicksetup", // AWS QuickSetup managed roles
	// ── GCP ─────────────────────────────────────────────────────────────────
	// App Engine default service-account naming pattern. Its actual grants
	// remain subject to the same escalation checks as any other principal.
	"@appspot.gserviceaccount.com",
	// Terraform / IaC deploy service accounts
	"terraform-deployer@",
	"terraform-deployment-manager@",
	"deployment-manager@",
	// GCP default compute SA: <project-number>-compute@developer.gserviceaccount.com
	// These are auto-created and should not be acting as user principals.
	"-compute@developer.gserviceaccount.com",
}

// nonProdPrefixes mark a principal as belonging to a non-production environment.
// For GCP service accounts the full email is checked for non-prod project
// suffixes (e.g. deployer@example-project-dev.iam.gserviceaccount.com).
var nonProdPrefixes = []string{"tst-", "stg-", "test-", "staging-", "dev-", "qa-"}

// nonProdSubstrings extends non-prod detection to GCP SA emails where the
// project name (not the SA name) carries the environment suffix.
var nonProdSubstrings = []string{"-tst.", "-stg.", "-test.", "-staging.", "-dev.", "-qa."}

// classifyPrincipal buckets an IAM principal resource id (ARN or GCP SA email)
// for scoring. Handles both AWS ARN format (arn:aws:iam::NNN:user/X) and GCP
// service account format (serviceAccount:name@project.iam.gserviceaccount.com).
func classifyPrincipal(resourceID string) principalClass {
	lower := strings.ToLower(resourceID)
	// AWS: human user is an IAM user with an email-style name.
	if strings.Contains(lower, ":user/") && strings.Contains(resourceID, "@") {
		return principalHumanUser
	}
	for _, p := range expectedRolePatterns {
		if strings.Contains(lower, p) {
			return principalExpectedRole
		}
	}
	// Non-prod detection: check both the name prefix (AWS) and substrings in
	// the full resource ID (GCP SA emails like name@example-project-dev.iam...).
	name := roleName(resourceID)
	for _, p := range nonProdPrefixes {
		if strings.HasPrefix(name, p) {
			return principalNonProd
		}
	}
	for _, s := range nonProdSubstrings {
		if strings.Contains(lower, s) {
			return principalNonProd
		}
	}
	return principalUnknown
}

// roleName returns the lowercased trailing name segment of a role/user ARN.
func roleName(resourceID string) string {
	lower := strings.ToLower(resourceID)
	for _, sep := range []string{":role/", ":user/"} {
		if i := strings.LastIndex(lower, sep); i >= 0 {
			seg := lower[i+len(sep):]
			// Take the final path component (roles can be pathed).
			if j := strings.LastIndex(seg, "/"); j >= 0 {
				seg = seg[j+1:]
			}
			return seg
		}
	}
	return lower
}
