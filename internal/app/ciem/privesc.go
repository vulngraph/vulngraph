package ciem

import (
	"fmt"
	"strings"
)

// AnyPrincipal is the sentinel TargetPrincipal for a cross-principal technique
// whose target is "any principal" rather than one concrete identity (e.g. a
// grant that lets the holder assign roles to anyone). It is NOT a real graph
// node — edge writers must skip it so they don't emit a can_escalate_to edge to
// a nonexistent node that would be dropped at Ladybug insert.
const AnyPrincipal = "(any principal)"

// principalTargetingActions are the actions whose resource scope names another
// principal rather than a service resource. For these, the scopes returned by
// AllowedResourceScopes ARE the identities the technique escalates into, which is
// what turns a detected path into a can_escalate_to graph edge.
//
// Only AWS appears here, and that is a data limitation rather than a choice:
// buildGCPPermissions and buildAzurePermissions (service.go) both synthesise
// EffectivePermission with Resource:"*" because the GCP collector stores a flat
// comma-separated permission list and the Azure collector a flat action union —
// neither carries per-binding resource scope, so there is nothing to resolve a
// target from. GCP/Azure paths therefore keep the AnyPrincipal sentinel until
// their collectors carry scope.
var principalTargetingActions = map[string]bool{
	// Target is a role ARN.
	"iam:AttachRolePolicy":       true,
	"iam:PutRolePolicy":          true,
	"iam:UpdateAssumeRolePolicy": true,
	"iam:PassRole":               true,
	"sts:AssumeRole":             true,
	// Target is a user ARN.
	"iam:AttachUserPolicy":   true,
	"iam:PutUserPolicy":      true,
	"iam:CreateLoginProfile": true,
	"iam:UpdateLoginProfile": true,
	"iam:CreateAccessKey":    true,
	"iam:AddUserToGroup":     true,
	// Target is a group ARN (iam_group maps onto the IamRole node label).
	"iam:AttachGroupPolicy": true,
	"iam:PutGroupPolicy":    true,
}

// resolveTargetPrincipals returns the concrete principals a detected path
// escalates into, taken from the resource scopes of the rule's
// principal-targeting actions. Without a concrete target the edge writer skips
// the sentinel AnyPrincipal and no can_escalate_to edge is produced at all, so
// this is what lets that graph edge exist. The scope data needed is already
// computed for triage by matchedResources; this reads it for the graph too.
//
// A wildcard scope is deliberately NOT resolved: "*" means every principal, which
// is what AnyPrincipal already says, and fabricating an edge per known role from
// it would invent topology the policy does not describe.
func resolveTargetPrincipals(rule PrivescRule, permissions []EffectivePermission) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, action := range rule.RequiredActions {
		if !principalTargetingActions[action] {
			continue
		}
		for _, scope := range AllowedResourceScopes(permissions, action) {
			if !isConcretePrincipalARN(scope) {
				continue
			}
			if _, dup := seen[scope]; dup {
				continue
			}
			seen[scope] = struct{}{}
			out = append(out, scope)
		}
	}
	return out
}

// isConcretePrincipalARN reports whether scope names one specific IAM principal.
// Anything containing a wildcard is rejected: a pattern is not a graph node, and
// a partial pattern ("arn:aws:iam::123:role/prod-*") names a set whose members
// this layer cannot enumerate.
func isConcretePrincipalARN(scope string) bool {
	if scope == "" || strings.ContainsAny(scope, "*?") {
		return false
	}
	if !strings.HasPrefix(scope, "arn:") {
		return false
	}
	// arn:aws:iam::<account>:role/<name> | user/<name> | group/<name>
	i := strings.Index(scope, ":role/")
	if i < 0 {
		i = strings.Index(scope, ":user/")
	}
	if i < 0 {
		i = strings.Index(scope, ":group/")
	}
	if i < 0 {
		return false
	}
	// Reject a bare "…:role/" with no name after it.
	return strings.Contains(scope[i:], "/") && !strings.HasSuffix(scope, "/")
}

// DetectPrivescPaths checks a principal's effective permissions against all
// known privesc rules for its provider and returns exploitable paths found.
// Provider field determines which rule set is evaluated: "aws", "gcp", "azure".
// Empty provider checks all rule sets (defensive fallback).
func DetectPrivescPaths(principal Principal, permissions []EffectivePermission) []PrivescResult {
	if len(permissions) == 0 {
		return nil
	}

	var rules []PrivescRule
	switch principal.Provider {
	case "aws":
		rules = AWSPrivescRules()
	case "gcp":
		rules = GCPPrivescRules()
	case "azure":
		rules = azureRulesInScope(AzurePrivescRules(), permissions)
	default:
		rules = append(AWSPrivescRules(), GCPPrivescRules()...)
		rules = append(rules, azureRulesInScope(AzurePrivescRules(), permissions)...)
	}

	var results []PrivescResult
	for _, rule := range rules {
		if principalHasAllActions(permissions, rule.RequiredActions) {
			result := PrivescResult{
				Rule:            rule,
				SourcePrincipal: principal.ARN,
				Steps:           buildSteps(rule, principal),
				Resources:       matchedResources(permissions, rule.RequiredActions),
			}
			// Concrete targets are what the graph can hold. Resolve them for every
			// rule, not only cross-principal ones: aws-privesc-13 (PassRole +
			// CreateStack) escalates into the passed role even though the technique
			// is not "act on another principal" in the isCrossPrincipalTechnique
			// sense. The sentinel stays for grants that genuinely name no target.
			result.TargetPrincipals = resolveTargetPrincipals(rule, permissions)
			if len(result.TargetPrincipals) == 0 && isCrossPrincipalTechnique(rule.ID) {
				result.TargetPrincipal = AnyPrincipal
			}
			results = append(results, result)
		}
	}
	return results
}

// matchedResources returns the distinct resource scopes on which the rule's
// required actions were granted, preserving first-seen order. It does NOT affect
// whether the rule fires — it only surfaces scope so downstream triage can tell
// a wildcard grant from one narrowed to a benign resource.
func matchedResources(permissions []EffectivePermission, requiredActions []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, required := range requiredActions {
		for _, scope := range AllowedResourceScopes(permissions, required) {
			if _, dup := seen[scope]; dup {
				continue
			}
			seen[scope] = struct{}{}
			out = append(out, scope)
		}
	}
	return out
}

// principalHasAllActions reports whether every required action is effectively
// available on at least one resource scope. Scopes are evaluated per action
// against that action's own resources and deliberately NOT folded across
// actions: a technique's required actions target different resource types
// (iam:PassRole names a role ARN, ec2:RunInstances an instance/"*"), so
// intersecting their scopes would be a category error. Narrow scope is surfaced
// via matchedResources for triage and scoring rather than gating the match — a
// PassRole confined to one role is still a real PassRole path, just a smaller one.
func principalHasAllActions(permissions []EffectivePermission, requiredActions []string) bool {
	for _, required := range requiredActions {
		if len(AllowedResourceScopes(permissions, required)) == 0 {
			return false
		}
	}
	return true
}

func isCrossPrincipalTechnique(ruleID string) bool {
	switch ruleID {
	case "aws-privesc-03", "aws-privesc-04", "aws-privesc-05", "aws-privesc-06",
		"aws-privesc-07", "aws-privesc-08", "aws-privesc-09", "aws-privesc-16", "aws-privesc-20",
		"gcp-privesc-01", "gcp-privesc-03", "gcp-privesc-04", "gcp-privesc-05",
		"gcp-privesc-10", "gcp-privesc-14", "gcp-privesc-15", "gcp-privesc-16",
		"azure-privesc-01", "azure-privesc-02", "azure-privesc-08", "azure-privesc-09",
		"azure-privesc-10", "azure-privesc-12", "azure-privesc-13", "azure-privesc-14",
		"azure-privesc-15", "azure-privesc-18":
		return true
	}
	return false
}

func buildSteps(rule PrivescRule, principal Principal) []string {
	name := principal.Name
	if name == "" {
		name = principal.ARN
	}
	steps := []string{
		fmt.Sprintf("Principal %q has the required permissions: %v", name, rule.RequiredActions),
	}

	// Per-rule human-readable attack chains sourced from Rhino Security Labs research.
	switch rule.ID {
	case "aws-privesc-01":
		steps = append(steps, "Create a new policy version with administrator access", "Set the new version as the default policy version", "Principal now has full administrator privileges")
	case "aws-privesc-02":
		steps = append(steps, "List existing policy versions to find a permissive one", "Set the permissive version as the default", "Principal gains the permissions from the older version")
	case "aws-privesc-03":
		steps = append(steps, "Attach an AWS managed administrator policy to a target user", "Target user now has full administrator access")
	case "aws-privesc-04":
		steps = append(steps, "Attach an AWS managed administrator policy to a target role", "Assume the role to gain administrator access")
	case "aws-privesc-05":
		steps = append(steps, "Create an inline policy with full admin access on a target user", "Target user gains administrator privileges")
	case "aws-privesc-06":
		steps = append(steps, "Create an inline policy with full admin access on a target role", "Assume the role to gain administrator access")
	case "aws-privesc-07":
		steps = append(steps, "Create a console login profile for a target IAM user", "Log in as the target user via AWS Console")
	case "aws-privesc-08":
		steps = append(steps, "Change the console password of a target IAM user", "Log in as the target user with the new password")
	case "aws-privesc-09":
		steps = append(steps, "Create a new access key pair for a target IAM user", "Use the new credentials to act as the target user")
	case "aws-privesc-10":
		steps = append(steps, "Create a Lambda function with a high-privilege execution role", "Pass the privileged role to the Lambda function", "Invoke the function to execute code with the role's permissions")
	case "aws-privesc-11":
		steps = append(steps, "Launch an EC2 instance with a privileged instance profile", "SSH or SSM into the instance", "Use the instance metadata service to obtain role credentials")
	case "aws-privesc-12":
		steps = append(steps, "Create a Glue development endpoint with a privileged role", "Connect to the endpoint and use the role's credentials")
	case "aws-privesc-13":
		steps = append(steps, "Create a CloudFormation stack with a privileged service role", "The stack's resources execute with the role's permissions")
	case "aws-privesc-14":
		steps = append(steps, "Create a SageMaker notebook with a privileged execution role", "Open the notebook and access the role's credentials via metadata")
	case "aws-privesc-15":
		steps = append(steps, "Assume a role with higher privileges than the current principal", "Operate with the target role's permissions")
	case "aws-privesc-16":
		steps = append(steps, "Modify a role's trust policy to allow the attacker to assume it", "Assume the role to gain its permissions")
	case "aws-privesc-17":
		steps = append(steps, "Update an existing Lambda function's code with a malicious payload", "The function executes with its assigned role's permissions")
	case "aws-privesc-18":
		steps = append(steps, "Modify an EC2 instance's user data to inject commands", "Commands execute on next instance restart with instance role permissions")
	case "aws-privesc-19":
		steps = append(steps, "Send commands to SSM-managed instances", "Commands execute with the instance's IAM role permissions")
	case "aws-privesc-20":
		steps = append(steps, "Create a new IAM user", "Attach an administrator policy to the new user", "Use the new user's credentials for full account access")
	case "gcp-privesc-01":
		steps = append(steps, "Call setIamPolicy on the GCP project or organization", "Grant the attacker's identity the roles/owner binding", "Principal now has full Owner access to the project")
	case "gcp-privesc-02":
		steps = append(steps, "Identify a service account with privileged roles", "Launch a Compute instance with that service account attached", "Access the metadata server (169.254.169.254) to obtain the SA's access token")
	case "gcp-privesc-03":
		steps = append(steps, "Call generateAccessToken on a target service account", "Receive a short-lived OAuth2 access token for the target SA", "Use the token to operate as the service account")
	case "gcp-privesc-04":
		steps = append(steps, "SA-A can impersonate SA-B, and SA-B can impersonate SA-C", "Request a token for SA-C via implicit delegation through the chain", "Operate as the final service account in the delegation chain")
	case "gcp-privesc-05":
		steps = append(steps, "Create a user-managed key for a target service account", "Download the JSON key file", "Authenticate as the service account indefinitely using the key")
	case "gcp-privesc-06":
		steps = append(steps, "Create a Cloud Function with a privileged service account", "Deploy code that uses the SA's credentials from the metadata server", "Invoke the function to execute with the SA's permissions")
	case "gcp-privesc-07":
		steps = append(steps, "Deploy a Cloud Run service with a privileged service account", "The container code accesses the SA's credentials via the metadata server", "Send requests to the service to execute with the SA's permissions")
	case "gcp-privesc-08":
		steps = append(steps, "Set instance metadata to inject SSH keys or a startup script", "SSH into the instance or wait for restart to trigger the startup script", "Execute code with the instance's service account permissions")
	case "gcp-privesc-09":
		steps = append(steps, "Set project-wide SSH keys via setCommonInstanceMetadata", "SSH into any instance in the project that does not block project SSH keys", "Gain access to all service accounts attached to those instances")
	case "gcp-privesc-10":
		steps = append(steps, "Update a custom IAM role to add additional permissions", "All principals bound to the role gain the new permissions")
	case "gcp-privesc-11":
		steps = append(steps, "Disable or modify organization policy constraints", "Bypass security controls such as domain restrictions or resource location constraints")
	case "gcp-privesc-12":
		steps = append(steps, "Create a Deployment Manager deployment", "The deployment executes as the project's Google APIs service account", "Resources created in the deployment operate with elevated permissions")
	case "gcp-privesc-13":
		steps = append(steps, "Modify a Cloud Storage bucket's IAM policy", "Grant self objectViewer or objectAdmin role on the bucket", "Access or exfiltrate bucket contents")
	case "gcp-privesc-14":
		steps = append(steps, "Call signBlob as a target service account", "Forge authentication tokens (JWTs) signed by the SA's private key", "Authenticate as the service account to any GCP service")
	case "gcp-privesc-15":
		steps = append(steps, "Change the service account attached to a Compute instance", "SSH into the instance and access the new SA's credentials via the metadata server", "Operate with the new service account's permissions")
	case "gcp-privesc-16":
		steps = append(steps, "Update an existing Cloud Function's source code with a malicious payload", "The function executes with its assigned service account's permissions", "Invoke the function to exfiltrate data or escalate further")
	case "gcp-privesc-17":
		steps = append(steps, "Update GKE cluster configuration (e.g., enable legacy ABAC or modify node pools)", "Retrieve cluster admin credentials via getCredentials", "Full Kubernetes control plane access — deploy privileged pods, access secrets")
	case "gcp-privesc-18":
		steps = append(steps, "Create an HMAC key for a service account on Cloud Storage", "Use the HMAC key for persistent S3-compatible access to buckets")
	case "azure-privesc-01":
		steps = append(steps, "Create a role assignment granting Owner or Contributor at subscription scope", "The target principal now has full control over all resources in the subscription")
	case "azure-privesc-02":
		steps = append(steps, "Create a custom role definition with wildcard (*) actions", "Assign the custom role to self or a controlled principal", "Operate with unrestricted permissions within the role's scope")
	case "azure-privesc-03":
		steps = append(steps, "Execute commands on a VM via Run Command", "The commands run with the VM's system-assigned managed identity", "Use the managed identity token from IMDS to access Azure resources")
	case "azure-privesc-04":
		steps = append(steps, "Install a Custom Script Extension on a target VM", "The script executes with SYSTEM privileges and can access the managed identity", "Use the identity token to operate with the VM's Azure permissions")
	case "azure-privesc-05":
		steps = append(steps, "Modify Key Vault access policies to grant self Get/List on secrets, keys, certificates", "Access stored secrets, encryption keys, and certificates")
	case "azure-privesc-06":
		steps = append(steps, "Assign a user-assigned managed identity with elevated roles to a VM", "Run code on the VM to request tokens for the managed identity", "Use the tokens to operate with the identity's Azure RBAC permissions")
	case "azure-privesc-07":
		steps = append(steps, "Deploy an ARM template that creates resources (VMs, functions) with elevated permissions", "The deployment runs with the deployer's permissions and creates new attack surfaces")
	case "azure-privesc-08":
		steps = append(steps, "Create or modify an Entra ID application registration", "Grant the application admin-consented API permissions (e.g., Directory.ReadWrite.All)", "Use the application's service principal to act with those permissions")
	case "azure-privesc-09":
		steps = append(steps, "Grant application roles (app-only permissions) to a service principal", "The service principal can now call Microsoft Graph or other APIs with elevated permissions")
	case "azure-privesc-10":
		steps = append(steps, "Assign an Entra ID directory role (Global Administrator, Privileged Role Administrator)", "The target principal inherits all permissions of the directory role")
	case "azure-privesc-11":
		steps = append(steps, "Add self or a controlled principal to a privileged security group", "Inherit all role assignments and permissions assigned to the group")
	case "azure-privesc-12":
		steps = append(steps, "Add a client secret or certificate credential to an existing application", "Authenticate as the application's service principal using the new credential", "Operate with all API permissions granted to the application")
	case "azure-privesc-13":
		steps = append(steps, "Create delegated permission grants (OAuth2PermissionGrant) on behalf of all users", "Any user who authenticates is now implicitly consenting to the attacker's scopes")
	case "azure-privesc-14":
		steps = append(steps, "Create a new Entra ID user", "Assign the user a privileged directory role (e.g., Global Administrator)", "Sign in as the new user with full tenant admin access")
	case "azure-privesc-15":
		steps = append(steps, "Principal holds Owner role at subscription scope", "Full read/write/delete access to every resource in the subscription", "Can assign roles, modify policies, and access all data planes")
	case "azure-privesc-16":
		steps = append(steps, "Call listClusterAdminCredential on an AKS managed cluster", "Obtain kubeconfig with cluster-admin privileges", "Full Kubernetes control plane access — deploy pods, read secrets, modify RBAC")
	case "azure-privesc-17":
		steps = append(steps, "Call listKeys on a storage account", "Obtain the primary and secondary access keys", "Full data-plane access to blobs, queues, tables, and files in the account")
	case "azure-privesc-18":
		steps = append(steps, "Set self as an Azure SQL Server administrator", "Gain full access to all databases on the server", "Read, modify, or exfiltrate any data stored in the SQL databases")
	case "azure-privesc-19":
		steps = append(steps, "Delete resource locks (CanNotDelete or ReadOnly) on protected resources", "Resources become eligible for modification or deletion")
	case "azure-privesc-20":
		steps = append(steps, "Retrieve App Service publish profile XML containing deployment credentials", "Deploy arbitrary code to the App Service using the publish credentials", "Code executes with the App Service's managed identity permissions")
	default:
		steps = append(steps, rule.Description)
	}
	return steps
}
