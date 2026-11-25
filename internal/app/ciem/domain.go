// Package ciem provides CIEM (Cloud Infrastructure Entitlement Management)
// types and privilege escalation detection across AWS, GCP, and Azure.
// Detection does no storage or network I/O; AnalyzeIAMAssets logs via pkg/log.
// Callers own writes: AnalyzeIAMAssets returns scored assets, privesc paths,
// findings and privilege tiers, and the sync job persists them.
package ciem

import "time"

// Principal types.
const (
	PrincipalUser           = "user"
	PrincipalRole           = "role"
	PrincipalGroup          = "group"
	PrincipalServiceAccount = "service_account"
)

// AWS privilege escalation techniques, keyed by the IAM action they abuse.
const (
	TechniqueCreatePolicyVersion    = "iam:CreatePolicyVersion"
	TechniqueSetDefaultPolicyVer    = "iam:SetDefaultPolicyVersion"
	TechniqueAttachUserPolicy       = "iam:AttachUserPolicy"
	TechniqueAttachGroupPolicy      = "iam:AttachGroupPolicy"
	TechniqueAttachRolePolicy       = "iam:AttachRolePolicy"
	TechniquePutUserPolicy          = "iam:PutUserPolicy"
	TechniquePutGroupPolicy         = "iam:PutGroupPolicy"
	TechniquePutRolePolicy          = "iam:PutRolePolicy"
	TechniquePassRoleLambda         = "iam:PassRole+lambda:CreateFunction"
	TechniquePassRoleEC2            = "iam:PassRole+ec2:RunInstances"
	TechniquePassRoleCloudFormation = "iam:PassRole+cloudformation:CreateStack"
	TechniquePassRoleGlue           = "iam:PassRole+glue:CreateDevEndpoint"
	TechniqueCreateAccessKey        = "iam:CreateAccessKey"
	TechniqueCreateLoginProfile     = "iam:CreateLoginProfile"
	TechniqueUpdateLoginProfile     = "iam:UpdateLoginProfile"
	TechniqueUpdateAssumeRolePolicy = "iam:UpdateAssumeRolePolicy"
	TechniqueSTSAssumeRole          = "sts:AssumeRole"
	TechniqueAddUserToGroup         = "iam:AddUserToGroup"
	TechniqueLambdaUpdateCode       = "lambda:UpdateFunctionCode"
)

// GCP privilege escalation techniques.
const (
	TechniqueGCPSetIAMPolicy        = "resourcemanager.projects.setIamPolicy"
	TechniqueGCPActAsCreateInstance = "iam.serviceAccounts.actAs+compute.instances.create"
	TechniqueGCPGetAccessToken      = "iam.serviceAccounts.getAccessToken"
	TechniqueGCPImplicitDelegation  = "iam.serviceAccounts.implicitDelegation"
	TechniqueGCPCreateSAKey         = "iam.serviceAccountKeys.create"
	TechniqueGCPActAsCloudFunction  = "iam.serviceAccounts.actAs+cloudfunctions.functions.create"
	TechniqueGCPActAsCloudRun       = "iam.serviceAccounts.actAs+run.services.create"
	TechniqueGCPSetMetadata         = "compute.instances.setMetadata"
	TechniqueGCPSetCommonMetadata   = "compute.projects.setCommonInstanceMetadata"
	TechniqueGCPUpdateRole          = "iam.roles.update"
	TechniqueGCPSetOrgPolicy        = "orgpolicy.policy.set"
	TechniqueGCPDeploymentManager   = "deploymentmanager.deployments.create"
	TechniqueGCPBucketSetIAMPolicy  = "storage.buckets.setIamPolicy"
	TechniqueGCPSignBlob            = "iam.serviceAccounts.signBlob"
	TechniqueGCPSetServiceAccount   = "compute.instances.setServiceAccount+iam.serviceAccounts.actAs"
	TechniqueGCPUpdateCloudFunction = "iam.serviceAccounts.actAs+cloudfunctions.functions.update"
	TechniqueGCPGKETakeover         = "container.clusters.update+container.clusters.getCredentials"
	TechniqueGCPHMACKeyCreate       = "storage.hmacKeys.create"
)

// Azure / Entra ID privilege escalation techniques.
const (
	TechniqueAzureRoleAssignmentWrite    = "Microsoft.Authorization/roleAssignments/write"
	TechniqueAzureRoleDefinitionWrite    = "Microsoft.Authorization/roleDefinitions/write"
	TechniqueAzureVMRunCommand           = "Microsoft.Compute/virtualMachines/runCommand/action"
	TechniqueAzureVMExtensionWrite       = "Microsoft.Compute/virtualMachines/extensions/write"
	TechniqueAzureKeyVaultAccessPolicy   = "Microsoft.KeyVault/vaults/accessPolicies/write"
	TechniqueAzureUserAssignedIdentity   = "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action+Microsoft.Compute/virtualMachines/write"
	TechniqueAzureARMDeployment          = "Microsoft.Resources/deployments/write"
	TechniqueAzureAppReadWriteAll        = "Application.ReadWrite.All"
	TechniqueAzureAppRoleAssignment      = "AppRoleAssignment.ReadWrite.All"
	TechniqueAzureDirectoryRoleWrite     = "RoleManagement.ReadWrite.Directory"
	TechniqueAzureGroupMemberWrite       = "GroupMember.ReadWrite.All"
	TechniqueAzureServicePrincipalSecret = "Application.ReadWrite.All+ServicePrincipalEndpoint.ReadWrite.All"
	TechniqueAzureOAuthGrant             = "DelegatedPermissionGrant.ReadWrite.All"
	TechniqueAzureUserWriteRoleAssign    = "User.ReadWrite.All+RoleManagement.ReadWrite.Directory"
	TechniqueAzureOwnerSubscription      = "Owner@subscription"
	TechniqueAzureAKSAdminCreds          = "Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action"
	TechniqueAzureStorageListKeys        = "Microsoft.Storage/storageAccounts/listKeys/action"
	TechniqueAzureSQLAdminWrite          = "Microsoft.Sql/servers/administrators/write"
	TechniqueAzureLockDelete             = "Microsoft.Authorization/locks/delete"
	TechniqueAzureAppServicePublish      = "Microsoft.Web/sites/publishxml/action"
)

// Privesc severity levels.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// Policy types.
const (
	PolicyIdentity = "identity"
	PolicyResource = "resource"
	PolicyBoundary = "boundary"
	PolicySCP      = "scp"
	// PolicyTrust carries an IAM role's trust policy (AssumeRolePolicyDocument) —
	// who may assume THIS role, not what THIS role may do. Its Allow statements
	// describe the assuming principal's grant, never the role's own effective
	// permissions, so EvaluateEffectivePermissions excludes it from
	// identityAllows: every role has a mandatory trust statement granting
	// *someone* sts:AssumeRole, and folding it in would make that read as a
	// self-granted permission on every role.
	PolicyTrust = "trust"
	// PolicyAzureNotActions carries an Azure role's NotActions (a comma-separated
	// action-pattern list) so buildAzurePermissions can emit them as Deny-effect
	// permissions. Azure RBAC is "Actions minus NotActions"; a permission is only
	// effective if some Action matches AND no NotAction matches — set subtraction
	// over wildcards (the AWS model) cannot express this, so Azure is evaluated
	// per-required-action with a deny-aware matcher instead.
	//
	// Fallback form: it flattens every role assignment of a principal into one
	// pair, which lets one role's NotActions mask another role's grant.
	// PolicyAzureRoleGrants is preferred; this is read only when a principal has
	// no parseable role_grants.
	PolicyAzureNotActions = "azure_not_actions"
	// PolicyAzureRoleGrants carries a principal's role assignments individually, as
	// a JSON array of AzureRoleGrant (asset Metadata["role_grants"]). Each becomes
	// its own EffectivePermission.Grant so Azure's per-assignment evaluation is
	// modelled faithfully.
	PolicyAzureRoleGrants = "azure_role_grants"
)

// Effect values on an EffectivePermission.
const (
	EffectAllow = "Allow"
	EffectDeny  = "Deny"
)

// PrivescRule defines one privilege escalation detection rule: the set of IAM
// actions that, if all present, constitute an exploitable path.
type PrivescRule struct {
	ID              string
	Technique       string
	Description     string
	Severity        string
	RequiredActions []string // ALL must be present
}

// PrivescResult captures a detected privilege escalation path for a principal.
type PrivescResult struct {
	Rule            PrivescRule
	SourcePrincipal string
	TargetPrincipal string // empty = self-escalation, AnyPrincipal = unbounded
	// TargetPrincipals are the concrete identities this path escalates into,
	// resolved from the resource scopes of the rule's principal-targeting actions
	// (see resolveTargetPrincipals). These are real asset IDs, so they are what
	// the can_escalate_to graph edge is built from; TargetPrincipal's AnyPrincipal
	// sentinel is not a node and is only set when no concrete target could be
	// resolved. AWS-only today — GCP/Azure effective permissions carry no
	// resource scope to resolve a target from.
	TargetPrincipals []string
	Steps            []string // human-readable attack chain
	// Resources lists the distinct resource scopes the rule's required actions
	// were actually granted on. Detection is action-only (a permission scoped to
	// a single benign resource still fires), so this lets the reasoner/operator
	// weigh scope — e.g. iam:PassRole on one benign role vs "*". Resource-aware
	// *detection* (suppressing benign scopes without risking false negatives on a
	// scoped-but-admin target) is deferred to a dedicated design decision.
	Resources []string
}

// Principal represents an IAM identity (user, role, or service account).
type Principal struct {
	ID        string
	Type      string
	Name      string
	ARN       string
	Provider  string
	AccountID string
	CreatedAt time.Time
	Policies  []Policy
}

// Policy is an IAM policy document attached to a principal.
type Policy struct {
	ID        string
	Name      string
	Type      string // identity, resource, boundary, scp
	Document  string // raw JSON
	IsManaged bool
	// Incomplete records an observed unreadable policy or restriction. An
	// empty Document with this flag is missing evidence, not an empty policy.
	Incomplete bool
	// SCPLevel is a positively identified organization attachment level. Its
	// policies are unioned within the level, then intersected with other levels.
	SCPLevel *SCPLevel
}

// SCPPolicyDocument is an observed policy attached at one organization level.
type SCPPolicyDocument struct {
	Name       string `json:"name"`
	Document   string `json:"document"`
	Incomplete bool   `json:"incomplete,omitempty"`
}

// SCPLevel preserves even a completely read level with zero attached policies.
type SCPLevel struct {
	TargetID string              `json:"target_id"`
	ParentID string              `json:"parent_id,omitempty"`
	Policies []SCPPolicyDocument `json:"policies"`
	Complete bool                `json:"complete"`
}

// AWSOrganizationEvidence carries provider observations establishing whether
// SCPs apply and the attachment chain that was actually read.
type AWSOrganizationEvidence struct {
	ObservedAt          time.Time  `json:"observed_at"`
	AccountID           string     `json:"account_id"`
	ManagementAccountID string     `json:"management_account_id,omitempty"`
	RootID              string     `json:"root_id,omitempty"`
	RootSCPStatus       string     `json:"root_scp_status,omitempty"`
	Applicability       string     `json:"applicability"`    // member | exempt | unknown
	Reason              string     `json:"reason,omitempty"` // management | standalone | disabled
	Complete            bool       `json:"complete"`
	Levels              []SCPLevel `json:"levels,omitempty"`
}

// PermissionStatement is one statement in a parsed IAM policy document.
type PermissionStatement struct {
	Effect       string
	Actions      []string
	NotActions   []string
	Resources    []string
	NotResources []string
	Conditions   map[string]map[string][]string
}
