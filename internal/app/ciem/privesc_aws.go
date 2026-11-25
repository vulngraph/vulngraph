package ciem

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// AWSPrivescRules returns the full catalog of AWS IAM privilege escalation
// detection rules, drawn from Rhino Security Labs research.
func AWSPrivescRules() []PrivescRule {
	return []PrivescRule{
		{ID: "aws-privesc-01", Technique: TechniqueCreatePolicyVersion, Severity: SeverityCritical,
			Description:     "Create a new policy version with administrator access and set it as default",
			RequiredActions: []string{"iam:CreatePolicyVersion"}},
		{ID: "aws-privesc-02", Technique: TechniqueSetDefaultPolicyVer, Severity: SeverityCritical,
			Description:     "Switch default policy version to a more permissive older version",
			RequiredActions: []string{"iam:SetDefaultPolicyVersion"}},
		{ID: "aws-privesc-03", Technique: TechniqueAttachUserPolicy, Severity: SeverityCritical,
			Description:     "Attach an administrator managed policy to any IAM user",
			RequiredActions: []string{"iam:AttachUserPolicy"}},
		{ID: "aws-privesc-04", Technique: TechniqueAttachRolePolicy, Severity: SeverityCritical,
			Description:     "Attach an administrator managed policy to any IAM role",
			RequiredActions: []string{"iam:AttachRolePolicy"}},
		{ID: "aws-privesc-05", Technique: TechniquePutUserPolicy, Severity: SeverityCritical,
			Description:     "Inject an inline administrator policy on any IAM user",
			RequiredActions: []string{"iam:PutUserPolicy"}},
		{ID: "aws-privesc-06", Technique: TechniquePutRolePolicy, Severity: SeverityCritical,
			Description:     "Inject an inline administrator policy on any IAM role",
			RequiredActions: []string{"iam:PutRolePolicy"}},
		{ID: "aws-privesc-07", Technique: TechniqueCreateLoginProfile, Severity: SeverityHigh,
			Description:     "Create a console login profile for another IAM user to take over their account",
			RequiredActions: []string{"iam:CreateLoginProfile"}},
		{ID: "aws-privesc-08", Technique: TechniqueUpdateLoginProfile, Severity: SeverityHigh,
			Description:     "Change another IAM user's console password to take over their account",
			RequiredActions: []string{"iam:UpdateLoginProfile"}},
		{ID: "aws-privesc-09", Technique: TechniqueCreateAccessKey, Severity: SeverityHigh,
			Description:     "Create programmatic access keys for another IAM user",
			RequiredActions: []string{"iam:CreateAccessKey"}},
		{ID: "aws-privesc-10", Technique: TechniquePassRoleLambda, Severity: SeverityCritical,
			Description:     "Pass a privileged role to a new Lambda function and invoke it for code execution",
			RequiredActions: []string{"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"}},
		{ID: "aws-privesc-11", Technique: TechniquePassRoleEC2, Severity: SeverityCritical,
			Description:     "Launch an EC2 instance with a privileged instance profile for credential theft",
			RequiredActions: []string{"iam:PassRole", "ec2:RunInstances"}},
		{ID: "aws-privesc-12", Technique: TechniquePassRoleGlue, Severity: SeverityHigh,
			Description:     "Create a Glue development endpoint with a privileged role",
			RequiredActions: []string{"iam:PassRole", "glue:CreateDevEndpoint"}},
		{ID: "aws-privesc-13", Technique: TechniquePassRoleCloudFormation, Severity: SeverityHigh,
			Description:     "Create a CloudFormation stack with a privileged service role",
			RequiredActions: []string{"iam:PassRole", "cloudformation:CreateStack"}},
		{ID: "aws-privesc-14", Technique: "iam:PassRole+sagemaker:CreateNotebookInstance", Severity: SeverityHigh,
			Description:     "Create a SageMaker notebook instance with a privileged execution role",
			RequiredActions: []string{"iam:PassRole", "sagemaker:CreateNotebookInstance"}},
		{ID: "aws-privesc-15", Technique: TechniqueSTSAssumeRole, Severity: SeverityMedium,
			Description:     "Assume a role with higher privileges than the current principal",
			RequiredActions: []string{"sts:AssumeRole"}},
		{ID: "aws-privesc-16", Technique: TechniqueUpdateAssumeRolePolicy, Severity: SeverityCritical,
			Description:     "Modify a role's trust policy to allow the attacker to assume it",
			RequiredActions: []string{"iam:UpdateAssumeRolePolicy"}},
		{ID: "aws-privesc-17", Technique: TechniqueLambdaUpdateCode, Severity: SeverityHigh,
			Description:     "Update an existing Lambda function's code for arbitrary code execution",
			RequiredActions: []string{"lambda:UpdateFunctionCode"}},
		{ID: "aws-privesc-18", Technique: "ec2:ModifyInstanceAttribute", Severity: SeverityHigh,
			Description:     "Modify EC2 instance user data to inject commands on restart",
			RequiredActions: []string{"ec2:ModifyInstanceAttribute"}},
		{ID: "aws-privesc-19", Technique: "ssm:SendCommand", Severity: SeverityHigh,
			Description:     "Execute commands on SSM-managed instances using their IAM role",
			RequiredActions: []string{"ssm:SendCommand"}},
		{ID: "aws-privesc-20", Technique: "iam:CreateUser+iam:AttachUserPolicy", Severity: SeverityCritical,
			Description:     "Create a new IAM user and attach administrator policy",
			RequiredActions: []string{"iam:CreateUser", "iam:AttachUserPolicy"}},
		{ID: "aws-privesc-21", Technique: TechniqueAttachGroupPolicy, Severity: SeverityCritical,
			Description:     "Attach an administrator managed policy to any IAM group",
			RequiredActions: []string{"iam:AttachGroupPolicy"}},
		{ID: "aws-privesc-22", Technique: TechniquePutGroupPolicy, Severity: SeverityCritical,
			Description:     "Inject an inline administrator policy on any IAM group",
			RequiredActions: []string{"iam:PutGroupPolicy"}},
		{ID: "aws-privesc-23", Technique: TechniqueAddUserToGroup, Severity: SeverityHigh,
			Description:     "Add self to an administrator group to inherit its permissions",
			RequiredActions: []string{"iam:AddUserToGroup"}},
		{ID: "aws-privesc-24", Technique: "iam:PassRole+ecs:RunTask", Severity: SeverityCritical,
			Description:     "Run an ECS task with a privileged task role for credential theft / code execution",
			RequiredActions: []string{"iam:PassRole", "ecs:RunTask"}},
		{ID: "aws-privesc-25", Technique: "iam:PassRole+ecs:RegisterTaskDefinition+ecs:RunTask", Severity: SeverityCritical,
			Description:     "Register a malicious task definition with a privileged role and run it",
			RequiredActions: []string{"iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"}},
		{ID: "aws-privesc-26", Technique: "iam:PassRole+codebuild:CreateProject+codebuild:StartBuild", Severity: SeverityCritical,
			Description:     "Create a CodeBuild project with a privileged service role and run arbitrary build commands",
			RequiredActions: []string{"iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"}},
		{ID: "aws-privesc-27", Technique: "iam:PassRole+datapipeline:CreatePipeline", Severity: SeverityHigh,
			Description:     "Create a Data Pipeline with a privileged role to run EC2 activities",
			RequiredActions: []string{"iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"}},
		{ID: "aws-privesc-28", Technique: "ssm:StartSession", Severity: SeverityHigh,
			Description:     "Start an SSM session on a managed instance to execute commands with its role",
			RequiredActions: []string{"ssm:StartSession"}},
	}
}

// ssmInstanceTargetingActions are the SSM actions whose resource scope names an
// EC2 INSTANCE, not a principal — the one shape resolveTargetPrincipals cannot
// handle, because that function only resolves scopes that are themselves
// principal ARNs (iam:PassRole, sts:AssumeRole, ...). The identity these
// techniques actually escalate into is the instance's attached IAM role, one
// hop removed from the scope AllowedResourceScopes returns.
var ssmInstanceTargetingActions = map[string]bool{
	"ssm:SendCommand":  true,
	"ssm:StartSession": true,
}

// usesSSMInstanceTargeting reports whether rule requires an SSM action from
// ssmInstanceTargetingActions.
func usesSSMInstanceTargeting(rule PrivescRule) bool {
	for _, action := range rule.RequiredActions {
		if ssmInstanceTargetingActions[action] {
			return true
		}
	}
	return false
}

// ec2InstanceRoleByID maps an EC2 instance's own asset ID (e.g. "i-0abc...",
// never a full ARN — see internal/collect/aws/instances.go) to the IAM role
// ARN attached to it via its instance profile
// (asset.Metadata["iam_role_arn"]). Built once per sweep from the full asset
// roster AnalyzeIAMAssets already has in scope, and consulted only by
// resolveSSMInstanceTargets below.
func ec2InstanceRoleByID(assets []asset.Asset) map[string]string {
	out := map[string]string{}
	for _, a := range assets {
		if a.Type != "ec2_instance" {
			continue
		}
		if role := a.Metadata["iam_role_arn"]; role != "" {
			out[a.ID] = role
		}
	}
	return out
}

// resolveSSMInstanceTargets fills in TargetPrincipals for aws-privesc-19/-28
// (ssm:SendCommand / ssm:StartSession). Their scope is an EC2 instance ARN,
// which resolveTargetPrincipals correctly declines to treat as a principal, so
// without this step TargetPrincipals stays empty and the reach/blast-radius
// BFS (which walks can_escalate_to) has nothing to traverse from the
// escalating principal — the instance's attached IAM role, one hop removed
// from the scope AllowedResourceScopes returns.
//
// Only a CONCRETE instance ARN is resolved (isConcretePrincipalARN's sibling
// rule for instance ARNs) — a scope of "*" or a wildcard instance pattern
// legitimately can't name one instance's role, and matchedResources/
// resolveTargetPrincipals already follow the same conservative rule: an
// unproven target is left unresolved rather than guessed at.
func resolveSSMInstanceTargets(paths []PrivescResult, ec2RoleByID map[string]string) {
	for i := range paths {
		p := &paths[i]
		if !usesSSMInstanceTargeting(p.Rule) || len(p.TargetPrincipals) > 0 {
			continue
		}
		seen := make(map[string]struct{}, len(p.Resources))
		for _, scope := range p.Resources {
			instanceID := ec2InstanceIDFromARN(scope)
			if instanceID == "" {
				continue
			}
			role, ok := ec2RoleByID[instanceID]
			if !ok || role == "" || role == p.SourcePrincipal {
				continue
			}
			if _, dup := seen[role]; dup {
				continue
			}
			seen[role] = struct{}{}
			p.TargetPrincipals = append(p.TargetPrincipals, role)
		}
	}
}

// ec2InstanceIDFromARN extracts the instance ID from a CONCRETE EC2 instance
// ARN ("arn:aws:ec2:<region>:<account>:instance/<id>"). Returns "" for
// anything else — a wildcard pattern, a non-instance ARN, or "*" — mirroring
// isConcretePrincipalARN's refusal to resolve a target it cannot prove.
func ec2InstanceIDFromARN(scope string) string {
	const marker = ":instance/"
	if scope == "" || strings.ContainsAny(scope, "*?") {
		return ""
	}
	_, id, ok := strings.Cut(scope, marker)
	if !ok {
		return ""
	}
	return id
}
