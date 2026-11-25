# Vulngraph organization onboarding (ADR 091), Terraform form of
# deploy/aws/graph-org-stackset.yaml. Apply with a provider for the
# management account (or a StackSets delegated admin, call_as = "DELEGATED_ADMIN").
#
# Creates: a service-managed StackSet that puts the member role in every
# account of the target OUs (auto-deploying to accounts added later), the same
# role in this account when call_as = "SELF" (StackSets never target the
# management account; with DELEGATED_ADMIN deploy graph-readonly-role.yaml in the
# management account separately), and the discovery role graph assumes to list
# the organization. A customer managed KMS key held in another account also
# needs that key's policy to allow the execution role's kms:CreateGrant.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

locals {
  # The member role template is shared with the CloudFormation path so the two
  # can never grant different permissions.
  member_template = file("${path.module}/../../aws/graph-readonly-role.yaml")
  member_parameters = {
    HubRoleArn              = var.hub_role_arn
    ExternalId              = var.external_id
    RoleName                = var.member_role_name
    OrgId                   = var.org_id
    GrantTerraformStateRead = var.grant_terraform_state_read ? "true" : "false"
  }
}

data "aws_partition" "current" {}

resource "aws_cloudformation_stack_set" "graph_readonly" {
  name             = "graph-readonly"
  description      = "Vulngraph read-only member role in every account of the target OUs."
  permission_model = "SERVICE_MANAGED"
  call_as          = var.call_as
  capabilities     = ["CAPABILITY_NAMED_IAM"]
  template_body    = local.member_template
  parameters       = local.member_parameters

  auto_deployment {
    enabled = true
    # An account leaving the organization loses the role; graph marks it
    # removed and disables its connector, keeping the collected data.
    retain_stacks_on_account_removal = false
  }

  managed_execution {
    active = true
  }

  operation_preferences {
    failure_tolerance_percentage = 10
    max_concurrent_percentage    = 25
    region_concurrency_type      = "PARALLEL"
  }

  lifecycle {
    # AWS manages administration_role_arn for service-managed StackSets.
    ignore_changes = [administration_role_arn]
  }
}

resource "aws_cloudformation_stack_set_instance" "graph_readonly" {
  stack_set_name            = aws_cloudformation_stack_set.graph_readonly.name
  call_as                   = var.call_as
  stack_set_instance_region = var.stackset_region

  deployment_targets {
    organizational_unit_ids = var.target_ou_ids
  }
}

# StackSets never deploy to the management account, so with call_as = "SELF"
# (this provider is the management account) its role is a plain stack. With
# "DELEGATED_ADMIN" this account is a member the StackSet already covers; the
# management account's role is then deployed separately (see
# docs/onboarding-aws-org.md), so every account gets exactly one.
resource "aws_cloudformation_stack" "management_account_readonly" {
  count         = var.call_as == "SELF" ? 1 : 0
  name          = "graph-readonly"
  capabilities  = ["CAPABILITY_NAMED_IAM"]
  template_body = local.member_template
  parameters    = local.member_parameters
}

resource "aws_iam_role" "org_discovery" {
  name                 = var.discovery_role_name
  description          = "Lets graph's hub list the organization's accounts and OUs. Read-only."
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.hub_role_arn }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "sts:ExternalId" = var.external_id } }
    }]
  })
}

resource "aws_iam_role_policy" "org_discovery" {
  name = "graph-org-discovery"
  role = aws_iam_role.org_discovery.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "GraphListOrganization"
      Effect = "Allow"
      Action = [
        "organizations:ListAccounts",
        "organizations:ListAccountsForParent",
        "organizations:ListRoots",
        "organizations:ListOrganizationalUnitsForParent",
      ]
      Resource = "*"
    }]
  })
}
