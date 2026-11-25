# Vulngraph hub role (ADR 091), Terraform form of deploy/aws/graph-hub-role.yaml.
# Apply in the account graph runs in. The role can only assume the discovery
# role and graph's member (and optional execution) roles; it holds no read or
# write permission on any resource itself.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

data "aws_partition" "current" {}

data "aws_caller_identity" "current" {}

locals {
  trust = {
    "eks-pod-identity" = {
      Effect    = "Allow"
      Principal = { Service = "pods.eks.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession"]
      # Only pod identity associations of clusters in this account, and only
      # for graph's own namespace and ServiceAccount(s): an association made for
      # any other ServiceAccount (the scanner's, or a workload outside graph)
      # cannot obtain the hub. EKS Pod Identity sets these session tags itself.
      Condition = { StringEquals = merge({
        "aws:SourceAccount"                         = data.aws_caller_identity.current.account_id
        "aws:RequestTag/kubernetes-namespace"       = var.pod_namespace
        "aws:RequestTag/kubernetes-service-account" = local.serve_trusted ? [var.pod_service_account, var.executor_service_account] : [var.pod_service_account]
      }, var.eks_cluster_arn == "" ? {} : { "aws:RequestTag/eks-cluster-arn" = var.eks_cluster_arn }) }
    }
    irsa = {
      Effect    = "Allow"
      Principal = { Federated = var.oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${var.oidc_provider_host}:sub" = var.service_account
          "${var.oidc_provider_host}:aud" = "sts.amazonaws.com"
        }
      }
    }
    principal = {
      Effect    = "Allow"
      Principal = { AWS = var.trusted_principal_arn }
      Action    = "sts:AssumeRole"
    }
  }
  serve_trusted   = var.trust_type == "eks-pod-identity" && var.executor_service_account != ""
  executor_pinned = local.serve_trusted && var.execution_role_name != ""
  execution_condition = merge(
    var.org_id == "" ? {} : { "aws:ResourceOrgID" = var.org_id },
    local.executor_pinned ? { "aws:PrincipalTag/kubernetes-service-account" = var.executor_service_account } : {},
  )
  # The Approve & run path is its own statement so it can be held to serve's
  # ServiceAccount (executor_service_account): the worker and the scanner
  # cannot present that session tag.
  execution_statements = var.execution_role_name == "" ? [] : [merge({
    Sid      = "GraphAssumeExecutionRoles"
    Effect   = "Allow"
    Action   = "sts:AssumeRole"
    Resource = "arn:${data.aws_partition.current.partition}:iam::*:role/${var.execution_role_name}"
    }, length(local.execution_condition) == 0 ? {} : {
    Condition = { StringEquals = local.execution_condition }
  })]
}

resource "aws_iam_role" "hub" {
  name                 = var.role_name
  description          = "Vulngraph hub identity. Can only assume Vulngraph's discovery and member roles, and the execution role when execution_role_name is set."
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [local.trust[var.trust_type]]
  })
}

resource "aws_iam_role_policy" "hub" {
  name = "graph-hub-assume"
  role = aws_iam_role.hub.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid      = "GraphAssumeOrgDiscovery"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = var.management_role_arn
      },
      merge({
        Sid      = "GraphAssumeMemberRoles"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "arn:${data.aws_partition.current.partition}:iam::*:role/${var.member_role_name}"
        }, var.org_id == "" ? {} : {
        Condition = { StringEquals = { "aws:ResourceOrgID" = var.org_id } }
      }),
    ], local.execution_statements)
  })
}
