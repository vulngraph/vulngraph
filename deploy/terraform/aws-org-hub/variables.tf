variable "role_name" {
  type    = string
  default = "GraphHub"
}

variable "trust_type" {
  description = "eks-pod-identity, irsa, or principal (an EC2 instance role, or the IAM user whose key an aws_org connector with hub_auth=access_key stores). With principal, set the aws_org connector's hub_role_arn to the hub_role_arn output: Vulngraph then calls sts:AssumeRole on the hub role from the principal's credentials."
  type        = string
  default     = "eks-pod-identity"
  validation {
    condition     = contains(["eks-pod-identity", "irsa", "principal"], var.trust_type)
    error_message = "trust_type must be eks-pod-identity, irsa or principal."
  }
}

variable "oidc_provider_arn" {
  description = "irsa only: the EKS OIDC provider ARN."
  type        = string
  default     = ""
}

variable "oidc_provider_host" {
  description = "irsa only: the provider without https://, e.g. oidc.eks.eu-west-1.amazonaws.com/id/ABC123."
  type        = string
  default     = ""
}

variable "service_account" {
  description = "irsa only: graph's Kubernetes service account subject."
  type        = string
  default     = "system:serviceaccount:graph:graph"
}

variable "pod_namespace" {
  description = "eks-pod-identity only: the namespace graph runs in; sessions from any other namespace are refused."
  type        = string
  default     = "graph"
}

variable "pod_service_account" {
  description = "eks-pod-identity only: graph's ServiceAccount (chart serviceAccount.name); sessions from any other ServiceAccount, the scanner's included, are refused."
  type        = string
  default     = "graph"
}

variable "executor_service_account" {
  description = "eks-pod-identity only: serve's own ServiceAccount (chart serviceAccount.serveName). The hub trusts it too (set it whenever serveName is set, or serve has no cloud identity), and with execution_role_name only it may assume the execution role. Empty: serve shares pod_service_account and every graph pod may."
  type        = string
  default     = ""
}

variable "eks_cluster_arn" {
  description = "eks-pod-identity only, optional: the cluster graph runs in; associations in any other cluster of this account are refused."
  type        = string
  default     = ""
}

variable "trusted_principal_arn" {
  description = "principal only: the IAM role or user ARN allowed to assume the hub role."
  type        = string
  default     = ""
}

variable "management_role_arn" {
  description = "The discovery role in the management or delegated-admin account (module aws-org output)."
  type        = string
}

variable "member_role_name" {
  type    = string
  default = "GraphReadOnly"
}

variable "execution_role_name" {
  description = "Optional Approve & run role name (deploy/aws/graph-execution-role.yaml). Empty grants no execution path."
  type        = string
  default     = ""
}

variable "org_id" {
  description = "Optional organization id; member roles outside it cannot be assumed (aws:ResourceOrgID)."
  type        = string
  default     = ""
}
