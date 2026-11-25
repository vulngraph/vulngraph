variable "hub_role_arn" {
  description = "The hub role graph runs as (module aws-org-hub, or deploy/aws/graph-hub-role.yaml)."
  type        = string
}

variable "external_id" {
  description = "The aws_org connector's external_id (graph's setup screen generates one)."
  type        = string
  sensitive   = true
}

variable "target_ou_ids" {
  description = "OU ids (ou-...), or the root id (r-...) for the whole organization."
  type        = list(string)
}

variable "member_role_name" {
  description = "The member role name; the aws_org connector's member_role_name."
  type        = string
  default     = "GraphReadOnly"
}

variable "discovery_role_name" {
  description = "The discovery role name; its ARN is the connector's management_role_arn."
  type        = string
  default     = "GraphOrgDiscovery"
}

variable "stackset_region" {
  description = "IAM is global; the StackSet needs one region to run its stacks in."
  type        = string
  default     = "us-east-1"
}

variable "org_id" {
  description = "Optional organization id (o-...); also requires the hub to be inside it."
  type        = string
  default     = ""
}

variable "grant_terraform_state_read" {
  description = "Opt-in: grant s3:GetObject on the *tfstate* / *terraform-state* buckets each member account owns (Terraform ownership). Terraform state often holds plaintext secrets, and this grant lets the member role read them."
  type        = bool
  default     = false
}

variable "call_as" {
  description = "SELF in the management account (the module also adds the member role there); DELEGATED_ADMIN in a StackSets delegated administrator (the StackSet covers it; deploy the member role in the management account separately)."
  type        = string
  default     = "SELF"
  validation {
    condition     = contains(["SELF", "DELEGATED_ADMIN"], var.call_as)
    error_message = "call_as must be SELF or DELEGATED_ADMIN."
  }
}
