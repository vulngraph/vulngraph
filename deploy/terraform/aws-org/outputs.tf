output "management_role_arn" {
  description = "The aws_org connector's management_role_arn."
  value       = aws_iam_role.org_discovery.arn
}

output "member_role_name" {
  description = "The aws_org connector's member_role_name."
  value       = var.member_role_name
}
