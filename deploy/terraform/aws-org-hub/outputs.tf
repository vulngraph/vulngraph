output "hub_role_arn" {
  description = "Run graph as this role; pass it as hub_role_arn to the aws-org module. With trust_type = principal, also set it as the aws_org connector's hub_role_arn."
  value       = aws_iam_role.hub.arn
}
