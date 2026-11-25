package iac

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// ruleIDs returns the set of rule IDs present in the issues.
func ruleIDs(issues []Issue) map[string]Issue {
	m := map[string]Issue{}
	for _, i := range issues {
		m[i.RuleID] = i
	}
	return m
}

func TestScan_DetectsHighImpactMisconfigs(t *testing.T) {
	tf := `
resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "weak" {
  bucket                  = aws_s3_bucket.public.id
  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = false
  restrict_public_buckets = true
}

resource "aws_security_group" "open_ssh" {
  name = "open-ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "db" {
  identifier          = "prod"
  publicly_accessible = true
  storage_encrypted   = false
}

resource "aws_ebs_volume" "vol" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

resource "aws_kms_key" "k" {
  enable_key_rotation = false
}

resource "aws_iam_policy" "admin" {
  name   = "admin"
  policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
}

resource "aws_instance" "web" {
  ami                         = "ami-123"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
}
`
	issues, parseErrs := Scan(map[string]string{"main.tf": tf})
	require.Nil(t, parseErrs)
	got := ruleIDs(issues)

	for _, want := range []string{
		"iac-tf-s3-public-acl",
		"iac-tf-s3-public-access-block-disabled",
		"iac-tf-sg-open-ingress",
		"iac-tf-rds-public",
		"iac-tf-rds-unencrypted",
		"iac-tf-ebs-unencrypted",
		"iac-tf-kms-no-rotation",
		"iac-tf-iam-wildcard-admin",
		"iac-tf-instance-public-ip",
	} {
		require.Contains(t, got, want, "expected rule %s to fire", want)
	}

	// SSH open to the world is escalated to High with a specific detail.
	require.Equal(t, SeverityHigh, got["iac-tf-sg-open-ingress"].Severity)
	require.Contains(t, got["iac-tf-sg-open-ingress"].Detail, "SSH")
	require.Equal(t, "aws_security_group.open_ssh", got["iac-tf-sg-open-ingress"].Resource)
	require.Equal(t, "main.tf", got["iac-tf-sg-open-ingress"].File)
}

// Conservative-by-design: attributes that reference variables cannot be read
// statically, so no issue fires (no false positive on a variable-driven config).
func TestScan_IgnoresUnreadableAndSafeConfigs(t *testing.T) {
	tf := `
variable "public" { type = bool }

resource "aws_s3_bucket" "safe" {
  bucket = "locked"
  acl    = "private"
}

resource "aws_db_instance" "safe" {
  identifier          = "prod"
  publicly_accessible = var.public   # interpolated → not statically readable
  storage_encrypted   = true
}

resource "aws_security_group" "internal" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
`
	issues, parseErrs := Scan(map[string]string{"safe.tf": tf})
	require.Nil(t, parseErrs)
	require.Empty(t, issues, "no misconfig should fire on safe / variable-driven config, got %+v", issues)
}

func TestScan_ReportsParseErrors(t *testing.T) {
	issues, parseErrs := Scan(map[string]string{"broken.tf": `resource "aws_s3_bucket" "x" {`})
	require.Empty(t, issues)
	require.Contains(t, parseErrs, "broken.tf")
}

func TestPolicyGrantsWildcardAdmin(t *testing.T) {
	require.True(t, policyGrantsWildcardAdmin(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`))
	require.True(t, policyGrantsWildcardAdmin(`{"Statement":{"Effect":"Allow","Action":["*"],"Resource":["*"]}}`))
	require.False(t, policyGrantsWildcardAdmin(`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`))
	require.False(t, policyGrantsWildcardAdmin(`{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`))
	require.False(t, policyGrantsWildcardAdmin(`not json`))
}
