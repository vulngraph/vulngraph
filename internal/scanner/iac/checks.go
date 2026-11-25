package iac

import (
	"encoding/json"
	"slices"
	"strings"
)

// checks is the full catalog. Each returns zero or more Issues for one resource.
// Checks are conservative: they fire only on a value they could statically read,
// never on an absent (unknown/interpolated) attribute — so a variable-driven
// config produces no false positive, at the cost of a possible false negative.
var checks = []func(Resource) []Issue{
	checkS3PublicACL,
	checkS3PublicAccessBlockDisabled,
	checkSecurityGroupOpenIngress,
	checkSecurityGroupRuleOpenIngress,
	checkRDSPubliclyAccessible,
	checkRDSUnencrypted,
	checkEBSUnencrypted,
	checkKMSNoRotation,
	checkIAMWildcardPolicy,
	checkInstancePublicIP,
}

const worldCIDR = "0.0.0.0/0"

func (r Resource) issue(rule, title, sev, detail, fix string) Issue {
	return Issue{RuleID: rule, Title: title, Severity: sev, Resource: r.Address, File: r.File, Detail: detail, Fix: fix}
}

func checkS3PublicACL(r Resource) []Issue {
	if r.Type != "aws_s3_bucket" {
		return nil
	}
	acl, ok := r.Attrs["acl"]
	if !ok || acl.Kind != "string" {
		return nil
	}
	if acl.Str == "public-read" || acl.Str == "public-read-write" {
		return []Issue{r.issue("iac-tf-s3-public-acl", "S3 bucket has a public ACL", SeverityHigh,
			"acl = \""+acl.Str+"\" grants public access to the bucket",
			"Set acl to \"private\" and manage access via bucket policy / access points.")}
	}
	return nil
}

func checkS3PublicAccessBlockDisabled(r Resource) []Issue {
	if r.Type != "aws_s3_bucket_public_access_block" {
		return nil
	}
	var weak []string
	for _, k := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
		if v, ok := r.Attrs[k]; ok && v.Kind == "bool" && !v.Bool {
			weak = append(weak, k)
		}
	}
	if len(weak) == 0 {
		return nil
	}
	return []Issue{r.issue("iac-tf-s3-public-access-block-disabled", "S3 public access block is weakened", SeverityHigh,
		"disabled: "+strings.Join(weak, ", "),
		"Set all four public-access-block settings to true unless a bucket is deliberately public.")}
}

func checkSecurityGroupOpenIngress(r Resource) []Issue {
	if r.Type != "aws_security_group" {
		return nil
	}
	var issues []Issue
	for _, b := range r.Blocks {
		if b.Type != "ingress" {
			continue
		}
		if cidrs, ok := b.Attrs["cidr_blocks"]; ok && cidrs.Kind == "list" && contains(cidrs.List, worldCIDR) {
			sev, detail := ingressSeverity(b)
			issues = append(issues, r.issue("iac-tf-sg-open-ingress", "Security group allows ingress from the internet", sev,
				detail, "Restrict cidr_blocks to known source ranges; never expose management ports to 0.0.0.0/0."))
		}
	}
	return issues
}

func checkSecurityGroupRuleOpenIngress(r Resource) []Issue {
	if r.Type != "aws_security_group_rule" {
		return nil
	}
	if t, ok := r.Attrs["type"]; ok && t.Kind == "string" && t.Str != "ingress" {
		return nil
	}
	cidrs, ok := r.Attrs["cidr_blocks"]
	if !ok || cidrs.Kind != "list" || !contains(cidrs.List, worldCIDR) {
		return nil
	}
	sev, detail := portSeverity(r.Attrs["from_port"], r.Attrs["to_port"])
	return []Issue{r.issue("iac-tf-sg-rule-open-ingress", "Security group rule allows ingress from the internet", sev,
		detail, "Restrict cidr_blocks to known source ranges.")}
}

func checkRDSPubliclyAccessible(r Resource) []Issue {
	if r.Type != "aws_db_instance" {
		return nil
	}
	if v, ok := r.Attrs["publicly_accessible"]; ok && v.Kind == "bool" && v.Bool {
		return []Issue{r.issue("iac-tf-rds-public", "RDS instance is publicly accessible", SeverityHigh,
			"publicly_accessible = true exposes the database endpoint to the internet",
			"Set publicly_accessible = false and reach the database from within the VPC.")}
	}
	return nil
}

func checkRDSUnencrypted(r Resource) []Issue {
	if r.Type != "aws_db_instance" {
		return nil
	}
	if v, ok := r.Attrs["storage_encrypted"]; ok && v.Kind == "bool" && !v.Bool {
		return []Issue{r.issue("iac-tf-rds-unencrypted", "RDS instance storage is not encrypted", SeverityHigh,
			"storage_encrypted = false leaves data at rest unencrypted",
			"Set storage_encrypted = true (requires a snapshot/restore for existing instances).")}
	}
	return nil
}

func checkEBSUnencrypted(r Resource) []Issue {
	if r.Type != "aws_ebs_volume" {
		return nil
	}
	if v, ok := r.Attrs["encrypted"]; ok && v.Kind == "bool" && !v.Bool {
		return []Issue{r.issue("iac-tf-ebs-unencrypted", "EBS volume is not encrypted", SeverityMedium,
			"encrypted = false leaves the volume's data at rest unencrypted",
			"Set encrypted = true; enable EBS encryption-by-default at the account level.")}
	}
	return nil
}

func checkKMSNoRotation(r Resource) []Issue {
	if r.Type != "aws_kms_key" {
		return nil
	}
	if v, ok := r.Attrs["enable_key_rotation"]; ok && v.Kind == "bool" && !v.Bool {
		return []Issue{r.issue("iac-tf-kms-no-rotation", "KMS key rotation is disabled", SeverityLow,
			"enable_key_rotation = false — the key material is never rotated",
			"Set enable_key_rotation = true for customer-managed keys.")}
	}
	return nil
}

func checkIAMWildcardPolicy(r Resource) []Issue {
	if r.Type != "aws_iam_policy" && r.Type != "aws_iam_role_policy" && r.Type != "aws_iam_user_policy" {
		return nil
	}
	doc, ok := r.Attrs["policy"]
	if !ok || doc.Kind != "string" {
		return nil // policy built via data source / jsonencode — not statically readable
	}
	if !policyGrantsWildcardAdmin(doc.Str) {
		return nil
	}
	return []Issue{r.issue("iac-tf-iam-wildcard-admin", "IAM policy grants wildcard admin (Action \"*\" on Resource \"*\")", SeverityHigh,
		"an Allow statement grants Action \"*\" on Resource \"*\"",
		"Scope actions and resources to the minimum the principal needs.")}
}

func checkInstancePublicIP(r Resource) []Issue {
	if r.Type != "aws_instance" {
		return nil
	}
	if v, ok := r.Attrs["associate_public_ip_address"]; ok && v.Kind == "bool" && v.Bool {
		return []Issue{r.issue("iac-tf-instance-public-ip", "EC2 instance is assigned a public IP", SeverityLow,
			"associate_public_ip_address = true places the instance directly on the internet",
			"Place the instance in a private subnet behind a NAT/load balancer unless public exposure is required.")}
	}
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func contains(list []string, v string) bool {
	for _, x := range list {
		if strings.TrimSpace(x) == v {
			return true
		}
	}
	return false
}

// sensitivePorts are management ports that must never be open to the world.
var sensitivePorts = map[int64]string{22: "SSH", 3389: "RDP", 5985: "WinRM", 5986: "WinRM-HTTPS", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"}

func ingressSeverity(b Block) (sev, detail string) {
	return portSeverity(b.Attrs["from_port"], b.Attrs["to_port"])
}

func portSeverity(from, to Value) (sev, detail string) {
	if from.Kind == "number" && to.Kind == "number" {
		for p, name := range sensitivePorts {
			if from.Num <= p && p <= to.Num {
				return SeverityHigh, "exposes " + name + " (port " + itoa(p) + ") to 0.0.0.0/0"
			}
		}
	}
	return SeverityMedium, "allows ingress from 0.0.0.0/0"
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// policyGrantsWildcardAdmin reports whether an IAM policy JSON document has an
// Allow statement with Action "*" and Resource "*". Handles both single-string
// and array forms for Statement/Action/Resource.
func policyGrantsWildcardAdmin(doc string) bool {
	var p struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(doc), &p) != nil {
		return false
	}
	var stmts []map[string]json.RawMessage
	if err := json.Unmarshal(p.Statement, &stmts); err != nil {
		var one map[string]json.RawMessage
		if json.Unmarshal(p.Statement, &one) != nil {
			return false
		}
		stmts = []map[string]json.RawMessage{one}
	}
	for _, s := range stmts {
		if effect := jsonString(s["Effect"]); effect != "Allow" {
			continue
		}
		if hasWildcard(s["Action"]) && hasWildcard(s["Resource"]) {
			return true
		}
	}
	return false
}

func hasWildcard(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	if s := jsonString(raw); s == "*" {
		return true
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return slices.Contains(list, "*")
	}
	return false
}

func jsonString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}
