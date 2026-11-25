package checks

// cspm_extra.go — CSPM checks that use metadata already collected by existing
// connectors (zero collector changes required). The checks are independently
// written and implement CIS Benchmark controls. No third-party check code or
// prose is incorporated.

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/cidrset"
)

// ── S3 ───────────────────────────────────────────────────────────────────────

// S3 versioning and access logging are graded only by hygiene.go's
// aws-s3-no-versioning and aws-s3-access-logging-disabled: a check here on the
// same metadata key and asset type would fire on the identical buckets.

// ── EC2 ──────────────────────────────────────────────────────────────────────

var awsEC2NoIAMRole = Check{
	ID:          "aws-ec2-no-iam-role",
	Title:       "EC2 instance has no IAM instance profile",
	Description: "The instance is not associated with an IAM role. Applications running on this instance must use long-lived access keys (a credential hygiene risk). Prefer instance profiles so AWS rotates credentials automatically.",
	Remediation: "Attach an IAM instance profile with the minimum permissions required for the workload.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "ec2_instance",
	Violates: func(a asset.Asset) bool {
		return observedNone(a, "iam_instance_profile")
	},
}

// ── Security Groups ──────────────────────────────────────────────────────────

// parseSGRules extracts ingress rules from the security group's ingress metadata
// JSON. Uses the canonical sgIngressRule (hygiene.go) — the collector serializes
// CIDRs as a plural array under json:"cidrs", and protocol "-1" is AWS's
// "all traffic" sentinel (FromPort/ToPort both 0).
//
// Unreadable JSON yields no rules, so the predicate stays silent — but that
// silence is not a clean reading: structuredMetadataUnreadable makes Evaluable
// report every check reading "ingress" as unevaluable for the asset, so an open
// finding is not closed as fixed on garbage input.
func parseSGRules(a asset.Asset) []sgIngressRule {
	rules, err := decodeSGRules(a.Metadata["ingress"])
	if err != nil {
		return nil
	}
	return rules
}

// decodeSGRules decodes a security group rule list; "" is an observed empty list.
func decodeSGRules(raw string) ([]sgIngressRule, error) {
	if raw == "" {
		return nil, nil
	}
	var rules []sgIngressRule
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		return nil, fmt.Errorf("decodeSGRules: %w", err)
	}
	return rules, nil
}

// structuredMetadataUnreadable reports whether a required key a predicate
// decodes as structured JSON is present on a but undecodable — the predicate
// then never saw the data. Today that is an AWS security group's ingress and
// egress rule lists; other providers' "ingress" keys have their own shapes.
func structuredMetadataUnreadable(a asset.Asset, keys []string) bool {
	if a.Provider != asset.ProviderAWS || a.Type != "security_group" {
		return false
	}
	for _, k := range keys {
		if k != "ingress" && k != "egress" {
			continue
		}
		if raw, present := a.Metadata[k]; present {
			if _, err := decodeSGRules(raw); err != nil {
				return true
			}
		}
	}
	return false
}

// ruleWorldOpen reports whether a rule's source is the IPv4/IPv6 world.
func ruleWorldOpen(r sgIngressRule) bool {
	// A rule's ranges that together span a family (0.0.0.0/1 + 128.0.0.0/1)
	// admit the same sources as the literal world range.
	return cidrset.CoversWorld(r.CIDRs)
}

func sgAllowsWorldOnPorts(a asset.Asset, ports []int32) bool {
	for _, rule := range parseSGRules(a) {
		// ICMP rules reuse the port fields for type/code (PortAddressed).
		if !ruleWorldOpen(rule) || !PortAddressed(rule.Protocol) {
			continue
		}
		// Protocol "-1"/"" is all-traffic (every port open); FromPort/ToPort are 0.
		if rule.Protocol == "-1" || rule.Protocol == "" {
			return true
		}
		for _, p := range ports {
			if rule.FromPort <= p && p <= rule.ToPort {
				return true
			}
		}
	}
	return false
}

// sgAllPortsWorldOpen reports whether the group opens EVERY port to the world —
// AWS's all-traffic protocol "-1" (FromPort/ToPort 0) or an explicit 0–65535
// range. It is the predicate behind aws-sg-open-all-ports and the gate the
// port-specific checks use: a group open on all ports is trivially open on 22,
// on 3306, and on everything else, so reporting those separately would be the
// same Critical exposure counted three times.
func sgAllPortsWorldOpen(a asset.Asset) bool {
	for _, rule := range parseSGRules(a) {
		if !ruleWorldOpen(rule) {
			continue
		}
		if rule.Protocol == "-1" || rule.Protocol == "" || (rule.FromPort == 0 && rule.ToPort >= 65535) {
			return true
		}
	}
	return false
}

// databaseServices names each port of the canonical world-open database port
// set; databasePorts and the aws-sg-open-database-ports description are both
// derived from it, so the text names every port the check fires on.
var databaseServices = []struct {
	name string
	port int32
}{
	{"MySQL", 3306}, {"PostgreSQL", 5432}, {"Redis", 6379}, {"MongoDB", 27017}, {"MSSQL", 1433},
	{"CouchDB", 5984}, {"Elasticsearch", 9200}, {"Elasticsearch transport", 9300},
}

// databasePorts is the canonical world-open database port set, shared with the
// aws-rds-publicly-accessible severity ladder so an RDS instance on 27017 is not
// invisible to one check and reported by the other.
var databasePorts = func() []int32 {
	out := make([]int32, 0, len(databaseServices))
	for _, s := range databaseServices {
		out = append(out, s.port)
	}
	return out
}()

// databasePortList renders databaseServices as "MySQL 3306, PostgreSQL 5432, …".
func databasePortList() string {
	parts := make([]string, 0, len(databaseServices))
	for _, s := range databaseServices {
		parts = append(parts, s.name+" "+strconv.Itoa(int(s.port)))
	}
	return strings.Join(parts, ", ")
}

var awsSGOpenDatabasePorts = Check{
	ID:          "aws-sg-open-database-ports",
	Title:       "Security group allows public access to database ports",
	Description: "This security group has an inbound rule allowing unrestricted access (0.0.0.0/0 or ::/0) to a database port (" + databasePortList() + "). Direct public database access bypasses application-layer controls and enables credential brute force.",
	Remediation: "Restrict database port ingress to known application CIDR ranges. Never expose databases directly to 0.0.0.0/0.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "security_group",
	Violates: func(a asset.Asset) bool {
		// Suppressed when the group is open on all ports: aws-sg-open-all-ports
		// already reports that at Critical and strictly dominates this finding.
		return !sgAllPortsWorldOpen(a) && sgAllowsWorldOnPorts(a, databasePorts)
	},
}

var awsSGOpenAllPorts = Check{
	ID:          "aws-sg-open-all-ports",
	Title:       "Security group allows unrestricted access on all ports",
	Description: "This security group has a rule allowing all traffic (port 0–65535) from anywhere (0.0.0.0/0 or ::/0). This is equivalent to no firewall and exposes every service on the instances to the internet.",
	Remediation: "Replace the catch-all rule with specific port allowances. Use separate rules per service.",
	Type:        "exposure",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderAWS,
	AssetType:   "security_group",
	Violates:    sgAllPortsWorldOpen,
}

// ── RDS ──────────────────────────────────────────────────────────────────────

var awsRDSPubliclyAccessible = Check{
	ID:          "aws-rds-publicly-accessible",
	Title:       "RDS instance is publicly accessible",
	Description: "The RDS instance has PubliclyAccessible=true, so it has a DNS name resolvable from the internet. Access still requires database credentials and a permissive security group — this is network reachability, not confirmed unauthenticated exposure — so it is surfaced at low severity. It is graded Medium when the instance also listens on the default port for its engine, because a public endpoint on a well-known port is what automated scanners and credential-stuffing bots enumerate first.",
	Remediation: "Disable public accessibility: `aws rds modify-db-instance --db-instance-identifier ID --no-publicly-accessible`. Place the database in a private subnet. If the endpoint must stay public, move it off the default port and restrict the security group to known application CIDRs.",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_instance",
	Violates: func(a asset.Asset) bool {
		// Steps aside when the instance is also in a subnet routed to an
		// internet gateway: aws-rds-public-subnet-igw then reports the same
		// root cause at High, with this check's port evidence, so the instance
		// carries one finding.
		return a.Metadata["publicly_accessible"] == "true" && !rdsPublicSubnetIGWViolates(a)
	},
	// The default port is a severity input, not its own check: that check's
	// predicate would be this one plus a port test — a strict subset reporting
	// the identical instances a second time. The port list is databasePorts,
	// the same set aws-sg-open-database-ports uses.
	SeverityFor: func(a asset.Asset) finding.Severity {
		if isDefaultDatabasePort(a.Metadata["port"]) {
			return finding.SeverityMedium
		}
		return finding.SeverityLow
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		port := a.Metadata["port"]
		if port == "" {
			return nil
		}
		return map[string]string{
			"port":                port,
			"default_db_port":     strconv.FormatBool(isDefaultDatabasePort(port)),
			"publicly_accessible": "true",
		}
	},
}

// isDefaultDatabasePort reports whether port is one of the well-known database
// ports in databasePorts.
func isDefaultDatabasePort(port string) bool {
	n, err := strconv.ParseInt(port, 10, 32)
	if err != nil {
		return false
	}
	return slices.Contains(databasePorts, int32(n))
}

// ── IAM ──────────────────────────────────────────────────────────────────────

var awsIAMUserNoMFA = Check{
	ID:          "aws-iam-user-no-mfa",
	Title:       "IAM user with console access has MFA disabled",
	Description: "This IAM user can sign in to the AWS Management Console but does not have multi-factor authentication enabled. A compromised password alone is sufficient to take over the account.",
	Remediation: "Enable MFA for the user: `aws iam enable-mfa-device`. Enforce MFA via an IAM policy condition `aws:MultiFactorAuthPresent`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_user",
	Violates: func(a asset.Asset) bool {
		// The account root is aws-iam-root-no-mfa's.
		return a.Metadata["root"] != "true" && a.Metadata["console_access"] == "true" && a.Metadata["mfa_enabled"] == "false"
	},
}

var awsIAMUserDirectPolicy = Check{
	ID:          "aws-iam-user-direct-policy",
	Title:       "IAM user has directly attached policies",
	Description: "Policies are attached directly to this IAM user rather than through a group. Direct attachments make permissions harder to audit and manage consistently — they tend to accumulate over time.",
	Remediation: "Move the user into appropriate IAM groups and detach the direct policies.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_user",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["policies"] != "" && a.Metadata["policies"] != "[]"
	},
}

// ── GCP ──────────────────────────────────────────────────────────────────────

var gcpGCEDefaultServiceAccount = Check{
	ID:          "gcp-gce-default-sa",
	Title:       "GCE instance runs as the default Compute service account",
	Description: "The instance uses the default Compute Engine service account, which typically has Editor or broad project permissions. If the instance is compromised, attackers gain these permissions via the metadata service.",
	Remediation: "Create a dedicated service account with minimal permissions and assign it to the instance.",
	Type:        "misconfiguration",
	// Medium by default, High when the instance is reachable from the internet:
	// on a private instance the threat model needs a separate foothold first,
	// the difference between a posture weakness and a live path.
	// gcp-function-open-ingress-default-sa grades the identical pairing this
	// way for Cloud Functions.
	Severity:  finding.SeverityMedium,
	Provider:  asset.ProviderGCP,
	AssetType: "gce_instance",
	// Steps aside when the instance also holds the cloud-platform scope
	// (gcp-gce-default-sa-full-scope reports it at High), and for GKE nodes,
	// which gcp-gke-node-default-sa reports once per cluster rather than once
	// per node VM.
	Violates: func(a asset.Asset) bool {
		return gceDefaultSA(a) && !gceDefaultSAFullScope(a) && !gkeNodeGraded(a)
	},
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.PublicIP != "" {
			return finding.SeverityHigh
		}
		return finding.SeverityMedium
	},
}

var gcpCloudSQLNoBackup = Check{
	ID:          "gcp-cloudsql-no-backup",
	Title:       "Cloud SQL instance has automated backups disabled",
	Description: "Automated backups are not enabled for this Cloud SQL instance. Without backups, data loss from accidental deletion, corruption, or ransomware cannot be recovered.",
	Remediation: "Enable automated backups in the Cloud SQL instance settings. Configure a backup retention period appropriate for your RPO.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		// The GCP mirror of the aws-rds-no-backup narrowing: only the explicit
		// "false" the collector writes when it actually read a
		// BackupConfiguration. collect/gcp/cloudsql.go omits `backups` entirely
		// when the API returned no BackupConfiguration, so an unread setting
		// can never arrive here as an observed negative.
		return a.Metadata["backups"] == "false"
	},
}

// cspmExtraChecks returns all checks defined in this file for registration
// via Default(). Kept as a function (not init) so tests can inspect the list.
func cspmExtraChecks() []Check {
	return []Check{
		// S3
		// EC2
		awsEC2NoIAMRole,
		// Security groups
		awsSGOpenDatabasePorts,
		awsSGOpenAllPorts,
		// RDS
		awsRDSPubliclyAccessible,
		// IAM
		awsIAMUserNoMFA,
		awsIAMUserDirectPolicy,
		// GCP
		gcpGCEDefaultServiceAccount,
		gcpCloudSQLNoBackup,
	}
}
