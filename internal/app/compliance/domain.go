// Package compliance maps CSPM checks to framework controls (CIS, SOC2,
// PCI-DSS, HIPAA) and reports per-control and per-requirement state. A control
// fails when any mapped check has an open finding. Without one, it passes only
// when every in-scope mapped check evaluated the live estate, is partial when
// only some did, and is not assessed when none did. No finding is not evidence
// of compliance when nothing was looked at. A check for a cloud with neither a
// configured connector nor inventory is out of scope, not a hole in the
// evidence.
package compliance

import (
	"errors"
	"time"
)

// Control is one control and the checks that evidence it. Frameworks lists the
// compliance frameworks this control contributes to (populated at compute time
// from controlFrameworks), so the same check set rolls up under CIS, SOC2,
// PCI-DSS, and HIPAA views — auditors work in framework terms, not check IDs.
type Control struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	CheckIDs   []string `json:"check_ids"`
	Frameworks []string `json:"frameworks"`
}

// Framework identifiers.
const (
	FrameworkCIS    = "CIS"
	FrameworkSOC2   = "SOC2"
	FrameworkPCIDSS = "PCI-DSS"
	FrameworkHIPAA  = "HIPAA"
)

// EvidenceSpec says which inventory facts decide whether a check could
// evaluate an asset, so the sample read keeps only those. A projected key's
// presence always counts; its value counts only where evaluability reads it:
//   - ValueKeys: always (CIEM tiers, completeness and Azure grant shape, plus
//     GCP identity values whose probes depend on completeness).
//   - Probes: on an asset missing one of a multi-key check's keys, Evaluable
//     runs the predicate over the keys that ARE present, so their values count.
//   - An AWS security group's ingress/egress: only whether the rule list
//     decodes (checks.Check.Evaluable rejects an undecodable one).
//   - permissions: only presence and empty/nonempty (Azure's complete empty
//     assignment observation differs from an unstructured nonempty grant).
//
// Everywhere else a value is noise (an AWS policy document, a rule list), and
// grouping on it would return about one sample per asset.
type EvidenceSpec struct {
	Types     []string
	Keys      []string
	ValueKeys []string
	Probes    []ProbeSet
}

// ProbeSet is one multi-key check's RequiredKeys, on the assets it applies to
// (Type "" is every type of the provider).
type ProbeSet struct {
	Provider string
	Type     string
	Keys     []string
}

// Framework sets shared across controls of the same security nature. One check
// commonly satisfies a requirement in several frameworks (e.g. blocking public
// network access is CIS, SOC2 CC6.6, and PCI-DSS Req 1).
var (
	// Network exposure: firewall/SG/public-IP/LB controls.
	fwExposure = []string{FrameworkCIS, FrameworkSOC2, FrameworkPCIDSS}
	// Public data stores: public buckets/blobs — adds HIPAA access control.
	fwPublicData = []string{FrameworkCIS, FrameworkSOC2, FrameworkPCIDSS, FrameworkHIPAA}
	// Encryption / transmission security: SSL/HTTPS/secret rotation.
	fwEncryption = []string{FrameworkCIS, FrameworkSOC2, FrameworkPCIDSS, FrameworkHIPAA}
	// Least privilege / access control: IAM privesc, RBAC.
	fwAccess = []string{FrameworkSOC2, FrameworkPCIDSS, FrameworkHIPAA}
	// CIS-only baseline for controls without a clean framework mapping.
	fwCISOnly = []string{FrameworkCIS}
	// Exposure checks that implement no CIS recommendation (the CIS benchmark
	// matrices in internal/checks/benchmarks list them under no control), so
	// they roll up under SOC2 and PCI-DSS only.
	fwExposureNoCIS = []string{FrameworkSOC2, FrameworkPCIDSS}
	// Secret rotation: no CIS GCP recommendation covers Secret Manager.
	fwRotationNoCIS = []string{FrameworkSOC2, FrameworkPCIDSS, FrameworkHIPAA}
	// Vulngraph hygiene controls that evidence no framework clause at all.
	fwNone = []string{}
)

// controlFrameworks maps a control ID to the frameworks it satisfies. Controls
// absent here default to CIS-only. Kept as one block (vs editing every struct)
// so the framework taxonomy is auditable in one place.
//
// Control IDs are Vulngraph's own labels, so a "CIS-" prefix claims nothing; the
// CIS tag here does. Every check of a control tagged CIS must be backed by the
// CIS benchmark matrix for its platform (TestCISControlsAgreeWithBenchmarkMatrix).
var controlFrameworks = map[string][]string{
	// Network exposure
	"CIS-AWS-5.1": fwExposure,
	"CIS-GCP-4.1": fwExposure, "CIS-GCP-3.1": fwExposure, "CIS-GCP-6.1": fwExposure,
	"CIS-AZ-6.1": fwExposure, "CIS-AZ-6.2": fwExposure,
	// Azure SQL left CIS Azure Foundations in v4.0.0 for the CIS Azure Database
	// Services benchmark, which has no matrix: no CIS tag until it is measured.
	"CIS-AZ-6.3":  fwExposureNoCIS,
	"CIS-AWS-4.1": fwExposureNoCIS, "CIS-AWS-5.2": fwExposureNoCIS, "CIS-AWS-5.3": fwExposureNoCIS,
	"CIS-AWS-ECS-1.1": fwExposureNoCIS, "CIS-AZ-6.6": fwExposureNoCIS, "CIS-K8S-5.4": fwExposureNoCIS,
	"SEC-AWS-NET-1.1": fwExposureNoCIS, "SEC-GCP-NET-1.1": fwExposureNoCIS,
	// Public data stores
	"CIS-AWS-2.1": fwPublicData, "CIS-GCP-5.1": fwPublicData, "CIS-AZ-6.5": fwPublicData,
	// Encryption / transmission / secret rotation
	"CIS-GCP-6.2": fwEncryption, "CIS-AZ-6.4": fwEncryption,
	"CIS-GCP-6.4": fwRotationNoCIS,
	// Access control / least privilege
	"CIS-GCP-6.3": fwAccess, "SOC2-CC6.3-AWS": fwAccess, "SOC2-CC6.3-GCP": fwAccess,
	"CIS-K8S-5.1": fwAccess, "CIS-K8S-5.1.1": fwAccess, "CIS-K8S-5.2": fwAccess, "CIS-K8S-5.3": fwAccess,
	// Misc
	"CIS-GH-1.1":  {FrameworkSOC2, FrameworkCIS},
	"CIS-AWS-5.4": fwNone, "SEC-DNS-1.1": fwNone,
}

// frameworksFor returns the frameworks a control satisfies (CIS-only default).
func frameworksFor(controlID string) []string {
	if fw, ok := controlFrameworks[controlID]; ok {
		return fw
	}
	return fwCISOnly
}

// controls is the static check→control mapping. It grows as checks are added;
// kept in code so it ships with the binary.
var controls = []Control{
	// ── CIS AWS ──────────────────────────────────────────────────────────────
	{ID: "CIS-AWS-4.1", Title: "EC2 instances should not be internet-exposed", CheckIDs: []string{"aws-ec2-public-ip"}},
	{ID: "CIS-AWS-2.1", Title: "S3 buckets should not be publicly accessible", CheckIDs: []string{"aws-s3-public-bucket", "aws-s3-public-read", "aws-s3-public-write"}},
	// The former single mapping named "aws-sg-world-open-admin-port", a check ID
	// that does not exist in the registry — so this control reported Passing
	// unconditionally, no matter how many security groups were world-open. Mapped
	// to the real IDs.
	{ID: "CIS-AWS-5.1", Title: "Security groups should not allow unrestricted admin-port ingress", CheckIDs: []string{"aws-security-group-world-open-admin-port", "aws-sg-open-all-ports"}},
	// World-open database ports are not a CIS AWS recommendation (CIS names
	// remote-administration ports only), so they are their own non-CIS control.
	{ID: "SEC-AWS-NET-1.1", Title: "Security groups should not expose database ports to the internet", CheckIDs: []string{"aws-sg-open-database-ports"}},
	{ID: "CIS-AWS-5.2", Title: "Subnets should not auto-assign public IPs", CheckIDs: []string{"aws-subnet-auto-assign-public-ip"}},
	{ID: "CIS-AWS-5.3", Title: "Load balancers should not be directly internet-facing", CheckIDs: []string{"aws-alb-internet-facing"}},
	{ID: "CIS-AWS-5.4", Title: "Elastic IPs should be attached to active resources", CheckIDs: []string{"aws-eip-unassociated"}},
	// ── CIS GCP ──────────────────────────────────────────────────────────────
	{ID: "CIS-GCP-4.1", Title: "Compute instances should not have public IPs", CheckIDs: []string{"gcp-gce-public-ip"}},
	{ID: "CIS-GCP-5.1", Title: "GCS buckets should not be publicly accessible", CheckIDs: []string{"gcp-gcs-public-bucket"}},
	{ID: "CIS-GCP-3.1", Title: "GCP firewall rules should not expose SSH or RDP to the internet", CheckIDs: []string{"gcp-firewall-ssh-open-internet", "gcp-firewall-rdp-open-internet", "gcp-firewall-all-ports-open-internet"}},
	// Internet-open ingress on other ports is not a CIS GCP recommendation (CIS
	// names SSH and RDP only), so, like SEC-AWS-NET-1.1, it is its own non-CIS control.
	{ID: "SEC-GCP-NET-1.1", Title: "GCP firewall rules should not allow unrestricted ingress", CheckIDs: []string{"gcp-firewall-open-ingress"}},
	{ID: "CIS-GCP-6.1", Title: "Cloud SQL should not have a public IP", CheckIDs: []string{"gcp-cloudsql-public-ip"}},
	{ID: "CIS-GCP-6.2", Title: "Cloud SQL should enforce SSL connections", CheckIDs: []string{"gcp-cloudsql-no-ssl"}},
	{ID: "CIS-GCP-6.3", Title: "Cloud Run services should not be publicly accessible without auth", CheckIDs: []string{"gcp-cloudrun-public"}},
	{ID: "CIS-GCP-6.4", Title: "Secret Manager secrets should be rotated", CheckIDs: []string{"gcp-secret-no-rotation"}},
	// ── CIS GitHub ────────────────────────────────────────────────────────────
	{ID: "CIS-GH-1.1", Title: "Repositories should not be unintentionally public", CheckIDs: []string{"github-public-repo"}},
	// ── CIS Kubernetes ────────────────────────────────────────────────────────
	// Namespaced Roles are folded into the same controls as their ClusterRole
	// siblings — the CIS control is about the RBAC grant, not whether it happens
	// to be cluster- or namespace-scoped.
	{ID: "CIS-K8S-5.1", Title: "Kubernetes RBAC roles should not use wildcard verbs", CheckIDs: []string{"k8s-cluster-role-wildcard-verbs", "k8s-role-wildcard-verbs"}},
	// Least-privilege in RBAC is not only about wildcards: a ClusterRole naming
	// secrets-read, pod-exec, escalate/bind/impersonate or CSR-approval explicitly
	// is equally a violation, and without this mapping those findings counted
	// toward no control at all.
	{ID: "CIS-K8S-5.1.1", Title: "Kubernetes RBAC roles should not grant privilege-escalation or credential-theft capabilities", CheckIDs: []string{"k8s-rbac-secrets-access", "k8s-rbac-pod-create", "k8s-rbac-pod-exec", "k8s-rbac-pv-create", "k8s-rbac-node-proxy", "k8s-rbac-csr-approve", "k8s-rbac-webhook-config", "k8s-rbac-token-create", "k8s-rbac-escalate"}},
	// RoleBindings binding the built-in admin/edit ClusterRole into a
	// namespace are an escalation path with no other visibility —
	// see k8s-rolebinding-admin-binding.
	{ID: "CIS-K8S-5.2", Title: "No ClusterRoleBindings or RoleBindings to cluster-admin/admin/edit should exist", CheckIDs: []string{"k8s-cluster-admin-binding", "k8s-clusterrolebinding-admin-edit", "k8s-rolebinding-admin-binding"}},
	{ID: "CIS-K8S-5.3", Title: "Default service accounts should not be actively bound", CheckIDs: []string{"k8s-default-service-account-bound", "k8s-rolebinding-default-service-account-bound"}},
	{ID: "CIS-K8S-5.4", Title: "Kubernetes Services should not expose public load balancers", CheckIDs: []string{"k8s-service-public-loadbalancer"}},
	// ── CIS Azure ─────────────────────────────────────────────────────────────
	{ID: "CIS-AZ-6.1", Title: "Azure NSGs should not allow RDP from the internet", CheckIDs: []string{"azure-nsg-rdp-not-open-internet"}},
	{ID: "CIS-AZ-6.2", Title: "Azure NSGs should not allow SSH from the internet", CheckIDs: []string{"azure-nsg-ssh-not-open-internet"}},
	{ID: "CIS-AZ-6.3", Title: "Azure SQL servers should disable public network access", CheckIDs: []string{"azure-sql-server-public-network-access"}},
	{ID: "CIS-AZ-6.4", Title: "Azure Storage should enforce HTTPS", CheckIDs: []string{"azure-storage-https-not-enforced"}},
	{ID: "CIS-AZ-6.5", Title: "Azure Storage should not allow public blob access", CheckIDs: []string{"azure-storage-public-blob-access"}},
	{ID: "CIS-AZ-6.6", Title: "Azure VMs should not have a direct public IP", CheckIDs: []string{"azure-vm-direct-public-ip"}},
	// ── SOC 2 CC6.3 — Least Privilege ────────────────────────────────────────
	// One control per CIEM family; each control covers the full set of techniques
	// that represent a violation of that principle in that cloud.
	{ID: "SOC2-CC6.3-AWS", Title: "AWS IAM principals must not hold privilege-escalation capabilities",
		CheckIDs: []string{
			"aws-privesc-01", "aws-privesc-02", "aws-privesc-03", "aws-privesc-04",
			"aws-privesc-05", "aws-privesc-06", "aws-privesc-07", "aws-privesc-08",
			"aws-privesc-09", "aws-privesc-10", "aws-privesc-11", "aws-privesc-12",
			"aws-privesc-13", "aws-privesc-14", "aws-privesc-15", "aws-privesc-16",
			"aws-privesc-17", "aws-privesc-18", "aws-privesc-19", "aws-privesc-20",
			"aws-privesc-21", "aws-privesc-22", "aws-privesc-23",
		}},
	{ID: "SOC2-CC6.3-GCP", Title: "GCP service accounts must not hold privilege-escalation capabilities",
		CheckIDs: []string{
			"gcp-privesc-01", "gcp-privesc-02", "gcp-privesc-03", "gcp-privesc-04",
			"gcp-privesc-05", "gcp-privesc-06", "gcp-privesc-07", "gcp-privesc-08",
			"gcp-privesc-09", "gcp-privesc-10", "gcp-privesc-11", "gcp-privesc-12",
			"gcp-privesc-13", "gcp-privesc-14", "gcp-privesc-15", "gcp-privesc-16",
			"gcp-privesc-17", "gcp-privesc-18",
		}},
	// ── DNS ───────────────────────────────────────────────────────────────────
	{ID: "SEC-DNS-1.1", Title: "DNS CNAME records should not point to unclaimed endpoints", CheckIDs: []string{"dns-cname-takeover-risk", "gcp-dns-cname-takeover-risk"}},
	// ── ECS ──────────────────────────────────────────────────────────────────
	{ID: "CIS-AWS-ECS-1.1", Title: "ECS services should not assign public IPs", CheckIDs: []string{"ecs-service-assign-public-ip"}},
}

// Control states.
const (
	StatePassing = "passing"
	StateFailing = "failing"
	// StateNotAssessed: no open finding, but none of the control's checks could
	// evaluate any live asset — no applicable assets (no connector for that
	// provider, or none of that resource type), or every applicable asset lacks
	// the evidence the check reads.
	StateNotAssessed = "not_assessed"
	// StatePartial: no open finding, and some but not all of the control's
	// checks could evaluate a live asset. The unevaluated checks are not
	// evidence of compliance, so the control is not passing.
	StatePartial = "partial"
)

// Status is the coverage report for one control. Passing is State ==
// StatePassing, a boolean shorthand; a partial or not-assessed control is not
// passing.
type Status struct {
	Control Control `json:"control"`
	State   string  `json:"state"`
	Passing bool    `json:"passing"`
}

// FrameworkCoverage is the per-state rollup for one framework.
type FrameworkCoverage struct {
	Framework   string `json:"framework"`
	Total       int    `json:"total"`
	Passing     int    `json:"passing"`
	Failing     int    `json:"failing"`
	Partial     int    `json:"partial"`
	NotAssessed int    `json:"not_assessed"`
}

// Coverage is the overall compliance summary.
type Coverage struct {
	Total       int                 `json:"total"`
	Passing     int                 `json:"passing"`
	Failing     int                 `json:"failing"`
	Partial     int                 `json:"partial"`
	NotAssessed int                 `json:"not_assessed"`
	Controls    []Status            `json:"controls"`
	Frameworks  []FrameworkCoverage `json:"frameworks"`
}

// ErrFrameworkNotFound: no requirement-level framework has that ID.
var ErrFrameworkNotFound = errors.New("compliance: framework not found")

// Requirement states (ADR 093). A requirement is passing only when every
// in-scope control it maps is fully covered by checks, every one of those
// checks evaluated live evidence or had nothing to evaluate, at least one did
// evaluate, and none has an open finding. Anything less is unknown, never
// passing: an unevaluable check, a benchmark control with no check, or a
// partial check is a hole in the evidence, not a pass.
const (
	RequirementPassing = "passing"
	RequirementFailing = "failing"
	// RequirementUnknown: no open finding, but the evidence is incomplete.
	RequirementUnknown = "unknown"
	// RequirementManual: no benchmark control maps to the requirement; it
	// needs human evidence.
	RequirementManual = "manual"
)

// RequirementStatus is one framework requirement's live rollup.
type RequirementStatus struct {
	ID    string
	Title string
	State string
	// Controls are the benchmark controls mapped ("aws-fsbp/IAM.6").
	Controls []string
	// CheckIDs evidence the in-scope covered and partial controls.
	CheckIDs []string
	// FailingChecks have an open finding.
	FailingChecks []string
	// UnevaluatedChecks apply to live assets that lack the evidence they read.
	UnevaluatedChecks []string
	// Gaps are in-scope controls a check does not fully evaluate (status
	// partial, missing, manual or not_applicable, or a row since removed).
	Gaps []string
	// OutOfScope controls belong to benchmarks for providers with neither a
	// configured connector nor inventory; they neither pass nor block.
	OutOfScope []string
	// EvidenceGaps are in-scope controls whose cloud cannot vouch for its
	// inventory (a connector that never produced assets, a stale or
	// partially failing connector, or inventory no connector refreshes).
	EvidenceGaps []string
	// EvidenceAsOf is the oldest last-successful-sync across the clouds of
	// the in-scope controls; zero when one of them never synced.
	EvidenceAsOf time.Time
	// UnjoinedSourceChecks counts the source mappings that reach no graph
	// control (a partial mapping): graph evaluates only part of what the
	// source counts as evidence, so the requirement is never passing.
	UnjoinedSourceChecks int
	// FailingResources counts distinct resources with an open finding for a
	// failing check. Filled only by the export, which reads them; when a
	// failing check's findings carry no resource ID the count is not a
	// measurement and FailingResourcesKnown is false.
	FailingResources      int
	FailingResourcesKnown bool
}

// CloudEvidence is whether one provider's inventory can vouch for its
// controls.
type CloudEvidence struct {
	Provider string
	// Connectors is the enabled collecting connectors for the provider.
	Connectors   int
	HasInventory bool
	// EvidenceAsOf is the oldest last successful sync across the provider's
	// connectors; zero when one never succeeded or none is configured.
	EvidenceAsOf time.Time
	// Stale: some connector is stale, partially failing or never synced, or
	// there is no connector or no inventory. Its controls are evidence gaps.
	Stale bool
}

// FrameworkSummary is one framework's per-state requirement counts.
type FrameworkSummary struct {
	ID      string
	Name    string
	Version string
	Total   int
	Passing int
	Failing int
	Unknown int
	Manual  int
}

// FrameworkStatus is a framework's summary plus every requirement.
type FrameworkStatus struct {
	FrameworkSummary
	// Clouds is each provider's evidence health, in provider order.
	Clouds       []CloudEvidence
	Requirements []RequirementStatus
}
