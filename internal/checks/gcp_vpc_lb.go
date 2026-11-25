package checks

// gcp_vpc_lb.go — CIS GCP Foundation VPC and load-balancer controls: the
// default (3.1) and legacy (3.2) networks, Cloud DNS logging (2.13), subnet
// flow logs (3.10, CIS GKE 5.6.1), HTTP(S) load-balancer logging (2.17),
// weak SSL policies (3.11), IAP backends reachable around the proxy (3.12)
// and GKE Ingress certificates (CIS GKE 5.6.7). Read from
// internal/collect/gcp/network.go and loadbalancing.go.

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

var gcpVPCDefaultNetwork = Check{
	ID:          "gcp-vpc-default-network",
	Title:       "Project still has the default VPC network",
	Description: "The auto-mode network named default, which GCP creates in every new project, still exists. It comes with a subnet in every region and permissive pre-populated firewall rules (default-allow-internal, -ssh, -rdp, -icmp), so anything attached to it inherits connectivity nobody designed. Its open firewall rules are reported on their own.",
	Remediation: "Move workloads to a custom-mode network, then delete the default network's firewall rules and the network: `gcloud compute networks delete default`. Enforce with the `compute.skipDefaultNetworkCreation` organization policy.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "vpc_network",
	Violates:    func(a asset.Asset) bool { return a.Metadata["default_network"] == "true" },
}

var gcpVPCLegacyNetwork = Check{
	ID:          "gcp-vpc-legacy-network",
	Title:       "Project uses a legacy VPC network",
	Description: "This is a legacy network: one global IPv4 range with no subnets. Legacy networks cannot use subnet-level controls — flow logs, Private Google Access, per-region ranges — and are no longer supported for new resources.",
	Remediation: "Create a subnet-mode network, migrate the instances, and delete the legacy network (`gcloud compute networks delete NETWORK`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "vpc_network",
	Violates:    func(a asset.Asset) bool { return a.Metadata["legacy_network"] == "true" },
}

var gcpDNSVPCLoggingDisabled = Check{
	ID:          "gcp-dns-vpc-logging-disabled",
	Title:       "VPC network does not log Cloud DNS queries",
	Description: "No Cloud DNS server policy with logging enabled is bound to this network, so the DNS queries its VMs make go unrecorded — the record that shows a host resolving a command-and-control or exfiltration domain.",
	Remediation: "Create (or update) a DNS policy with logging and bind it: `gcloud dns policies create dns-logging --networks=NETWORK --enable-logging --description=\"query logging\"`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "vpc_network",
	Violates:    func(a asset.Asset) bool { return a.Metadata["dns_logging"] == "false" },
}

var gcpSubnetFlowLogsDisabled = Check{
	ID:          "gcp-subnet-flow-logs-disabled",
	Title:       "Subnet does not capture full VPC flow logs",
	Description: "VPC flow logs are off on this subnet, or on with less than the capture CIS asks for (5-second aggregation, sampling 1.0, all metadata, no filter). Without them there is no record of which hosts talked to which, for incident response or for spotting lateral movement. Proxy-only and Private Service Connect subnets carry no VM traffic and are not graded.",
	Remediation: "Enable full flow logs: `gcloud compute networks subnets update SUBNET --region=REGION --enable-flow-logs --logging-aggregation-interval=interval-5-sec --logging-flow-sampling=1 --logging-metadata=include-all`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_subnetwork",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["flow_logs"] == "false" || a.Metadata["flow_logs_config_gaps"] != ""
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"flow_logs": a.Metadata["flow_logs"], "config_gaps": a.Metadata["flow_logs_config_gaps"]}
	},
}

var gcpLBLoggingDisabled = Check{
	ID:          "gcp-lb-logging-disabled",
	Title:       "HTTP(S) load balancer backend does not log requests",
	Description: "Request logging is off on this HTTP(S) load balancer backend service, so the requests it served — source addresses, URLs, response codes — are not recorded for investigating an attack against the application behind it.",
	Remediation: "Enable logging: `gcloud compute backend-services update BACKEND --global --enable-logging --logging-sample-rate=1.0` (use --region for a regional backend).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_backend_service",
	Violates:    func(a asset.Asset) bool { return a.Metadata["logging"] == "false" },
}

var gcpLBWeakSSLPolicy = Check{
	ID:          "gcp-lb-weak-ssl-policy",
	Title:       "TLS load balancer allows weak protocols or ciphers",
	Description: "The HTTPS or SSL proxy's SSL policy allows TLS versions below 1.2 or cipher suites without forward secrecy: no policy (the default, COMPATIBLE with TLS 1.0), a COMPATIBLE profile, MODERN with a TLS floor below 1.2, or a CUSTOM profile enabling RSA key-exchange or 3DES suites.",
	Remediation: "Attach an SSL policy using the MODERN profile with minimum TLS 1.2, or RESTRICTED: `gcloud compute ssl-policies create tls12-modern --profile=MODERN --min-tls-version=1.2` then `gcloud compute target-https-proxies update PROXY --ssl-policy=tls12-modern`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_target_proxy",
	Violates:    func(a asset.Asset) bool { return a.Metadata["ssl_policy_weak"] == "true" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"ssl_policy": a.Metadata["ssl_policy"], "weakness": a.Metadata["ssl_policy_weakness"]}
	},
}

var gcpIAPBackendBypass = Check{
	ID:          "gcp-iap-backend-bypass",
	Title:       "Instances behind IAP are reachable around the proxy",
	Description: "This backend service is protected by Identity-Aware Proxy, but firewall rules admit its instances from sources other than Google's load-balancer and health-check ranges (35.191.0.0/16, 130.211.0.0/22) and IAP's TCP range (35.235.240.0/20) — another range, a source tag or a source service account. Traffic over those rules reaches the application without passing IAP's authentication.",
	Remediation: "Restrict ingress to the backend instances to the Google proxy ranges, and remove or narrow the listed rules: `gcloud compute firewall-rules update RULE --source-ranges=35.191.0.0/16,130.211.0.0/22`.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_backend_service",
	Violates:    func(a asset.Asset) bool { return a.Metadata["iap_bypass_firewall_rules"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"firewall_rules": a.Metadata["iap_bypass_firewall_rules"]}
	},
}

var gcpGKEIngressSelfManagedCert = Check{
	ID:          "gcp-gke-ingress-self-managed-cert",
	Title:       "GKE Ingress serves a self-managed TLS certificate",
	Description: "A load balancer created by a GKE Ingress serves certificates uploaded from Kubernetes Secrets (self-managed) rather than Google-managed certificates, so renewal is manual and the private key lives in a cluster Secret any namespace admin with secret-read can copy.",
	Remediation: "Use a ManagedCertificate resource (networking.gke.io/v1) and reference it with the networking.gke.io/managed-certificates annotation on the Ingress; then remove the TLS Secret.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_target_proxy",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["gke_ingress"] == "true" && a.Metadata["self_managed_certificates"] != ""
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"certificates": a.Metadata["self_managed_certificates"]}
	},
}
