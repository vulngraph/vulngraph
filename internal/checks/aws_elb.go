package checks

import (
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Load balancer listener, TLS and attribute posture (AWS FSBP ELB.1-4, 6-10,
// 12, 14, 17, 18, 21, 22). ALB/NLB/GWLB and Classic Load Balancers are all
// load_balancer assets told apart by `type` (application, network, gateway,
// classic); target groups are lb_target_group assets.

const (
	lbTypeApplication = "application"
	lbTypeNetwork     = "network"
	lbTypeGateway     = "gateway"
	lbTypeClassic     = "classic"
)

// recommendedELBv2TLSPolicies is FSBP ELB.17's sslPolicies parameter (not
// customizable): the TLS 1.3-capable policies with a restricted cipher set.
var recommendedELBv2TLSPolicies = []string{
	"ELBSecurityPolicy-TLS13-1-3-2021-06",
	"ELBSecurityPolicy-TLS13-1-3-FIPS-2023-04",
	"ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Res-FIPS-2023-04",
	"ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-3-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09",
}

// recommendedClassicTLSPolicy is FSBP ELB.8's predefinedPolicyName.
const recommendedClassicTLSPolicy = "ELBSecurityPolicy-TLS-1-2-2017-01"

// tls12MinimumMarkers identify predefined ELB security policies whose minimum
// protocol is TLS 1.2: every AWS policy name carries its floor
// (ELBSecurityPolicy-TLS-1-2-*, -TLS13-1-2-*, -TLS13-1-3-*, -FS-1-2-*). A name
// without one (ELBSecurityPolicy-2016-08, -TLS-1-1-2017-01, -FS-2018-06,
// TLS13-1-0/1-1 …) still negotiates TLS 1.0 or 1.1.
var tls12MinimumMarkers = []string{"-TLS-1-2-", "-TLS13-1-2-", "-TLS13-1-3-", "-FS-1-2-"}

func lbType(a asset.Asset, types ...string) bool { return slices.Contains(types, a.Metadata["type"]) }

func internetFacing(a asset.Asset) bool { return a.Metadata["scheme"] == "internet-facing" }

// exposureGraded grades a transport finding on an internet-facing balancer at
// Medium (strangers' traffic crosses it) and an internal one at Low.
func exposureGraded(a asset.Asset) finding.Severity {
	if internetFacing(a) {
		return finding.SeverityMedium
	}
	return finding.SeverityLow
}

// listedValues splits a collector CSV, "" meaning observed none.
func listedValues(a asset.Asset, key string) []string {
	var out []string
	for v := range strings.SplitSeq(a.Metadata[key], ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

var awsELBHTTPNoHTTPSRedirect = Check{
	ID:          "aws-elb-http-no-https-redirect",
	Title:       "Application Load Balancer serves HTTP without redirecting to HTTPS",
	Description: "An HTTP listener on the Application Load Balancer forwards requests to targets, or never redirects them to HTTPS, so the application is served in clear text: credentials, session cookies and data cross the network readable and modifiable by anyone on the path. An HTTP listener whose only actions are an HTTPS redirect (and fixed responses) is the intended pattern and is not reported, here or by the listener-protocol check.",
	Remediation: "Make the HTTP listener's default action a redirect to HTTPS:443 and remove every forward rule from it. Console: EC2 > Load Balancers > the ALB > Listeners > HTTP:80 > Edit > Redirect to HTTPS, port 443. CLI: `aws elbv2 modify-listener --listener-arn ARN --default-actions Type=redirect,RedirectConfig='{Protocol=HTTPS,Port=443,StatusCode=HTTP_301}'`, then `aws elbv2 delete-rule --rule-arn RULE` for each forwarding rule.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "load_balancer",
	Violates: func(a asset.Asset) bool {
		return lbType(a, lbTypeApplication) && len(listedValues(a, "http_listeners_without_https_redirect")) > 0
	},
	SeverityFor: exposureGraded,
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"http_listeners_without_https_redirect": a.Metadata["http_listeners_without_https_redirect"], "scheme": a.Metadata["scheme"]}
	},
}

// plaintextHTTP reports whether any listed plaintext listener speaks HTTP —
// application traffic in clear text, as opposed to a TCP/UDP listener that
// may be passing TLS straight through to the targets.
func plaintextHTTP(a asset.Asset) bool {
	for _, l := range listedValues(a, "plaintext_listeners") {
		if strings.HasPrefix(l, "HTTP:") {
			return true
		}
	}
	return false
}

var awsELBPlaintextListener = Check{
	ID:          "aws-elb-plaintext-listener",
	Title:       "Load balancer listener does not terminate TLS",
	Description: "A Classic or Network Load Balancer listener accepts client connections over HTTP, TCP or UDP rather than HTTPS/SSL/TLS, so the load balancer does not encrypt the client leg. An HTTP listener on an internet-facing balancer serves application traffic in clear text and is graded Medium; a TCP or UDP listener may be passing TLS through to the targets (the balancer cannot tell), so it is Low. Application Load Balancer HTTP listeners are graded by aws-elb-http-no-https-redirect, which exempts a redirect-only HTTP listener.",
	Remediation: "Replace the listener with an HTTPS/SSL (Classic) or TLS (Network) listener backed by an ACM certificate. Console: EC2 > Load Balancers > the balancer > Listeners > Add listener (HTTPS/TLS), then delete the plaintext one. CLI: `aws elbv2 create-listener --load-balancer-arn ARN --protocol TLS --port 443 --certificates CertificateArn=ACM_ARN --default-actions Type=forward,TargetGroupArn=TG`; Classic: `aws elb create-load-balancer-listeners --load-balancer-name NAME --listeners Protocol=HTTPS,LoadBalancerPort=443,InstanceProtocol=HTTP,InstancePort=80,SSLCertificateId=ACM_ARN`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "load_balancer",
	Violates: func(a asset.Asset) bool {
		return lbType(a, lbTypeClassic, lbTypeNetwork) && len(listedValues(a, "plaintext_listeners")) > 0
	},
	SeverityFor: func(a asset.Asset) finding.Severity {
		if internetFacing(a) && plaintextHTTP(a) {
			return finding.SeverityMedium
		}
		return finding.SeverityLow
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"plaintext_listeners": a.Metadata["plaintext_listeners"], "scheme": a.Metadata["scheme"]}
	},
}

// tlsPolicyFinding is one HTTPS/TLS listener whose policy the benchmark does
// not recommend; legacy marks a policy that still negotiates TLS 1.0/1.1 or
// one whose protocols cannot be told from its name (custom or unset).
type tlsPolicyFinding struct {
	listener string
	legacy   bool
}

// weakTLSListeners parses tls_listener_policies ("PROTO:port=policy") and
// returns the listeners that miss the benchmark's policy: ELB.8's single
// predefined policy on a Classic balancer, ELB.17's list on ALB/NLB.
func weakTLSListeners(a asset.Asset) []tlsPolicyFinding {
	var out []tlsPolicyFinding
	for _, entry := range listedValues(a, "tls_listener_policies") {
		listener, policy, _ := strings.Cut(entry, "=")
		var ok bool
		if lbType(a, lbTypeClassic) {
			ok = policy == recommendedClassicTLSPolicy
		} else {
			ok = slices.Contains(recommendedELBv2TLSPolicies, policy)
		}
		if ok {
			continue
		}
		legacy := true
		for _, m := range tls12MinimumMarkers {
			if strings.Contains(policy, m) {
				legacy = false
			}
		}
		out = append(out, tlsPolicyFinding{listener: listener + "=" + policy, legacy: legacy})
	}
	return out
}

var awsELBWeakTLSPolicy = Check{
	ID:          "aws-elb-weak-tls-policy",
	Title:       "Load balancer TLS listener does not use the recommended security policy",
	Description: "An HTTPS/TLS listener negotiates with a security policy outside the AWS-recommended set: ELBSecurityPolicy-TLS-1-2-2017-01 for a Classic Load Balancer (FSBP ELB.8), the TLS 1.3 restricted-cipher policies for an ALB/NLB (ELB.17). A policy that still allows TLS 1.0/1.1 (or a custom/unset Classic policy whose protocols cannot be confirmed) lets clients be downgraded to protocols with known weaknesses and is graded Medium on an internet-facing balancer, Low on an internal one. A TLS 1.2+ policy that merely is not on the recommended list — the default for new listeners — is Info.",
	Remediation: "Switch the listener to a recommended policy. ALB/NLB console: Listeners > the listener > Edit > Security policy ELBSecurityPolicy-TLS13-1-2-Res-2021-06; CLI: `aws elbv2 modify-listener --listener-arn ARN --ssl-policy ELBSecurityPolicy-TLS13-1-2-Res-2021-06`. Classic: `aws elb create-load-balancer-policy --load-balancer-name NAME --policy-name tls12 --policy-type-name SSLNegotiationPolicyType --policy-attributes AttributeName=Reference-Security-Policy,AttributeValue=ELBSecurityPolicy-TLS-1-2-2017-01`, then `aws elb set-load-balancer-policies-of-listener --load-balancer-name NAME --load-balancer-port 443 --policy-names tls12`. Check client compatibility first: older clients without TLS 1.2 will no longer connect.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "load_balancer",
	Violates:    func(a asset.Asset) bool { return len(weakTLSListeners(a)) > 0 },
	// An absent policy key is probed with a real entry so the lifecycle sees an
	// unread balancer as not evaluable: no literal in the predicate parses as one.
	TableProbes: []string{"HTTPS:443=ELBSecurityPolicy-2016-08"},
	SeverityFor: func(a asset.Asset) finding.Severity {
		for _, w := range weakTLSListeners(a) {
			if w.legacy {
				return exposureGraded(a)
			}
		}
		return finding.SeverityInfo
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		var ls []string
		for _, w := range weakTLSListeners(a) {
			ls = append(ls, w.listener)
		}
		return map[string]string{"weak_tls_listeners": strings.Join(ls, ","), "scheme": a.Metadata["scheme"]}
	},
}

// desyncDefended reports a desync mitigation mode FSBP ELB.12/ELB.14 accept.
func desyncDefended(mode string) bool { return mode == "defensive" || mode == "strictest" }

var awsELBDesyncMitigationWeak = Check{
	ID:          "aws-elb-desync-mitigation-weak",
	Title:       "Load balancer desync mitigation is in monitor mode",
	Description: "The Application or Classic Load Balancer's HTTP desync mitigation mode is monitor, so it forwards requests whose framing is ambiguous (conflicting Content-Length / Transfer-Encoding headers) to the targets. That is the precondition for HTTP request smuggling: an attacker can desynchronise the balancer and a backend, poison the connection queue or caches, and ride another user's request. defensive (the AWS default) and strictest both block the dangerous classes.",
	Remediation: "Set the mode to defensive or strictest. ALB: `aws elbv2 modify-load-balancer-attributes --load-balancer-arn ARN --attributes Key=routing.http.desync_mitigation_mode,Value=defensive`. Classic: `aws elb modify-load-balancer-attributes --load-balancer-name NAME --load-balancer-attributes '{\"AdditionalAttributes\":[{\"Key\":\"elb.http.desyncmitigationmode\",\"Value\":\"defensive\"}]}'`. Console: EC2 > Load Balancers > the balancer > Attributes > Desync mitigation mode.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "load_balancer",
	Violates: func(a asset.Asset) bool {
		mode, ok := a.Metadata["desync_mitigation_mode"]
		return ok && mode != "" && lbType(a, lbTypeApplication, lbTypeClassic) && !desyncDefended(mode)
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"desync_mitigation_mode": a.Metadata["desync_mitigation_mode"]}
	},
}

var awsELBInvalidHeadersAllowed = Check{
	ID:          "aws-elb-alb-invalid-headers-allowed",
	Title:       "Application Load Balancer forwards invalid HTTP header fields",
	Description: "The ALB does not drop header fields whose names are not valid HTTP (routing.http.drop_invalid_header_fields.enabled=false, the AWS default), so malformed headers reach the targets, where a lenient parser may read them differently than the balancer did. With desync mitigation at defensive or strictest the request-smuggling classes are already blocked, which is why this is Info; when desync mitigation is in monitor mode, aws-elb-desync-mitigation-weak reports the balancer instead — AWS itself advises against running both controls.",
	Remediation: "Enable dropping: `aws elbv2 modify-load-balancer-attributes --load-balancer-arn ARN --attributes Key=routing.http.drop_invalid_header_fields.enabled,Value=true`. Console: EC2 > Load Balancers > the ALB > Attributes > Drop invalid header fields. Confirm no client sends header names with underscores or other invalid characters the application relies on.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "load_balancer",
	// Fires only once the desync mode is known to be defended: a monitor-mode
	// balancer is the desync check's, and an unread mode is unknown.
	Violates: func(a asset.Asset) bool {
		return lbType(a, lbTypeApplication) && a.Metadata["drop_invalid_header_fields"] == "false" &&
			desyncDefended(a.Metadata["desync_mitigation_mode"])
	},
}

var awsELBNoDeletionProtection = Check{
	ID:          "aws-elb-no-deletion-protection",
	Title:       "Load balancer deletion protection is disabled",
	Description: "The Application, Network or Gateway Load Balancer can be deleted by a single API call, taking every service behind it offline (and releasing its DNS name and, for an NLB, its static addresses). Resilience only; no change to exposure.",
	Remediation: "`aws elbv2 modify-load-balancer-attributes --load-balancer-arn ARN --attributes Key=deletion_protection.enabled,Value=true`. Console: EC2 > Load Balancers > the balancer > Attributes > Deletion protection.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "load_balancer",
	Violates: func(a asset.Asset) bool {
		return lbType(a, lbTypeApplication, lbTypeNetwork, lbTypeGateway) && a.Metadata["deletion_protection"] == "false"
	},
}

var awsELBClassicConnectionDraining = Check{
	ID:          "aws-elb-classic-connection-draining-disabled",
	Title:       "Classic Load Balancer connection draining is disabled",
	Description: "When an instance is deregistered or fails its health check, the Classic Load Balancer cuts its in-flight requests instead of letting them finish, so scale-in and deployments drop live connections. Resilience only.",
	Remediation: "`aws elb modify-load-balancer-attributes --load-balancer-name NAME --load-balancer-attributes '{\"ConnectionDraining\":{\"Enabled\":true,\"Timeout\":300}}'`. Console: EC2 > Load Balancers > the balancer > Attributes > Connection draining.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "load_balancer",
	Violates: func(a asset.Asset) bool {
		return lbType(a, lbTypeClassic) && a.Metadata["connection_draining"] == "false"
	},
}

var awsELBClassicCrossZoneDisabled = Check{
	ID:          "aws-elb-classic-cross-zone-disabled",
	Title:       "Classic Load Balancer cross-zone load balancing is disabled",
	Description: "Each Classic Load Balancer node only sends traffic to instances in its own Availability Zone, so an uneven instance count across zones overloads the thinner zone and a zone left without healthy instances blackholes its share of requests. Resilience only.",
	Remediation: "`aws elb modify-load-balancer-attributes --load-balancer-name NAME --load-balancer-attributes '{\"CrossZoneLoadBalancing\":{\"Enabled\":true}}'`. Console: EC2 > Load Balancers > the balancer > Attributes > Cross-zone load balancing.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "load_balancer",
	Violates: func(a asset.Asset) bool {
		return lbType(a, lbTypeClassic) && a.Metadata["cross_zone_load_balancing"] == "false"
	},
}

var awsELBClassicNonACMCertificate = Check{
	ID:          "aws-elb-classic-non-acm-certificate",
	Title:       "Classic Load Balancer TLS listener uses a certificate outside ACM",
	Description: "An HTTPS/SSL listener on the Classic Load Balancer presents an IAM server certificate rather than one from AWS Certificate Manager. IAM certificates never renew themselves, so the listener breaks (or someone pastes a private key into a CLI) every time it expires.",
	Remediation: "Request or import the certificate in ACM, then `aws elb set-load-balancer-listener-ssl-certificate --load-balancer-name NAME --load-balancer-port 443 --ssl-certificate-id ACM_ARN`. Console: EC2 > Load Balancers > the balancer > Listeners > Change SSL certificate.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "load_balancer",
	Violates: func(a asset.Asset) bool {
		return lbType(a, lbTypeClassic) && len(listedValues(a, "non_acm_certificate_listeners")) > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"non_acm_certificate_listeners": a.Metadata["non_acm_certificate_listeners"]}
	},
}

// targetGroupUnencrypted is FSBP ELB.22: a target group routing to its targets
// over HTTP, TCP, UDP, TCP_UDP or TCP_QUIC. Lambda and ALB-type groups and
// GENEVE (Gateway Load Balancer) groups are out of the control's scope.
func targetGroupUnencrypted(a asset.Asset) bool {
	switch a.Metadata["target_type"] {
	case "", "lambda", "alb":
		return false
	}
	switch a.Metadata["protocol"] {
	case "HTTP", "TCP", "UDP", "TCP_UDP", "TCP_QUIC":
		return true
	}
	return false
}

var awsELBTargetGroupUnencrypted = Check{
	ID:          "aws-elb-target-group-unencrypted",
	Title:       "Load balancer target group sends traffic to targets unencrypted",
	Description: "The target group routes requests from the load balancer to its targets over a plaintext protocol (HTTP, TCP or UDP), so traffic decrypted at the balancer crosses the VPC in clear text, health checks included. Terminating TLS at the balancer is a common, deliberate design inside a trusted VPC, which is why this is Info; it matters where the VPC is shared or traffic must stay encrypted end to end.",
	Remediation: "A target group's protocol cannot be changed: create an HTTPS/TLS target group (targets must serve TLS), move the listener rules to it, then delete the old one. CLI: `aws elbv2 create-target-group --name NAME --protocol HTTPS --port 443 --vpc-id VPC --health-check-protocol HTTPS`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "lb_target_group",
	Violates:    targetGroupUnencrypted,
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"protocol": a.Metadata["protocol"], "target_type": a.Metadata["target_type"]}
	},
}

var awsELBTargetGroupHealthCheckUnencrypted = Check{
	ID:          "aws-elb-target-group-health-check-unencrypted",
	Title:       "Encrypted target group health-checks targets without TLS",
	Description: "The target group sends traffic to its targets over TLS but health-checks them over HTTP or TCP, so the health-check exchange — which decides where traffic is routed — can be read or forged on the network path. A group whose traffic is itself plaintext is reported once, by aws-elb-target-group-unencrypted.",
	Remediation: "`aws elbv2 modify-target-group --target-group-arn ARN --health-check-protocol HTTPS`. Console: EC2 > Target groups > the group > Health checks > Edit > Protocol HTTPS.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "lb_target_group",
	Violates: func(a asset.Asset) bool {
		hc, ok := a.Metadata["health_check_protocol"]
		return ok && hc != "" && hc != "HTTPS" && a.Metadata["target_type"] != "lambda" && !targetGroupUnencrypted(a)
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"health_check_protocol": a.Metadata["health_check_protocol"], "protocol": a.Metadata["protocol"]}
	},
}

func awsELBChecks() []Check {
	return []Check{
		awsELBHTTPNoHTTPSRedirect,
		awsELBPlaintextListener,
		awsELBWeakTLSPolicy,
		awsELBDesyncMitigationWeak,
		awsELBInvalidHeadersAllowed,
		awsELBNoDeletionProtection,
		awsELBClassicConnectionDraining,
		awsELBClassicCrossZoneDisabled,
		awsELBClassicNonACMCertificate,
		awsELBTargetGroupUnencrypted,
		awsELBTargetGroupHealthCheckUnencrypted,
	}
}
