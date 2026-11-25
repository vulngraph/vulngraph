package checks

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// EC2 and security-group posture from fields the AWS collector already reads:
// the security group's serialized rules and DescribeInstances attributes.
// Benchmarks: CIS AWS Foundations 6.1.2/6.5, AWS FSBP EC2.2/4/17/18/19/24.

// highRiskPorts is THE world-open port list: AWS FSBP EC2.19's critical ports,
// CIS 6.1.2's CIFS/NetBIOS (445, 139), Redshift (5439), plus every port the
// dedicated admin (adminPorts) and database (databasePorts) checks own.
// Those two lists are subsets of this one (TestHighRiskPortsCoverSubsets), so a
// port is high-risk in exactly one place; aws-sg-open-high-risk-ports reports
// the remainder so each exposed port carries exactly one finding.
var highRiskPorts = []int32{
	20, 21, // FTP
	22,         // SSH
	23,         // Telnet
	25,         // SMTP
	110,        // POP3
	135,        // MS RPC
	139,        // NetBIOS session (CIS 6.1.2)
	143,        // IMAP
	445,        // CIFS/SMB (CIS 6.1.2)
	1433, 1434, // SQL Server
	3000,       // dev web servers / Grafana
	3306,       // MySQL
	3389,       // RDP
	4333,       // mSQL
	5000,       // dev web servers / Docker registry
	5432,       // PostgreSQL
	5439,       // Redshift
	5500,       // VNC listener
	5601,       // Kibana
	5984,       // CouchDB
	5985, 5986, // WinRM
	6379,             // Redis
	8080, 8088, 8888, // proxies, Hadoop YARN, notebooks
	9200, 9300, // Elasticsearch
	27017, // MongoDB
}

// authorizedWorldPorts are the TCP ports FSBP EC2.18 allows open to the world
// by default: plain and TLS web.
var authorizedWorldPorts = []int32{80, 443}

// PortAddressed reports whether a security-group rule's protocol is
// port-addressed (TCP, UDP, or AWS's all-traffic -1). ICMP rules reuse
// FromPort/ToPort for the ICMP type and code, so treating them as port ranges
// would invent exposures. Exported for the internet-reachability correlator.
func PortAddressed(protocol string) bool {
	switch strings.ToLower(protocol) {
	case "-1", "", "tcp", "udp", "6", "17":
		return true
	}
	return false
}

// worldOpenPortsIn returns the ports from candidates that a world-open,
// port-addressed rule exposes, in candidate order.
func worldOpenPortsIn(a asset.Asset, candidates []int32) []int32 {
	var out []int32
	for _, r := range parseSGRules(a) {
		if !ruleWorldOpen(r) || !PortAddressed(r.Protocol) {
			continue
		}
		for _, p := range candidates {
			if slices.Contains(out, p) {
				continue
			}
			if r.Protocol == "-1" || r.Protocol == "" || (r.FromPort <= p && p <= r.ToPort) {
				out = append(out, p)
			}
		}
	}
	return out
}

// residualHighRiskPorts are the high-risk ports no dedicated check owns.
func residualHighRiskPorts() []int32 {
	var out []int32
	for _, p := range highRiskPorts {
		if !slices.Contains(adminPorts, p) && !slices.Contains(databasePorts, p) {
			out = append(out, p)
		}
	}
	return out
}

func joinPorts(ports []int32) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(int(p))
	}
	return strings.Join(s, ",")
}

var awsSGOpenHighRiskPorts = Check{
	ID:          "aws-sg-open-high-risk-ports",
	Title:       "Security group exposes a high-risk service port to the internet",
	Description: "An ingress rule allows 0.0.0.0/0 or ::/0 to reach a port used by a service that should never face the internet — FTP, Telnet, SMTP, POP3/IMAP, MS RPC, SMB/CIFS and NetBIOS (445/139), Redshift, VNC, Kibana, Hadoop, notebooks or development servers. These services are routinely brute-forced, carry a long history of unauthenticated remote-code-execution bugs, or expose data without authentication by default. Admin ports (SSH/RDP/WinRM) and database ports are reported by their own checks.",
	Remediation: "Restrict the rule's source to known CIDRs, a VPN, or a source security group, or remove it. Reach internal services through a bastion, SSM Session Manager, or a private load balancer.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "security_group",
	// Steps aside for an all-ports group: aws-sg-open-all-ports reports it at
	// Critical and strictly dominates.
	Violates: func(a asset.Asset) bool {
		return !sgAllPortsWorldOpen(a) && len(worldOpenPortsIn(a, residualHighRiskPorts())) > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"world_open_ports": joinPorts(worldOpenPortsIn(a, residualHighRiskPorts()))}
	},
}

// unauthorizedWorldRanges returns the world-open TCP and UDP rules that reach
// a port nothing more specific reports, rendered "proto:from-to". A port is
// authorized when it is web TCP (authorizedWorldPorts; no UDP port is
// authorized, as in the AWS Config rule behind FSBP EC2.18), and owned when it
// is in highRiskPorts — the admin, database and high-risk checks report those
// ports themselves. Stepping aside per PORT rather than per group keeps a
// group open on 22 and 9000 reporting 9000 here and 22 under the admin check.
func unauthorizedWorldRanges(a asset.Asset) []string {
	var out []string
	for _, r := range parseSGRules(a) {
		if !ruleWorldOpen(r) {
			continue
		}
		var proto string
		switch strings.ToLower(r.Protocol) {
		case "tcp", "6":
			proto = "tcp"
		case "udp", "17":
			proto = "udp"
		default:
			continue // all-traffic belongs to aws-sg-open-all-ports; ICMP has no ports
		}
		for port := r.FromPort; port <= r.ToPort; port++ {
			if slices.Contains(highRiskPorts, port) || (proto == "tcp" && slices.Contains(authorizedWorldPorts, port)) {
				continue
			}
			out = append(out, proto+":"+strconv.Itoa(int(r.FromPort))+"-"+strconv.Itoa(int(r.ToPort)))
			break
		}
	}
	return out
}

var awsSGOpenUnauthorizedPort = Check{
	ID:          "aws-sg-open-unauthorized-port",
	Title:       "Security group opens an unauthorized port to the internet",
	Description: "An ingress rule allows 0.0.0.0/0 or ::/0 on a TCP port other than 80 or 443, or on any UDP port, that no more specific check covers. Any service listening there on an attached instance is reachable by every scanner on the internet; a world-open rule should be the deliberate exception for a public endpoint, not the default.",
	Remediation: "Narrow the rule to the sources that need it, or front the service with a load balancer that terminates on 80/443. If the port must stay public (a VPN or DNS endpoint), document the exception.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "security_group",
	// A group open on every port is aws-sg-open-all-ports's, which dominates;
	// otherwise only ports no specific check owns count (unauthorizedWorldRanges).
	Violates: func(a asset.Asset) bool {
		return !sgAllPortsWorldOpen(a) && len(unauthorizedWorldRanges(a)) > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"world_open_ranges": strings.Join(unauthorizedWorldRanges(a), ",")}
	},
}

// sgRuleCount reads a collector-written rule count. ok is false when the key
// is absent or malformed — an unread group, never "no rules".
func sgRuleCount(a asset.Asset, key string) (int, bool) {
	n, err := strconv.Atoi(a.Metadata[key])
	return n, err == nil
}

var awsSGDefaultAllowsTraffic = Check{
	ID:          "aws-sg-default-allows-traffic",
	Title:       "Default security group allows traffic",
	Description: "The VPC's default security group has inbound or outbound rules. Any resource launched without an explicit security group lands in the default group, so its rules silently apply to whatever someone forgets to scope. AWS creates it allowing all traffic between members and all egress; CIS and AWS FSBP require it to allow nothing.",
	Remediation: "Remove every inbound and outbound rule from the default security group (it cannot be deleted) and attach purpose-built groups to resources instead. Find members first: `aws ec2 describe-network-interfaces --filters Name=group-id,Values=SG_ID`.",
	Type:        "misconfiguration",
	// Low: every untouched VPC fails this, and the exposure it enables is
	// reported by the port checks when a rule is actually world-open.
	Severity:  finding.SeverityLow,
	Provider:  asset.ProviderAWS,
	AssetType: "security_group",
	Violates: func(a asset.Asset) bool {
		if a.Name != "default" {
			return false
		}
		in, inOK := sgRuleCount(a, "ingress_rules")
		out, outOK := sgRuleCount(a, "egress_rules")
		return (inOK && in > 0) || (outOK && out > 0)
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"ingress_rules": a.Metadata["ingress_rules"], "egress_rules": a.Metadata["egress_rules"]}
	},
}

// longStoppedDays is FSBP EC2.4's default allowed stop period.
const longStoppedDays = 30

var awsEC2StoppedLong = Check{
	ID:          "aws-ec2-stopped-long",
	Title:       "EC2 instance has been stopped for more than 30 days",
	Description: "The instance has been stopped for over 30 days. A long-stopped instance misses every patch released while it was off, keeps its attached volumes, instance profile and security groups, and comes back exactly as stale as it went down when someone restarts it.",
	Remediation: "Terminate the instance if it is no longer needed (snapshot its volumes first if the data matters), or patch it before returning it to service.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "ec2_instance",
	Violates: func(a asset.Asset) bool {
		if a.Metadata["state"] != "stopped" {
			return false
		}
		at, err := time.Parse(time.RFC3339, a.Metadata["stopped_at"])
		return err == nil && time.Since(at) > longStoppedDays*24*time.Hour
	},
	// The probe the lifecycle tries for an absent stopped_at: the predicate only
	// fires on a parseable timestamp, which the derived literal probes never are.
	TableProbes: []string{"2000-01-01T00:00:00Z"},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"stopped_at": a.Metadata["stopped_at"]}
	},
}

var awsEC2MultipleENIs = Check{
	ID:          "aws-ec2-multiple-enis",
	Title:       "EC2 instance has more than one network interface",
	Description: "The instance has several elastic network interfaces. Each interface can sit in a different subnet with its own security groups, so a multi-homed instance can bridge network segments that were meant to stay apart. Kubernetes nodes are exempt: the VPC CNI attaches secondary interfaces to them by design.",
	Remediation: "Detach interfaces the workload does not need, or document why the instance must be multi-homed.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "ec2_instance",
	Violates: func(a asset.Asset) bool {
		n, err := strconv.Atoi(a.Metadata["eni_count"])
		return err == nil && n > 1 && a.Metadata["k8s_node"] != "true"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"eni_count": a.Metadata["eni_count"]}
	},
}

var awsEC2Paravirtual = Check{
	ID:          "aws-ec2-paravirtual",
	Title:       "EC2 instance uses paravirtual virtualization",
	Description: "The instance runs a paravirtual (PV) AMI. PV is a retired virtualization mode limited to previous-generation instance types, which no longer receive new hardware-level security mitigations and cannot use current instance families.",
	Remediation: "Rebuild the workload on an HVM AMI and a current-generation instance type.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "ec2_instance",
	Violates:    func(a asset.Asset) bool { return a.Metadata["virtualization_type"] == "paravirtual" },
}

// singleAZ reports a collector-written zone count below two. An absent or
// malformed count is unknown.
func singleAZ(a asset.Asset, key string) bool {
	n, err := strconv.Atoi(a.Metadata[key])
	return err == nil && n < 2
}

var awsELBSingleAZ = Check{
	ID:          "aws-elb-single-az",
	Title:       "Load balancer is enabled in fewer than two Availability Zones",
	Description: "The load balancer (ALB/NLB/GWLB or Classic) serves from a single Availability Zone, so an outage of that zone takes down everything behind it. Resilience only; no change to exposure.",
	Remediation: "Enable a second zone: `aws elbv2 set-subnets --load-balancer-arn ARN --subnets SUBNET_A SUBNET_B`; for a Classic Load Balancer `aws elb attach-load-balancer-to-subnets --load-balancer-name NAME --subnets SUBNET_B` (EC2-Classic: `aws elb enable-availability-zones-for-load-balancer`).",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "load_balancer",
	Violates:    func(a asset.Asset) bool { return singleAZ(a, "availability_zone_count") },
}

var awsLambdaSingleAZ = Check{
	ID:          "aws-lambda-single-az",
	Title:       "VPC Lambda function runs in a single Availability Zone",
	Description: "The function is attached to subnets in only one Availability Zone, so a zone outage stops every invocation. Resilience only; no change to exposure.",
	Remediation: "Attach the function to subnets in at least two zones: `aws lambda update-function-configuration --function-name NAME --vpc-config SubnetIds=SUBNET_A,SUBNET_B,SecurityGroupIds=SG`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "lambda_function",
	Violates:    func(a asset.Asset) bool { return singleAZ(a, "vpc_az_count") },
}

func awsComputeNetworkChecks() []Check {
	return []Check{
		awsSGOpenHighRiskPorts,
		awsSGOpenUnauthorizedPort,
		awsSGDefaultAllowsTraffic,
		awsEC2StoppedLong,
		awsEC2MultipleENIs,
		awsEC2Paravirtual,
		awsELBSingleAZ,
		awsLambdaSingleAZ,
	}
}
