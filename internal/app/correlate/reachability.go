package correlate

import (
	"maps"
	"net/netip"
	"strconv"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/cidrset"
)

// InternetReachability computes which assets are actually reachable from the
// internet and records each as an exposed_to_internet edge to the singleton
// `internet` sentinel node. Exposure requires BOTH a public entry point AND a
// permissive path to it:
//
//   - AWS EC2: per address family, a public IPv4 address + an SG rule spanning
//     0.0.0.0/0, or a global IPv6 address + one spanning ::/0, in a subnet not
//     observed private for that family (routeBasis). An unread route/SG is
//     possible, and only an observed public route supports confirmation.
//   - GCP GCE: the same interface has an external address and an applicable
//     INGRESS allow in that family, with no preceding matching deny. Missing
//     interface, destination or rule-list evidence retains a possible path.
//   - Azure VM: a public NIC whose subnet and NIC NSGs all admit internet
//     traffic (0.0.0.0/0, ::/0, *, Any, Internet) on some port, rules
//     evaluated in priority order with first match winning; or a public NIC
//     with no NSG on a Basic-SKU IP. An unread NSG or SKU yields the possible
//     tier.
//   - Managed services: any asset with Metadata["public"]=="true" is intrinsically
//     reachable (Cloud SQL/Run/Functions, GCP Forwarding Rules, API Gateway, ECS,
//     Lambda, Azure WebApp/AppGateway/Storage/SQL).
type InternetReachability struct{}

func (InternetReachability) Name() string { return "internet_reachability" }

func (InternetReachability) InterestedIn() []string {
	return []string{
		"ec2_instance", "security_group", "gce_instance", "gcp_firewall",
		"azure_vm", "azure_public_ip",
		"cloudsql_instance", "cloudrun_service", "cloud_function",
		"gcp_forwarding_rule", "api_gateway", "ecs_service", "lambda_function",
		"azure_webapp", "azure_app_gateway", "azure_storage_account", "azure_sql_server",
		"load_balancer", "k8s_ingress",
		// eks_cluster/gke_cluster/s3_bucket/gcs_bucket/rds_instance: these are all
		// producers in Correlate() below and must appear here too, or
		// PartialCorrelate (gated by InterestedIn) never recomputes reachability
		// for them on a targeted sync — only the next full sweep would catch it.
		"eks_cluster", "gke_cluster", "s3_bucket", "gcs_bucket", "rds_instance",
		// kms_key/ecr_repository/sqs_queue/sns_topic: a leaked resource policy
		// (public_access=confirmed) is direct unauthenticated access — see the
		// PublicResourcePolicies case comment in NewGraph. Must stay in sync with
		// asset.NeverSyncTypes.
		"kms_key", "ecr_repository", "sqs_queue", "sns_topic",
		// ebs_snapshot/rds_snapshot/ami/gcp_image/gcp_disk_snapshot/azure_disk: a
		// public snapshot/image/disk is directly copyable by anyone with no
		// credential — same confirmed-tier exposure as a public bucket. See the
		// PublicSnapshots case comment in NewGraph.
		"ebs_snapshot", "rds_snapshot", "ami", "gcp_image", "gcp_disk_snapshot", "azure_disk",
	}
}

func (r InternetReachability) Correlate(g Graph) []asset.Edge {
	edges, _ := r.evaluate(g)
	return edges
}

// Demotions reports the assets that would have been exposed but for a
// route-table observation that their subnet is private (see routeBasis). The
// service logs them, so a demotion is never an edge that silently stopped
// appearing.
func (r InternetReachability) Demotions(g Graph) []Demotion {
	_, demoted := r.evaluate(g)
	return demoted
}

func (InternetReachability) evaluate(g Graph) ([]asset.Edge, []Demotion) {
	var (
		edges   []asset.Edge
		demoted []Demotion
	)

	// AWS EC2: each address family is its own entry point. A public IPv4
	// address is opened only by a rule spanning the IPv4 internet and put on
	// an internet path by an IPv4 route to an internet gateway; a global IPv6
	// address only by a rule spanning the IPv6 internet and an IPv6 route.
	// An observed-private subnet demotes a family; the instance is demoted
	// only when every family a rule opens is.
	for _, inst := range g.PublicAWSInstances() {
		edge, demotion, ok := ec2Exposure(g, inst)
		switch {
		case ok:
			edges = append(edges, edge)
		case demotion:
			demoted = append(demoted, Demotion{AssetID: inst.ID, AssetType: inst.Type, Reason: demotedPrivateSubnet})
		}
	}

	// GCP GCE: external IP + some protocol/port that the world-sourced rules
	// governing the instance leave open, evaluated per port, protocol and IP
	// family in priority order (gcp_firewall_exposure.go).
	for _, inst := range g.GCEInstances() {
		if edge, ok := gceExposure(g, inst); ok {
			edges = append(edges, edge)
		}
	}

	// Azure VM: a public NIC whose subnet and NIC NSGs all admit internet
	// traffic on some port, rules evaluated in priority order, or a public NIC
	// with no NSG whose IP SKU admits it (azure_nsg.go). An NSG or SKU that was
	// not read makes the exposure possible, never absent.
	if vms := g.PublicAzureVMs(); len(vms) > 0 {
		nsgByID := securityGroupsByFoldedID(g)
		for _, inst := range vms {
			if e, ok := azureVMExposure(inst, nsgByID); ok {
				props := map[string]string{"nsg": e.nsgs, "ports": e.ports}
				if e.possiblePorts != "" {
					props["possible_ports"] = e.possiblePorts
				}
				edges = append(edges, exposureEdge(inst, e.via, e.tier, props))
			}
		}
	}

	// Managed services with public=true are intrinsically internet-reachable —
	// no SG/firewall hop to evaluate.
	for _, a := range g.PublicManaged() {
		edges = append(edges, exposureEdge(a, "managed_public", managedTier(a), nil))
	}

	// A publicly-accessible RDS instance is network-reachable from the internet
	// but never unauthenticated — always the possible tier, by definition, which
	// is why this reads asset.PublicAccessPossible directly rather than through
	// managedTier (whose untiered default is Confirmed, correct for other types,
	// wrong here).
	//
	// A publicly-accessible instance whose every subnet is observed private
	// has a public DNS name that resolves to an address no internet client can
	// complete a connection to, so it is demoted the same way as EC2.
	for _, a := range g.PublicRDSInstances() {
		basis, private := routeBasis(a, false)
		if private {
			demoted = append(demoted, Demotion{AssetID: a.ID, AssetType: a.Type, Reason: demotedPrivateSubnet})
			continue
		}
		edges = append(edges, exposureEdge(a, "rds_publicly_accessible", asset.PublicAccessPossible, map[string]string{
			"exposure_basis": basis,
		}))
	}

	// A leaked resource policy (KMS key/ECR repo/SQS queue/SNS topic) that
	// allows everyone — Principal "*" or an Allow with NotPrincipal, under no
	// condition that pins the caller — is unauthenticated access, full stop —
	// there is no credential to check, unlike the RDS case above.
	for _, a := range g.PublicResourcePolicies() {
		edges = append(edges, exposureEdge(a, "resource_policy_public", asset.PublicAccessConfirmed, nil))
	}

	// A public snapshot/image/disk is directly copyable by anyone with no
	// credential — confirmed-tier, same reasoning as the resource-policy leaks
	// above.
	for _, a := range g.PublicSnapshots() {
		edges = append(edges, exposureEdge(a, "snapshot_public", asset.PublicAccessConfirmed, nil))
	}

	return edges, demoted
}

// ec2Exposure evaluates an EC2 instance's public IPv4 address, then its global
// IPv6 addresses, and returns the edge for the first family that a world-open
// SG rule opens on a subnet not observed private. demoted reports that some
// family was opened but every opened family sits in an observed-private subnet.
func ec2Exposure(g Graph, inst asset.Asset) (edge asset.Edge, demoted, ok bool) {
	var possible asset.Edge
	families := []struct {
		name  string
		has   bool
		world netip.Prefix
		viaV6 bool
	}{
		{"ipv4", inst.PublicIP != "", cidrset.WorldV4, false},
		{"ipv6", hasGlobalIPv6(inst), cidrset.WorldV6, true},
	}
	for _, f := range families {
		if !f.has {
			continue
		}
		sgIDs := splitValues(inst.Metadata["security_groups"])
		if len(sgIDs) == 0 {
			sgIDs = []string{""}
		}
		for _, sgID := range sgIDs {
			sg, found := g.SecurityGroup(sgID)
			if !found || !sgIngressObserved(sg) {
				if basis, private := routeBasis(inst, f.viaV6); !private {
					possible = exposureEdge(inst, "aws_sg_unknown", asset.PublicAccessPossible, map[string]string{
						"security_group": sgID, "ports": "all", "exposure_basis": basis, "address_family": f.name,
					})
				}
				continue
			}
			ports := worldOpenPorts(sg, f.world)
			if ports == "" {
				continue
			}
			basis, private := routeBasis(inst, f.viaV6)
			if private {
				demoted = true
				break
			}
			tier := asset.PublicAccessConfirmed
			if basis == basisRouteUnknown {
				tier = asset.PublicAccessPossible
			}
			edge = exposureEdge(inst, "aws_sg_world_open", tier, map[string]string{
				"security_group": sgID,
				"ports":          ports,
				"exposure_basis": basis,
				"address_family": f.name,
			})
			if tier == asset.PublicAccessConfirmed {
				return edge, false, true
			}
			possible = edge
		}
	}
	if possible.SrcID != "" {
		return possible, false, true
	}
	return asset.Edge{}, demoted, false
}

// exposure_basis values: how the network path behind a public-IP exposure was
// established.
const (
	// basisRouteConfirmed: the collector read the subnet's route table and it
	// routes to an internet gateway.
	basisRouteConfirmed = "route_confirmed"
	// basisRouteUnknown: the route table was not read, or its default route
	// goes somewhere public-ness cannot be judged from (transit gateway,
	// peering, appliance). The public address and security group establish
	// a candidate, but the route still needs verification.
	basisRouteUnknown = "route_unknown"
)

// demotedPrivateSubnet is the Demotion reason for a public entry point whose
// subnet routing was observed to have no internet gateway route.
const demotedPrivateSubnet = "private_subnet"

// routeBasis reads the collector's in_public_subnet fact (aws/routes.go). Only
// an explicit "false" — every subnet the resource can sit in was read and none
// routes to an internet gateway — demotes; an absent key is unknown and keeps
// today's exposure, so a failed route-table read can never hide an exposure.
//
// With viaIPv6 it reads in_public_subnet_v6 instead: an instance's IPv6
// address is on an internet path only through an IPv6 route to an internet
// gateway, so a subnet whose IGW route is IPv4-only (its IPv6 default going to
// an egress-only gateway) demotes that family.
//
// This governs only the resource's OWN public entry point. Exposure through a
// load balancer is the load balancer's edge, so a private-subnet target behind
// an internet-facing LB stays reachable through it.
func routeBasis(a asset.Asset, viaIPv6 bool) (basis string, private bool) {
	placement := a.Metadata["in_public_subnet"]
	if viaIPv6 {
		placement = a.Metadata["in_public_subnet_v6"]
	}
	switch placement {
	case "false":
		return "", true
	case "true":
		return basisRouteConfirmed, false
	default:
		return basisRouteUnknown, false
	}
}

// exposureEdge builds an exposed_to_internet edge from an asset to the internet
// sentinel, recording why it was deemed reachable and how well proven it is.
//
// tier is how well the exposure is PROVEN, and it is a property of the evidence,
// not of the asset. A network-derived exposure — a world-open SG/firewall/NSG
// rule on a resolved public IP, a public LoadBalancer Service, a standalone
// public IP — passes confirmed: an observed open path at the layers read (AWS
// network ACLs and GCP firewall policies are not), with nothing left to verify.
// Possible also covers incomplete route, interface, destination and rule-list
// evidence. Other configuration candidates include managedTier(), a publicly accessible RDS instance, an Azure NIC
// whose NSG or public IP SKU was not read, and a LoadBalancer Service limited
// by source ranges or on an unstated scheme (k8sServiceTier).
//
// The property deliberately does NOT reuse the `confidence` key: that one
// already carries the ordinal low/medium/high vocabulary correlate.dedupe ranks
// edges by, and two vocabularies in one key would make the dedupe winner depend
// on which rule happened to stamp it. Same key and same values as the asset
// metadata it derives from is the version that cannot drift.
func exposureEdge(a asset.Asset, via, tier string, extra map[string]string) asset.Edge {
	props := map[string]string{
		"origin":                   edgeOrigin,
		"rule":                     "internet_reachability",
		"via":                      via,
		asset.EdgePropPublicAccess: tier,
	}
	maps.Copy(props, extra)
	return asset.Edge{
		SrcID: a.ID, SrcType: a.Type,
		DstID: InternetNodeID, DstType: "internet",
		EdgeType:   EdgeExposedToInternet,
		Properties: props,
	}
}

// managedTier grades a managed service's exposure from the collector's own
// `public_access` key. An absent grade is confirmed: the key postdates the
// `public` flag, so treating "ungraded" as possible would silently move every
// pre-tier collector's entry points one hop away from the internet.
func managedTier(a asset.Asset) string {
	if a.Metadata["public_access"] == asset.PublicAccessPossible {
		return asset.PublicAccessPossible
	}
	return asset.PublicAccessConfirmed
}

// parsePriority parses a GCP firewall priority from its string metadata value.
// Returns 1000 (GCP default) when the value is absent or unparseable.
func parsePriority(s string) int64 {
	if s == "" {
		return 1000
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 1000
	}
	return n
}
