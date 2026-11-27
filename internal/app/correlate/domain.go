// Package correlate is the cross-asset correlation stage: it derives edges that
// no single collector can produce because their endpoints live in different
// connectors, accounts, or clouds (e.g. a Route53 record in account A pointing
// to an EC2 public IP in account B, or an AWS DNS record pointing to a GCP
// address). It is Vulngraph's post-sync analysis pass over the graph.
//
// A correlation run loads the relevant inventory once, hands every Rule the same
// read-only Graph view, and writes the edges they derive through the asset edge
// write path (so computed edges share the graph_edges lifecycle with collector
// edges). New relationship families are added by writing one Rule and appending
// it to the slice in cmd/graph/worker.go — the service never changes.
package correlate

import (
	"errors"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// ErrViewTruncated means the inventory view hit correlationLimit. It is an ERROR,
// not a warning: a rule that cannot see an endpoint does not
// re-stamp the edge, and an un-re-stamped edge leaves the traversable graph
// within the 48h freshness window. A truncated sweep therefore DELETES topology
// rather than merely missing it, so the only safe response is to refuse the
// sweep. Refusal does not extend prior edges beyond their freshness window.
var ErrViewTruncated = errors.New("correlate: inventory view truncated at limit")

// EdgeType values produced by correlation rules.
const (
	EdgeDNSPointsTo       = "dns_points_to"
	EdgeCanAssume         = "can_assume"
	EdgeDeploysTo         = "deploys_to"
	EdgeSGAllowsFrom      = "sg_allows_from"      // security_group → security_group (A permits ingress from B)
	EdgeFirewallAppliesTo = "applies_to"          // gcp_firewall → gce_instance
	EdgeExposedToInternet = "exposed_to_internet" // asset → internet sentinel (computed reachability)
	EdgeDefinedIn         = "defined_in"          // IaC ownership: asset declared in a repo
)

// Demotion is an exposure a rule withheld because of positive evidence
// against it (e.g. a public IP in a subnet with no internet gateway route).
// Rules report them so a lost exposed_to_internet edge is logged, not silent.
type Demotion struct {
	AssetID   string
	AssetType string
	Reason    string
}

// InternetNodeID is the singleton sentinel node every exposed_to_internet edge
// points at, so "everything internet-reachable" is one EdgesInto lookup.
const InternetNodeID = "internet"

// edgeOrigin marks an edge as computed by correlation (vs collected), stamped in
// Edge.Properties so computed edges are distinguishable and safely re-derivable.
const edgeOrigin = "correlate"

// Rule derives edges from the whole-graph view. Rules are pure and deterministic:
// the same Graph yields the same edges (stable SrcID/DstID/EdgeType) so the
// ReplacingMergeTree upserts them in place rather than accumulating versions.
type Rule interface {
	Name() string
	// InterestedIn returns the asset types this rule reads from the Graph. Used
	// by PartialCorrelate to skip rules that cannot produce new edges for a
	// given set of changed asset types.
	InterestedIn() []string
	Correlate(g Graph) []asset.Edge
}

// Graph is the read-only inventory view shared across all rules in one run. The
// service builds it once (one scan, many rules), pre-indexing the lookups rules
// need so matching is O(records) rather than O(records × assets).
type Graph struct {
	dnsRecords []asset.Asset
	iamRoles   []asset.Asset
	// permissionPrincipals holds every principal whose identity policies grant
	// permissions — iam_role, iam_user, AND gcp_service_account. Kept separate
	// from iamRoles because only AWS roles carry a trust policy (the
	// can_assume correlator needs roles alone), while the permission-based
	// correlators must cover every principal type they declare interest in —
	// a rule that iterates iamRoles while also declaring iam_user or
	// gcp_service_account in InterestedIn produces nothing for a changed
	// principal of either type.
	permissionPrincipals []asset.Asset
	// changedIDs is the partial-correlate seed set (nil for a full sweep) — see
	// NeedsPermissionRecompute, which scopes a whole-view-cost rule like
	// IAMEffectivePermissions back down to it so a small partial doesn't pay
	// the cost of recomputing the entire principal set.
	changedIDs map[string]bool
	// changedSCPAccounts holds account IDs whose aws_scp_set changed this
	// partial — an SCP caps every principal in-account, not just itself.
	changedSCPAccounts map[string]bool
	// changedTypes is the set of asset types present in changedIDs this
	// partial — see OtherSideUnchanged.
	changedTypes map[string]bool
	// scpPoliciesByAccount maps an account ID to that account's SCP policy
	// documents, from aws_scp_set assets, so correlated edges apply the same
	// organization-level cap that CIEM privesc detection does.
	scpPoliciesByAccount map[string][]collectedPolicy
	workloads            []asset.Asset
	byPublicIP           map[string][]asset.Asset
	byDomain             map[string][]asset.Asset
	repos                []asset.Asset            // every github_repo, in view order
	reposByFull          map[string]asset.Asset   // key: lowercased "org/repo" (the repo's ID)
	reposByName          map[string][]asset.Asset // key: lowercased short repo name

	// Topology / reachability indexes.
	securityGroups         map[string]asset.Asset   // key: SG id
	gcpFirewalls           []asset.Asset            // gcp_firewall rules
	gceInstances           []asset.Asset            // gce_instance assets
	publicAWSInstances     []asset.Asset            // ec2_instance with a public IP or a global IPv6 address
	allEC2Instances        []asset.Asset            // ALL ec2_instance assets (for HasRole — instance profiles on private instances matter too)
	publicAzureVMs         []asset.Asset            // azure_vm with a public IP resolved from NIC
	publicManaged          []asset.Asset            // managed services intrinsically public (Cloud SQL/Run/Functions)
	publicRDSInstances     []asset.Asset            // rds_instance with publicly_accessible=true — network-reachable, ALWAYS credential-gated (never confirmed)
	publicResourcePolicies []asset.Asset            // kms_key/ecr_repository/sqs_queue/sns_topic with a leaked resource policy — direct unauthenticated access, no possible tier
	publicSnapshots        []asset.Asset            // ebs_snapshot/rds_snapshot/ami/gcp_image/gcp_disk_snapshot/azure_disk that is public/internet_exportable — copyable with no credential, no possible tier
	k8sServices            []asset.Asset            // k8s_service assets (for selector→workload linkage)
	k8sServiceAccounts     []asset.Asset            // k8s_service_account assets (for GKE Workload Identity Federation)
	eksClusters            []asset.Asset            // eks_cluster assets (OIDC issuer → cluster, for IRSATrust)
	assetsBySG             map[string][]asset.Asset // assets grouped by SG ID from Metadata["security_groups"]

	// Compute services — ECS, Lambda, Cloud Run, Cloud Functions, Azure Web Apps.
	// Indexed regardless of public status so DeploysTo can link repos to ALL
	// deployments (not just internet-exposed ones). Name-based matching only.
	computeServices      []asset.Asset            // all compute service assets (ecs_service, lambda_function, etc.)
	computeServiceByName map[string][]asset.Asset // key: lowercased service/function name

	// Storage / database assets for DSPM data classification.
	// Populated for all storage types so DataClassification.storageAssets() has
	// something to iterate; it must never iterate Workloads() instead.
	dataStoreAssets []asset.Asset

	// Secret stores (AWS Secrets Manager, SSM SecureString, GCP Secret Manager)
	// keyed by ARN/ID for the SecretAccess correlator's resource-ARN matching.
	secretAssets []asset.Asset

	// Identity / execution indexes (ExecutesAs rule).
	execWorkloads      []asset.Asset   // assets carrying Metadata["exec_role"] (a target IAM node ID)
	principalIDs       map[string]bool // IDs of IAM principals (roles, users, SAs) present in inventory
	gcpServiceAccounts []asset.Asset   // gcp_service_account assets (GCPImpersonation rule)

	// Unified identity — human_identity assets from Okta/Google/GitHub.
	humanIdentities []asset.Asset          // all human_identity assets
	humanByEmail    map[string]asset.Asset // key: lowercased email (Domain field)

	// IaC k8s-manifest ownership.
	declaredK8sWorkloads []asset.Asset            // declared_k8s_workload intermediates
	liveK8sBySuffix      map[string][]asset.Asset // key: <kind>/<ns>/<name> (live ID minus cluster)
	liveK8sByNameKey     map[string][]asset.Asset // key: <kind>/<name> (namespace-agnostic fallback)

	// CI-workflow → cloud-identity federation.
	declaredCIAccess   []asset.Asset // declared_ci_access intermediates
	declaredIdentities []asset.Asset // declared_cloud_identity intermediates (generic harvest)

	// IaC Terraform-state ownership.
	declaredTFResources []asset.Asset // declared_tf_resource intermediates

	// Container image → repo ownership. declaredImageBuilds are the image paths
	// harvested from repo text; containerImagesByPath indexes the live images by
	// their tag-free path so one declaration links every deployed tag/digest of
	// that image at once.
	declaredImageBuilds   []asset.Asset
	containerImagesByPath map[string][]asset.Asset

	// Generic asset-by-id index, keyed by the live asset's own ID (which for
	// most collectors is the ARN, and for a few — s3_bucket, security_group —
	// a bare name/id). TFOwnership is the only rule that needs a lookup across
	// EVERY asset type rather than one type-specific accessor: a
	// declared_tf_resource can name any Terraform-managed resource, so there is
	// no fixed set of type-specific accessor methods to call. Every other rule already has a narrower,
	// purpose-built index and should keep using that instead of this map.
	assetsByID map[string]asset.Asset
}

// NewGraph indexes assets for correlation: DNS records are kept as a list to
// iterate; IP-bearing assets are indexed by public IP; domain-bearing assets
// (load balancers) are indexed by lowercased domain; github repos are indexed by
// full name and short name; k8s workloads are kept as a list to iterate.
func NewGraph(assets []asset.Asset) Graph {
	g := Graph{
		byPublicIP:            map[string][]asset.Asset{},
		byDomain:              map[string][]asset.Asset{},
		reposByFull:           map[string]asset.Asset{},
		reposByName:           map[string][]asset.Asset{},
		securityGroups:        map[string]asset.Asset{},
		assetsBySG:            map[string][]asset.Asset{},
		principalIDs:          map[string]bool{},
		humanByEmail:          map[string]asset.Asset{},
		computeServiceByName:  map[string][]asset.Asset{},
		liveK8sBySuffix:       map[string][]asset.Asset{},
		liveK8sByNameKey:      map[string][]asset.Asset{},
		containerImagesByPath: map[string][]asset.Asset{},
		assetsByID:            map[string]asset.Asset{},
	}
	for _, a := range assets {
		g.assetsByID[a.ID] = a
		// Any asset that declares the IAM identity it runs as is a candidate for an
		// executes_as edge (lambda_function, gce_instance, ecs_service, …).
		if a.Metadata["exec_role"] != "" {
			g.execWorkloads = append(g.execWorkloads, a)
		}
		if isPrincipalType(a.Type) {
			g.principalIDs[a.ID] = true
		}
		// Index storage/database assets for DSPM data classification regardless
		// of public status — private RDS/GCS still classify as PII/financial.
		switch a.Type {
		case "s3_bucket", "gcs_bucket", "azure_blob_container",
			"rds_instance", "dynamodb_table", "firestore_collection", "elasticache_cluster",
			"cloudsql_instance", "cloud_sql_instance", "azure_sql_server", "azure_sql_database":
			g.dataStoreAssets = append(g.dataStoreAssets, a)
			// rds_instance is ALSO an internet-reachability signal, distinct from
			// the DSPM indexing above: PubliclyAccessible=true (aws/rds.go) means
			// the instance has a DNS name resolvable from the internet — network
			// reachability, not confirmed unauthenticated access, since a database
			// credential and a permissive security group are still required.
			//
			// Kept OUT of the generic publicManaged/managedTier path deliberately:
			// managedTier defaults an untiered asset to Confirmed (correct for
			// e.g. azure_public_ip, which needs no credentials at all), and that
			// default would be WRONG here — a public RDS endpoint is possible-tier
			// by definition, never confirmed, so it gets its own always-possible
			// producer instead of borrowing one designed for a different default.
			if a.Metadata["publicly_accessible"] == "true" {
				g.publicRDSInstances = append(g.publicRDSInstances, a)
			}
		// kms_key, ecr_repository, sqs_queue, sns_topic: their resource-policy
		// checks (aws-kms-key-policy-public etc.) run over ClickHouse directly
		// and fire regardless, but the finding's blast radius only reaches the
		// internet-hops BFS if the type is also seeded here.
		//
		// Confirmed-only, unlike managedTier's generic default: a resource
		// policy that allows everyone (Principal "*", or an Allow with
		// NotPrincipal) under no condition that restricts the caller (what
		// publicResourceAccess in collect/aws/resourcepolicy.go checks) IS
		// unauthenticated access — there is no credential-gated middle tier
		// the way there is for a publicly_accessible RDS endpoint.
		case "kms_key", "ecr_repository", "sqs_queue", "sns_topic":
			if a.Metadata["public_access"] == asset.PublicAccessConfirmed {
				g.publicResourcePolicies = append(g.publicResourcePolicies, a)
			}
		// ebs_snapshot/rds_snapshot/ami/gcp_image/gcp_disk_snapshot: a snapshot
		// or image shared publicly can be copied into any attacker-controlled
		// account with no credential of the owner's at all — the exposure
		// checks (aws-ebs-snapshot-public etc.) already grade this Critical/High.
		// Confirmed-tier, same as PublicResourcePolicies above: there is no
		// credential gate to make this "possible" the way RDS network
		// reachability is.
		case "ebs_snapshot", "rds_snapshot", "ami", "gcp_image", "gcp_disk_snapshot":
			if a.Metadata["public"] == "true" {
				g.publicSnapshots = append(g.publicSnapshots, a)
			}
		// azure_disk: same exposure, different metadata key
		// (aws-disk-internet-exportable reads internet_exportable, not public).
		case "azure_disk":
			if a.Metadata["internet_exportable"] == "true" {
				g.publicSnapshots = append(g.publicSnapshots, a)
			}
		case "secretsmanager_secret", "ssm_parameter", "gcp_secret":
			g.secretAssets = append(g.secretAssets, a)
			g.dataStoreAssets = append(g.dataStoreAssets, a) // also classifiable by DSPM
		}
		switch a.Type {
		case "dns_record":
			g.dnsRecords = append(g.dnsRecords, a)
		case "iam_role":
			g.iamRoles = append(g.iamRoles, a)
			g.permissionPrincipals = append(g.permissionPrincipals, a)
		case "iam_user":
			g.permissionPrincipals = append(g.permissionPrincipals, a)
		case "aws_scp_set":
			if a.AccountID != "" {
				if g.scpPoliciesByAccount == nil {
					g.scpPoliciesByAccount = map[string][]collectedPolicy{}
				}
				g.scpPoliciesByAccount[a.AccountID] = append(
					g.scpPoliciesByAccount[a.AccountID], scpPoliciesOf(a)...)
			}
		case "k8s_pod", "k8s_deployment":
			g.workloads = append(g.workloads, a)
			indexLiveK8s(&g, a)
		case "k8s_statefulset", "k8s_daemonset", "k8s_job":
			// Not otherwise tracked by any existing index; index every
			// workload/service kind for suffix-keyed ownership.
			indexLiveK8s(&g, a)
		case "declared_k8s_workload":
			g.declaredK8sWorkloads = append(g.declaredK8sWorkloads, a)
		case "declared_ci_access":
			g.declaredCIAccess = append(g.declaredCIAccess, a)
		case "declared_tf_resource":
			g.declaredTFResources = append(g.declaredTFResources, a)
		case "declared_cloud_identity":
			g.declaredIdentities = append(g.declaredIdentities, a)
		case "declared_image_build":
			g.declaredImageBuilds = append(g.declaredImageBuilds, a)
		case "container_image":
			// Keyed on the tag-free path: a live image asset exists per digest,
			// but a repo declares the path once.
			if p := asset.NormalizeImageRef(a.Name); p != "" {
				g.containerImagesByPath[p] = append(g.containerImagesByPath[p], a)
			}
		case "github_repo":
			g.repos = append(g.repos, a)
			g.reposByFull[strings.ToLower(a.ID)] = a
			if name := repoShortName(a.ID); name != "" {
				key := strings.ToLower(name)
				g.reposByName[key] = append(g.reposByName[key], a)
				// Also index under the name with a leading "<domain>_" prefix
				// removed, so a service deployed as <service> matches a repo named
				// <domain>_<service>. See repoNameWithoutDomainPrefix.
				if stripped := repoNameWithoutDomainPrefix(key); stripped != "" && stripped != key {
					g.reposByName[stripped] = append(g.reposByName[stripped], a)
				}
			}
		case "security_group":
			g.securityGroups[a.ID] = a
		case "gcp_firewall":
			g.gcpFirewalls = append(g.gcpFirewalls, a)
		case "gce_instance":
			g.gceInstances = append(g.gceInstances, a)
		case "ec2_instance":
			g.allEC2Instances = append(g.allEC2Instances, a) // all EC2 — instance profiles on private instances carry blast radius too
			if a.PublicIP != "" || hasGlobalIPv6(a) {
				g.publicAWSInstances = append(g.publicAWSInstances, a)
			}
		case "azure_vm":
			// The collector resolves PublicIP inline from the NIC expansion.
			if a.PublicIP != "" || a.Metadata["direct_public_ip"] != "false" {
				g.publicAzureVMs = append(g.publicAzureVMs, a)
			}
		case "cloudsql_instance", "cloudrun_service", "cloud_function",
			"gcp_forwarding_rule",
			"api_gateway",
			"ecs_service",
			"lambda_function",
			// Azure managed/public services — intrinsically internet-reachable
			// when public=true (web apps always; storage accounts with public blob
			// access; app gateways; external load balancers; public SQL servers).
			"azure_webapp", "azure_app_gateway", "azure_storage_account", "azure_sql_server",
			"azure_sql_database",
			"azure_function",
			// s3_bucket/gcs_bucket: a public bucket policy/ACL is a direct
			// unauthenticated internet entry point, same class of fact as a
			// public storage account two lines up. A bucket without `public`
			// gets no internet edge here, and its public-bucket check stays
			// unevaluated, so the open finding is held, not closed. gcp/gcs.go
			// omits `public` whenever the bucket's IAM policy was unreadable.
			// aws/s3.go omits it, writing public_access=unknown, only when none
			// of the bucket's own block config, its policy status and its ACL
			// was observed: with any one of them read, a bucket not proven
			// public and not locked down grades possible and writes
			// public=true, so a single failed read can still put it here.
			"s3_bucket", "gcs_bucket",
			"load_balancer": // covers both AWS and Azure load_balancer type
			// Always index compute services by name for DeploysTo correlation,
			// regardless of public status (private ECS services are still deployments).
			switch a.Type {
			case "ecs_service", "lambda_function", "cloud_function",
				"cloudrun_service", "azure_webapp", "azure_function":
				g.computeServices = append(g.computeServices, a)
				if name := strings.ToLower(a.Name); name != "" {
					g.computeServiceByName[name] = append(g.computeServiceByName[name], a)
				}
			case "cloudsql_instance", "azure_sql_server", "azure_sql_database":
				// SQL databases — index for DSPM classification.
				g.dataStoreAssets = append(g.dataStoreAssets, a)
			}
			// BOTH tiers become internet edges; the tier travels on the edge as
			// the `public_access` property instead of deciding whether the edge
			// exists at all. Requiring the confirmed tier here would make a
			// SCORING grade govern GRAPH CONSTRUCTION: exposed_to_internet is the
			// only seed of the reachability BFS (graphstore/reach.go), so a
			// resource the collector could not PROVE unauthenticated would be
			// placed at infinite distance from the internet along with everything
			// downstream of it — a loss that is unrecoverable and invisible,
			// since nothing counts an edge that was never created.
			if a.Metadata["public"] == "true" {
				g.publicManaged = append(g.publicManaged, a)
			}
		case "azure_public_ip":
			// A standalone Azure public IP address is always internet-reachable by
			// definition — it is the internet entry point for whatever it's attached to.
			if a.PublicIP != "" {
				g.publicManaged = append(g.publicManaged, a)
			}
		case "k8s_ingress":
			// Public-class ingress hosts are externally reachable — the ingress
			// controller is the internet entry point; the host rule is what's being
			// scanned. Internal-class ingresses are collected public=false.
			if a.Metadata["public"] == "true" {
				g.publicManaged = append(g.publicManaged, a)
			}
		case "k8s_service":
			g.k8sServices = append(g.k8sServices, a)
			indexLiveK8s(&g, a)
		case "k8s_service_account":
			g.k8sServiceAccounts = append(g.k8sServiceAccounts, a)
		case "eks_cluster", "gke_cluster":
			if a.Type == "eks_cluster" {
				g.eksClusters = append(g.eksClusters, a)
			}
			// A managed cluster's API server is an internet entry point when its
			// endpoint is public and its authorized-network allowlist is the whole
			// internet. Both collectors already decide exactly that and record it
			// as public_access=possible (a kubeconfig credential is still needed,
			// so it is never `confirmed`). Keyed on public_access rather than
			// `public` because these collectors grade the tier and never set the
			// boolean.
			if a.Metadata["public_access"] != "" {
				g.publicManaged = append(g.publicManaged, a)
			}
		case "human_identity":
			g.humanIdentities = append(g.humanIdentities, a)
			if email := strings.ToLower(a.Domain); email != "" {
				g.humanByEmail[email] = a
			}
		case "gcp_service_account":
			g.gcpServiceAccounts = append(g.gcpServiceAccounts, a)
			g.permissionPrincipals = append(g.permissionPrincipals, a)
		}
		// byPublicIP / byDomain are the DNS *resolution target* indexes: what a
		// record's value can point AT. DNS name assets are excluded because they
		// are the left side of that join, never the right — a dns_record carries
		// both a Domain (its own name) and, for an A record, a PublicIP copied
		// off its own values, so indexing it would make every record a
		// resolution target for every other record sharing a value, crowding out
		// real infrastructure targets and reading as "resolved" when it points
		// at nothing real. Public IPs are still split on commas for the types
		// that DO belong here: an asset with several public IPs must be
		// findable by each of them.
		if !isDNSNameType(a.Type) {
			for _, ip := range splitValues(a.PublicIP) {
				g.byPublicIP[ip] = append(g.byPublicIP[ip], a)
			}
			if a.Domain != "" {
				key := strings.ToLower(strings.TrimSuffix(a.Domain, "."))
				g.byDomain[key] = append(g.byDomain[key], a)
			}
		}
		// Index assets by every SG ID in their security_groups or nsg_ids metadata
		// so SharedSecurityGroup emits membership edges in O(assets) not O(assets²).
		// Azure VMs carry their NSGs in nsg_ids (Azure NSGs are collected as
		// security_group assets), so folding both keys in records Azure NSG
		// membership the same way as AWS SG membership.
		for _, sgID := range append(splitValues(a.Metadata["security_groups"]), splitValues(a.Metadata["nsg_ids"])...) {
			if sgID != "" {
				g.assetsBySG[sgID] = append(g.assetsBySG[sgID], a)
			}
		}
	}
	// Keep only groupings whose key is a real security_group asset. The
	// security_groups metadata is polluted with non-SG IDs (notably EC2 instance
	// IDs) for some assets — without this an instance becomes a fake hub with
	// thousands of "members", regenerating the O(N²) mesh the spoke-hub design
	// removed. It also guarantees every connected_via_sg edge points at a
	// SecurityGroup node that exists in the graph, so the edge is never dropped
	// at Ladybug insert.
	for sgID := range g.assetsBySG {
		if _, ok := g.securityGroups[sgID]; !ok {
			delete(g.assetsBySG, sgID)
		}
	}
	return g
}

// isDNSNameType reports whether an asset type is a DNS name record rather than
// a piece of infrastructure — the left side of the dns_points_to join, never a
// valid resolution target. See the byPublicIP/byDomain indexing in NewGraph.
func isDNSNameType(t string) bool {
	return t == "dns_record" || t == "dns_zone"
}

// isPrincipalType reports whether an asset type is an IAM principal that a
// workload can execute as — the valid targets of an executes_as edge.
func isPrincipalType(t string) bool {
	switch t {
	case "iam_role", "iam_user", "iam_group", "gcp_service_account",
		"azure_service_principal", "azure_managed_identity":
		return true
	}
	return false
}

// ExecWorkloads returns assets that declare the IAM identity they run as
// (Metadata["exec_role"] = the target principal's node ID).
func (g Graph) ExecWorkloads() []asset.Asset { return g.execWorkloads }

// IsPrincipal reports whether id is an IAM principal present in the inventory —
// so executes_as edges aren't emitted to dangling targets.
func (g Graph) IsPrincipal(id string) bool { return g.principalIDs[id] }

// repoShortName returns the "repo" of an "org/repo" full name.
func repoShortName(fullName string) string {
	if i := strings.LastIndex(fullName, "/"); i >= 0 {
		return fullName[i+1:]
	}
	return fullName
}

// repoNameWithoutDomainPrefix strips a leading "<domain>_" ownership prefix from
// a repo's short name — alpha_svc-a → svc-a, beta_svc-b → svc-b.
//
// This exists because matching a container image to the repo that ships it by
// exact short name rarely fires: images are named
// <registry>/<project>/<service>:<tag>, so DeploysTo extracts <service>, but
// repos are often named <domain>_<service> by convention. Stripping the prefix
// closes most of that gap; an ambiguous stripped name that resolves to more
// than one repo is handled by DeploysTo the same way a plain ambiguous short
// name is — an edge per candidate at medium confidence.
//
// Only the first "_" segment is stripped, and only when something follows it, so
// a repo genuinely named with an underscore (gamma_svc_c_infra → svc_c_infra)
// still yields one extra key rather than being shredded.
// Returns "" when there is no prefix to strip.
func repoNameWithoutDomainPrefix(shortName string) string {
	prefix, rest, ok := strings.Cut(shortName, "_")
	if !ok || prefix == "" || rest == "" {
		return ""
	}
	return rest
}

// DNSRecords returns every dns_record asset in the view.
func (g Graph) DNSRecords() []asset.Asset { return g.dnsRecords }

// IAMRoles returns every iam_role asset in the view.
func (g Graph) IAMRoles() []asset.Asset { return g.iamRoles }

// PermissionPrincipals returns every principal whose identity policies grant
// permissions — iam_role, iam_user, and gcp_service_account. Use this (not
// IAMRoles) in any rule that reasons about what a principal is allowed to DO;
// IAMRoles is for rules that need a trust policy, which only (AWS) roles have.
func (g Graph) PermissionPrincipals() []asset.Asset { return g.permissionPrincipals }

// SCPPoliciesForAccount returns the SCP policy documents capping the given
// account, so a rule evaluating effective permissions applies the same
// organization-level cap that CIEM privesc detection does.
func (g Graph) SCPPoliciesForAccount(accountID string) []collectedPolicy {
	return g.scpPoliciesByAccount[accountID]
}

// scpPoliciesOf decodes the policy documents an aws_scp_set asset carries. The
// collector stores them in the same {type,document} metadata shape as a
// principal's own policies, already typed "scp".
func scpPoliciesOf(a asset.Asset) []collectedPolicy {
	return []collectedPolicy{{Type: "aws_organization", Document: a.Metadata["organization_policies"]}}
}

// AssetsByPublicIP returns assets whose public IP equals ip.
func (g Graph) AssetsByPublicIP(ip string) []asset.Asset { return g.byPublicIP[ip] }

// AssetsByDomain returns assets whose domain equals host (case-insensitive,
// trailing dot trimmed).
func (g Graph) AssetsByDomain(host string) []asset.Asset {
	return g.byDomain[strings.ToLower(strings.TrimSuffix(host, "."))]
}

// Workloads returns every k8s_pod / k8s_deployment asset in the view.
func (g Graph) Workloads() []asset.Asset { return g.workloads }

// RepoByFullName returns the github_repo whose ID equals full (case-insensitive
// "org/repo"), if present.
func (g Graph) RepoByFullName(full string) (asset.Asset, bool) {
	a, ok := g.reposByFull[strings.ToLower(full)]
	return a, ok
}

// GitHubRepos returns every github_repo asset in the view.
func (g Graph) GitHubRepos() []asset.Asset { return g.repos }

// ReposByName returns github repos whose short name equals name (case-insensitive).
func (g Graph) ReposByName(name string) []asset.Asset {
	return g.reposByName[strings.ToLower(name)]
}

// SecurityGroup returns the security_group asset with the given id, if present.
func (g Graph) SecurityGroup(id string) (asset.Asset, bool) {
	a, ok := g.securityGroups[id]
	return a, ok
}

// SecurityGroups returns every security_group asset in the view.
func (g Graph) SecurityGroups() []asset.Asset {
	out := make([]asset.Asset, 0, len(g.securityGroups))
	for _, a := range g.securityGroups {
		out = append(out, a)
	}
	return out
}

// GCPFirewalls returns every gcp_firewall asset in the view.
func (g Graph) GCPFirewalls() []asset.Asset { return g.gcpFirewalls }

// GCEInstances returns every gce_instance asset in the view.
func (g Graph) GCEInstances() []asset.Asset { return g.gceInstances }

// GCPServiceAccounts returns all gcp_service_account assets (GCPImpersonation).
func (g Graph) GCPServiceAccounts() []asset.Asset { return g.gcpServiceAccounts }

// PublicAWSInstances returns ec2_instance assets that carry a public IP.
func (g Graph) PublicAWSInstances() []asset.Asset { return g.publicAWSInstances }

// AllEC2Instances returns ALL ec2_instance assets regardless of public IP.
// Used by EC2InstanceProfile — instance profiles on private instances are
// just as important for blast radius (an attacker inside the VPC can reach them).
func (g Graph) AllEC2Instances() []asset.Asset { return g.allEC2Instances }

// PublicAzureVMs returns azure_vm assets whose public IP was resolved from the NIC.
func (g Graph) PublicAzureVMs() []asset.Asset { return g.publicAzureVMs }

// AssetsBySG returns the map from security group ID to the assets that belong
// to it (via Metadata["security_groups"] CSV). Used by SharedSecurityGroup.
func (g Graph) AssetsBySG() map[string][]asset.Asset { return g.assetsBySG }

// PublicManaged returns managed-service assets (Cloud SQL / Cloud Run / Cloud
// Functions) flagged public — intrinsically internet-reachable entry points.
// Both public_access tiers are included; exposureEdge stamps which one on the
// edge so the tier grades the finding rather than deciding the topology.
func (g Graph) PublicManaged() []asset.Asset { return g.publicManaged }

// PublicRDSInstances returns rds_instance assets with PubliclyAccessible=true.
// Always seeded at the possible tier — see the case comment in NewGraph for why
// this is a separate producer from PublicManaged rather than another entry in it.
func (g Graph) PublicRDSInstances() []asset.Asset { return g.publicRDSInstances }

// PublicResourcePolicies returns kms_key/ecr_repository/sqs_queue/sns_topic
// assets whose resource policy allows everyone (Principal "*", or an Allow
// with NotPrincipal) under no condition that restricts the caller.
// Always seeded confirmed — see the case comment in NewGraph.
func (g Graph) PublicResourcePolicies() []asset.Asset { return g.publicResourcePolicies }

// PublicSnapshots returns public EBS/RDS snapshots, AMIs, GCP images/snapshots
// and internet-exportable Azure disks. Always seeded confirmed — see the case
// comment in NewGraph.
func (g Graph) PublicSnapshots() []asset.Asset { return g.publicSnapshots }

// K8sServices returns every k8s_service asset in the view.
func (g Graph) K8sServices() []asset.Asset { return g.k8sServices }

// K8sServiceAccounts returns every k8s_service_account asset in the view.
func (g Graph) K8sServiceAccounts() []asset.Asset { return g.k8sServiceAccounts }

// EKSClusters returns every eks_cluster asset in the view. IRSATrust reads their
// OIDC issuer / provider ARN to identify which cluster a role's federated trust
// belongs to.
func (g Graph) EKSClusters() []asset.Asset { return g.eksClusters }

// DataStoreAssets returns storage and database assets indexed for DSPM
// data classification (ContainsData edge emission).
func (g Graph) DataStoreAssets() []asset.Asset { return g.dataStoreAssets }

// SecretAssets returns secret-store assets (Secrets Manager, SSM SecureString,
// GCP Secret Manager) for the SecretAccess correlator's ARN matching.
func (g Graph) SecretAssets() []asset.Asset { return g.secretAssets }

// ComputeServices returns ECS services, Lambda functions, Cloud Run services,
// Cloud Functions, and Azure Web Apps — indexed for DeploysTo name matching.
func (g Graph) ComputeServices() []asset.Asset { return g.computeServices }

// ComputeServicesByName returns compute services whose name equals the given
// string (case-insensitive). Used by the DeploysTo correlator.
func (g Graph) ComputeServicesByName(name string) []asset.Asset {
	return g.computeServiceByName[strings.ToLower(name)]
}

// HumanIdentities returns all human_identity assets (from Okta, Google, GitHub).
func (g Graph) HumanIdentities() []asset.Asset { return g.humanIdentities }

// HumanByEmail returns the human_identity asset for an email address (case-insensitive).
func (g Graph) HumanByEmail(email string) (asset.Asset, bool) {
	a, ok := g.humanByEmail[strings.ToLower(email)]
	return a, ok
}

// indexLiveK8s indexes a live k8s asset by the cluster-agnostic suffix of its ID
// (<kind>/<ns>/<name>) and by a namespace-agnostic name key (<kind>/<name>), so
// K8sManifestOwnership can join a manifest — which never names the cluster — to
// every live workload it declares. The ID format <cluster>/<kind>/<ns>/<name> is
// guaranteed by the k8s collector (load-bearing).
func indexLiveK8s(g *Graph, a asset.Asset) {
	suffix, nameKey, ok := k8sIDKeys(a.ID)
	if !ok {
		return
	}
	g.liveK8sBySuffix[suffix] = append(g.liveK8sBySuffix[suffix], a)
	g.liveK8sByNameKey[nameKey] = append(g.liveK8sByNameKey[nameKey], a)
}

// k8sIDKeys splits a live k8s asset ID "<cluster>/<kind>/<ns>/<name>" into the
// suffix key "<kind>/<ns>/<name>" and the name key "<kind>/<name>". ok is false
// for an ID that is not the expected 4-segment shape.
func k8sIDKeys(id string) (suffix, nameKey string, ok bool) {
	parts := strings.SplitN(id, "/", 4)
	if len(parts) != 4 {
		return "", "", false
	}
	kind, ns, name := parts[1], parts[2], parts[3]
	return kind + "/" + ns + "/" + name, kind + "/" + name, true
}

// DeclaredK8sWorkloads returns the declared_k8s_workload intermediates.
func (g Graph) DeclaredK8sWorkloads() []asset.Asset { return g.declaredK8sWorkloads }

// LiveK8sBySuffix returns live k8s assets whose ID suffix (<kind>/<ns>/<name>)
// equals key, across all clusters.
func (g Graph) LiveK8sBySuffix(key string) []asset.Asset { return g.liveK8sBySuffix[key] }

// LiveK8sByNameKey returns live k8s assets whose <kind>/<name> equals key
// (namespace-agnostic fallback for manifests that omit the namespace).
func (g Graph) LiveK8sByNameKey(key string) []asset.Asset { return g.liveK8sByNameKey[key] }

// DeclaredCIAccess returns the declared_ci_access intermediates parsed from
// GitHub Actions workflows, for the CIAccess correlator's join to
// live iam_role / gcp_service_account nodes.
func (g Graph) DeclaredCIAccess() []asset.Asset { return g.declaredCIAccess }

// DeclaredIdentities returns the declared_cloud_identity intermediates harvested
// from repo text by the generic identifier sweep (iac.HarvestIdentities).
func (g Graph) DeclaredIdentities() []asset.Asset { return g.declaredIdentities }

// DeclaredTFResources returns the declared_tf_resource intermediates parsed
// from Terraform state, for the TFOwnership correlator's join to
// live assets by ARN/ID.
func (g Graph) DeclaredTFResources() []asset.Asset { return g.declaredTFResources }

// DeclaredImageBuilds returns the declared_image_build intermediates harvested
// from repo text by the generic repo sweep (github.HarvestImageRefs).
func (g Graph) DeclaredImageBuilds() []asset.Asset { return g.declaredImageBuilds }

// ContainerImagesByPath returns the live container_image assets whose tag-free
// path equals path — every deployed tag and digest of one image.
func (g Graph) ContainerImagesByPath(path string) []asset.Asset {
	return g.containerImagesByPath[path]
}

// AssetByID returns the asset with the given ID, across every asset type in
// the view — used by TFOwnership, which must join a declared_tf_resource's
// target_arn/target_id against ANY live asset type rather than one fixed set.
func (g Graph) AssetByID(id string) (asset.Asset, bool) {
	a, ok := g.assetsByID[id]
	return a, ok
}
