package graphstore

// NamedQuery is a pre-baked Cypher query exposed via POST /api/graph/cypher.
// These showcase patterns a native graph engine makes possible: enriched risk
// scores, multi-hop IAM escalation chains, and cross-domain exposure correlation.
type NamedQuery struct {
	Name        string
	Description string
	Query       string
	// Params lists $variable names the caller must bind (empty = no params).
	Params []string
}

// NamedQueries is the catalog served by GET /api/graph/queries.
// Each entry is a read-only Cypher query validated by graphquery.IsReadOnly.
//
// Conventions every entry follows:
//   - Boolean signal fields (exposed, has_kev, exploitable, toxic_combo) are INT32;
//     compare with = 1, not = true.
//   - Labels that are Cypher reserved words (Group) must be backtick-quoted.
//   - RETURN node/relationship objects, not scalar projections — named queries
//     render as a graph via RunNamedQuery, which keeps only nodes/edges. (execCypher
//     itself captures scalar columns into Result.Rows for the ad-hoc Cypher/NL
//     endpoints, but that path is not wired through named queries.)
//   - Enumerate explicit rel types rather than an untyped -[]->: the rel list is
//     what decides which relationships a query follows.
//   - RunsIn rel table (Package→Asset) is never populated — runs_in edge_type rows
//     map to Accesses (topology). Use RunsPackage (Asset→Package)
//     for asset-to-package traversals instead.
//   - Accesses rel table is Asset→Asset only — Package cannot be its source.
//   - ProtectedBy is Asset→Asset, written by collectors from the protected resource to its
//     security group: (instance|load_balancer)-[:ProtectedBy]->(security_group).
//   - A workload's IAM role is ExecutesAs OR HasRole (an EC2 instance profile):
//     a workload→role hop matches both, or every EC2 instance drops out.
//   - Sharing a security group is not a network path: AWS admits a member's
//     traffic only through an ingress rule naming its SG (or a CIDR covering it).
//     ConnectedViaSG is membership; the allow is (permitting)-[:AllowsFrom]->(admitted),
//     a self-loop when an SG admits its own members. An attacker moves AGAINST
//     AllowsFrom, so an outbound AllowsFrom hop is never attacker movement.
var NamedQueries = []NamedQuery{
	{
		Name:        "internet_exposed_high_risk",
		Description: "Internet-exposed assets with a risk score in the high band or above (>= 61)",
		Params:      []string{},
		Query: `
MATCH (a:Asset)-[e:ExposedToInternet]->(net:Asset {id: 'internet'})
WHERE a.score >= 61
RETURN a, e, net
ORDER BY a.score DESC
LIMIT 50`,
	},
	{
		Name:        "attack_path_internet_to_iam",
		Description: "Full attack path: internet entry -> workload -> IAM role -> assumed target role",
		Params:      []string{},
		Query: `
MATCH (entry:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (entry)-[:ExecutesAs|HasRole]->(role:IamRole)
MATCH (role)-[:CanAssume]->(target:IamRole)
WHERE entry.score >= 40
RETURN entry, role, target
ORDER BY entry.score DESC
LIMIT 25`,
	},
	{
		Name:        "blast_radius",
		Description: "Direct neighbours of a seed asset (one hop outbound)",
		Params:      []string{"id"},
		// This is Go-orchestrated (RunNamedQuery dispatches to blastRadiusGraph in
		// repo_cypher.go), not executed as raw Cypher — a raw MATCH here only ever
		// seeds the generic Asset label, so a seed of any other Ladybug node type
		// would silently return empty. blastRadiusGraph seeds and traverses across
		// all 6 Ladybug node labels safely. The Query field below documents the
		// approximated shape (single-hop outbound from seed); it is not executed.
		Query: `
MATCH (seed:Asset {id: $id})-[r]->(reached)
RETURN seed, r, reached
ORDER BY reached.score DESC
LIMIT 100`,
	},
	{
		Name:        "lateral_movement_via_sg",
		Description: "Internet-exposed assets and the assets they can reach because a security group on the target admits the entry's security group (self-references included). Only security-group-referencing rules are modelled: a CIDR rule covering the entry's private address is not, and sharing a security group alone is not a path.",
		Params:      []string{},
		Query: `
MATCH (entry:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (entry)-[:ConnectedViaSG]->(src:Asset)
MATCH (dst:Asset)-[a:AllowsFrom]->(src)
MATCH (pivot:Asset)-[:ConnectedViaSG]->(dst)
WHERE pivot.id <> entry.id
RETURN entry, src, a, dst, pivot
ORDER BY pivot.score DESC
LIMIT 50`,
	},
	// ── Deep CIEM — CanEscalateTo edges from the CIEM technique catalogue ───
	// CanEscalateTo differs from CanAssume: these are permission-based attacks
	// (CreatePolicyVersion, PassRole+Lambda, SSM SendCommand, etc.) not trust-policy
	// chaining. Both types are queryable — use CanEscalateTo|CanAssume to see all paths.
	{
		Name:        "ciem_escalation_paths",
		Description: "All CIEM technique-based privilege escalation paths (CanEscalateTo edges from the AWS, GCP and Azure technique catalogue)",
		Params:      []string{},
		Query: `
MATCH (a:IamRole)-[r:CanEscalateTo]->(b:IamRole)
RETURN a, r, b
ORDER BY b.score DESC
LIMIT 50`,
	},
	{
		Name:        "ciem_full_attack_chain",
		Description: "Full CIEM attack chain: internet-exposed workload → IAM role → CIEM or trust-policy escalation → high-risk role (risk score >= 70). Risk score ranks findings and reachability, not the permissions a role holds.",
		Params:      []string{},
		Query: `
MATCH (entry:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (entry)-[r1:ExecutesAs|HasRole]->(role:IamRole)
MATCH (role)-[r2:CanEscalateTo|CanAssume]->(target:IamRole)
WHERE target.score >= 70
RETURN entry, r1, role, r2, target
ORDER BY target.score DESC
LIMIT 25`,
	},
	{
		Name:        "ciem_vs_trust_comparison",
		Description: "Roles with CIEM escalation paths that are NOT in CanAssume chains — attacks that bypass trust-policy detection entirely",
		Params:      []string{},
		Query: `
MATCH (a:IamRole)-[:CanEscalateTo]->(b:IamRole)
WHERE NOT (a)-[:CanAssume]->(b)
RETURN a, b
ORDER BY b.score DESC
LIMIT 50`,
	},
	{
		Name:        "iam_privilege_escalation",
		Description: "Workloads whose IAM role can assume a high-risk target role (risk score >= 70, 2-hop)",
		Params:      []string{},
		Query: `
MATCH (workload:Asset)-[:ExecutesAs|HasRole]->(start:IamRole)
MATCH (start)-[:CanAssume]->(target:IamRole)
WHERE target.score >= 70
RETURN workload, start, target
ORDER BY workload.score DESC
LIMIT 30`,
	},
	{
		Name:        "supply_chain_exposure",
		Description: "Internet-exposed assets running vulnerable packages (SBOM supply chain risk)",
		Params:      []string{},
		// RunsIn rel table (Package->Asset) is never populated —
		// the runs_in edge_type is remapped to Accesses (topology: pod->namespace, EC2->subnet).
		// RunsPackage (Asset->Package) is the populated direction for SBOM edges.
		// Traverse Asset->Package via RunsPackage and filter on exposed assets.
		Query: `
MATCH (app:Asset)-[rp:RunsPackage]->(pkg:Package)
MATCH (app)-[:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE app.score >= 40
RETURN app, rp, pkg
ORDER BY app.score DESC
LIMIT 50`,
	},
	{
		Name:        "dns_chain_exposure",
		Description: "DNS records that resolve to internet-exposed targets",
		Params:      []string{},
		Query: `
MATCH (record:Asset)-[d:DnsPointsTo]->(target:Asset)
MATCH (target)-[:ExposedToInternet]->(:Asset {id: 'internet'})
RETURN record, d, target
ORDER BY target.score DESC
LIMIT 40`,
	},
	{
		Name:        "repos_deploying_to_exposed",
		Description: "Source repos that deploy to internet-exposed high-risk assets",
		Params:      []string{},
		Query: `
MATCH (repo:Repo)-[d:DeploysTo]->(app:K8sWorkload)
MATCH (app)-[:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE app.score >= 61
RETURN repo, d, app
ORDER BY app.score DESC
LIMIT 30`,
	},
	{
		Name:        "top_composite_risk",
		Description: "Top 25 assets by risk score",
		Params:      []string{},
		// Sorts directly on the score property rather than a computed composite.
		Query: `
MATCH (a:Asset)
WHERE a.score > 0
RETURN a
ORDER BY a.score DESC
LIMIT 25`,
	},
	{
		Name:        "github_oidc_to_aws_roles",
		Description: "GitHub repos that can assume IAM roles via OIDC — CI/CD cloud access",
		Params:      []string{},
		Query: `
MATCH (repo:Repo)-[f:FederatedAccess]->(role:IamRole)
RETURN repo, f, role
ORDER BY role.score DESC
LIMIT 50`,
	},
	{
		Name:        "github_oidc_full_chain",
		Description: "GitHub repos -> OIDC role -> assumed target role (2-hop CI/CD privilege escalation)",
		Params:      []string{},
		Query: `
MATCH (repo:Repo)-[f:FederatedAccess]->(entry:IamRole)
MATCH (entry)-[:CanAssume]->(target:IamRole)
WHERE entry.score >= 40
RETURN repo, f, entry, target
ORDER BY entry.score DESC
LIMIT 30`,
	},
	{
		Name:        "github_oidc_to_internet_exposed",
		Description: "GitHub repos with OIDC access to roles on internet-exposed workloads",
		Params:      []string{},
		Query: `
MATCH (repo:Repo)-[f:FederatedAccess]->(role:IamRole)
MATCH (role)<-[x:ExecutesAs|HasRole]-(workload:Asset)
MATCH (workload)-[:ExposedToInternet]->(:Asset {id: 'internet'})
RETURN repo, f, role, x, workload
ORDER BY workload.score DESC
LIMIT 30`,
	},
	{
		Name:        "repo_package_dependencies",
		Description: "Repos and the packages they depend on (SBOM — DependsOn edges)",
		Params:      []string{},
		Query: `
MATCH (repo:Repo)-[d:DependsOn]->(pkg:Package)
RETURN repo, d, pkg
ORDER BY repo.name
LIMIT 50`,
	},
	// ── "Where is package X used?" ───────────────────────────────────────────
	//
	// A Package node has no outbound loaded edge — every edge that answers "where
	// is this used" points AT it — so it can't be reached via blast_radius from a
	// seed. These two queries take a package name directly.
	//
	// Both queries key on p.name (the ecosystem-qualified package name, e.g.
	// "@acme-corp/db-client"), not p.id, so one name covers every version.
	{
		Name:        "package_source_repos",
		Description: "Which repos pull in a package, by package name — the SBOM half of \"where is this package used\"",
		Params:      []string{"name"},
		Query: `
MATCH (repo:Repo)-[d:DependsOn]->(pkg:Package)
WHERE pkg.name = $name
RETURN repo, d, pkg
ORDER BY repo.name
LIMIT 100`,
	},
	{
		Name:        "package_running_workloads",
		Description: "Which live workloads (k8s pods, ECS services, Cloud Run services) run a package, by package name — the runtime half of \"where is this package used\" (workload -> image -> package)",
		Params:      []string{"name"},
		// Two explicit hops: workload -> image -> package. RunsImage is a loaded rel
		// precisely so this second hop exists: without it the chain stops at the
		// container_image and no query can name the pod.
		// RunsImageAsset is the same hop from an ECS / Cloud Run service; the
		// unlabelled w matches either source label.
		Query: `
MATCH (img:Asset)-[rp:RunsPackage]->(pkg:Package)
WHERE pkg.name = $name
MATCH (w)-[ri:RunsImage|RunsImageAsset]->(img)
RETURN w, ri, img, rp, pkg
ORDER BY w.score DESC
LIMIT 100`,
	},
	{
		Name:        "high_risk_package_dependents",
		Description: "Repos depending on packages that run on exposed high-risk assets",
		Params:      []string{},
		// RunsIn (Package->Asset) is never populated. Use RunsPackage (Asset->Package)
		// to find assets running a given package, then join to the repo via DependsOn.
		Query: `
MATCH (repo:Repo)-[:DependsOn]->(pkg:Package)
MATCH (app:Asset)-[:RunsPackage]->(pkg)
WHERE app.score >= 61 AND app.exposed = 1
RETURN repo, pkg, app
ORDER BY app.score DESC
LIMIT 30`,
	},

	// --- Cross-account / cross-provider attack paths ---

	{
		Name:        "cross_account_role_chains",
		Description: "IAM roles that can assume roles in different AWS accounts — lateral movement across account boundaries",
		Params:      []string{},
		Query: `
MATCH (a:IamRole)-[r:CanAssume]->(b:IamRole)
WHERE a.account_id <> b.account_id AND b.account_id <> ''
RETURN a, r, b
ORDER BY b.score DESC
LIMIT 50`,
	},
	{
		Name:        "workloads_with_kev_packages",
		Description: "Cloud assets running packages with known-exploited (KEV) vulnerabilities",
		Params:      []string{},
		// RunsIn (Package->Asset) is never populated. Use RunsPackage (Asset->Package)
		// to find assets that run a KEV-affected package.
		// Package.has_kev (INT32) is populated by SignalsByResource.
		Query: `
MATCH (app:Asset)-[r:RunsPackage]->(pkg:Package)
WHERE pkg.has_kev = 1
RETURN app, r, pkg
ORDER BY app.score DESC
LIMIT 50`,
	},
	{
		Name:        "shared_iam_identity",
		Description: "IAM roles executed by multiple workloads — compromising one workload compromises all",
		Params:      []string{},
		// A pairwise self-join (w1,w2 both -[:ExecutesAs|HasRole]->role, pair-enumerated
		// before LIMIT) exhausts Ladybug's buffer pool once a role has hundreds of
		// executors. Aggregate the executor list per role instead (linear cost),
		// filter/sort/limit on the aggregate, then unwind — no pairwise blowup.
		Query: `
MATCH (role:IamRole)<-[:ExecutesAs|HasRole]-(w:Asset)
WITH role, collect(w) AS workloads
WHERE size(workloads) > 1
WITH role, workloads
ORDER BY role.score DESC
LIMIT 30
UNWIND workloads AS w
RETURN role, w`,
	},

	// --- K8s attack paths ---

	{
		Name:        "k8s_internet_exposed_services",
		Description: "Kubernetes LoadBalancer/NodePort services directly reachable from the internet",
		Params:      []string{},
		Query: `
MATCH (svc:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE svc.type = 'k8s_service'
RETURN svc
ORDER BY svc.score DESC
LIMIT 50`,
	},
	{
		Name:        "k8s_service_to_workload",
		Description: "K8s services and the deployments/pods they target (selector match via AccessesK8sWorkload edge)",
		Params:      []string{},
		// k8s_deployment/k8s_pod live under the dedicated K8sWorkload label, not
		// Asset — the generic Accesses table is Asset->Asset and would silently
		// drop these. `workload` is typed :K8sWorkload directly (the label already
		// constrains the type, so no separate WHERE type filter is needed).
		Query: `
MATCH (svc:Asset)-[r:AccessesK8sWorkload]->(workload:K8sWorkload)
WHERE svc.type = 'k8s_service'
RETURN svc, r, workload
ORDER BY svc.score DESC
LIMIT 50`,
	},
	{
		Name:        "k8s_exposed_service_to_workload",
		Description: "Internet-exposed k8s services and the workloads they front — direct attack surface",
		Params:      []string{},
		// Same label/edge shape as "k8s_service_to_workload" above.
		Query: `
MATCH (svc:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (svc)-[r:AccessesK8sWorkload]->(workload:K8sWorkload)
WHERE svc.type = 'k8s_service'
RETURN svc, r, workload
ORDER BY svc.score DESC
LIMIT 50`,
	},

	// --- High-value targets ---

	{
		Name:        "high_risk_roles",
		Description: "IAM roles with risk score >= 80. Risk score ranks a role's findings, escalation paths and neighbouring risk, not the permissions it holds.",
		Params:      []string{},
		Query: `
MATCH (r:IamRole)
WHERE r.score >= 80
RETURN r
ORDER BY r.score DESC
LIMIT 50`,
	},
	{
		Name:        "repos_deploying_to_k8s",
		Description: "GitHub repos that deploy directly to Kubernetes — CI/CD pipeline to cluster attack surface",
		Params:      []string{},
		// DeploysTo is FROM Repo TO K8sWorkload (schema.go), never generic Asset.
		// k8s_service is dropped from the type filter: it's NOT in
		// graphstore.assetTypeToNode's K8sWorkload mapping, so it can never appear
		// as a DeploysTo destination.
		Query: `
MATCH (repo:Repo)-[d:DeploysTo]->(app:K8sWorkload)
WHERE app.type IN ['k8s_deployment', 'k8s_pod']
RETURN repo, d, app
ORDER BY app.score DESC
LIMIT 50`,
	},
	{
		Name:        "databases_reachable_from_internet",
		Description: "Databases and caches whose security group admits an internet-exposed asset's security group (self-references included) — lateral movement into datastores. Only security-group-referencing rules are modelled: a CIDR rule covering the entry's private address is not.",
		Params:      []string{},
		Query: `
MATCH (entry:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (entry)-[:ConnectedViaSG]->(src:Asset)
MATCH (dst:Asset)-[a:AllowsFrom]->(src)
MATCH (db:Asset)-[:ConnectedViaSG]->(dst)
WHERE db.id <> entry.id
  AND db.type IN ['rds_instance', 'elasticache_cluster', 'redshift_cluster']
RETURN entry, src, a, dst, db
ORDER BY db.score DESC
LIMIT 40`,
	},
	{
		Name:        "gcp_oidc_federation",
		Description: "GitHub repos with GCP Workload Identity Federation — CI/CD direct to GCP",
		Params:      []string{},
		Query: `
MATCH (repo:Repo)-[f:FederatedAccess]->(sa:IamRole)
WHERE sa.type = 'gcp_service_account' OR sa.provider = 'gcp'
RETURN repo, f, sa
ORDER BY sa.score DESC
LIMIT 50`,
	},

	// --- graph-unique high-value attack path queries ---

	{
		Name:        "repos_deploying_to_exposed_assets",
		Description: "Source repos that deploy directly to internet-exposed K8s workloads",
		Params:      []string{},
		// exposed is INT32 — use = 1 not = true.
		// DeploysTo is FROM Repo TO K8sWorkload (schema.go), not generic Asset.
		Query: `
MATCH (r:Repo)-[:DeploysTo]->(w:K8sWorkload)
WHERE w.exposed = 1
RETURN r, w
LIMIT 25`,
	},
	{
		Name:        "org_exposed_assets",
		Description: "Internet-exposed assets owned by a specific GitHub org — all deploy paths (K8s workloads + direct services)",
		Params:      []string{"org"},
		// $org is the GitHub org prefix, e.g. "acme-corp" — the "org/repo" form lives on
		// Repo.id, NOT Repo.name (Repo.name is the bare repo name, e.g. "api-service").
		// exposed is INT32 — use = 1 not = true.
		Query: `
MATCH (r:Repo)-[:DeploysTo]->(w:K8sWorkload)
WHERE r.id STARTS WITH $org
  AND w.exposed = 1
RETURN r, w
ORDER BY w.score DESC
LIMIT 50`,
	},
	{
		Name:        "iac_orphan_lbs",
		Description: "Internet-exposed load balancers not deployed-to by any source repo — no IaC ownership, potential dead weight",
		Params:      []string{},
		// DeploysToService is Repo→Asset. An LB with no incoming DeploysToService edge has no
		// repo claiming ownership. Combined with internet exposure this is a hygiene signal:
		// either a forgotten LB (cost + attack surface) or one managed outside of tracked IaC.
		// NOT patterns use typed :Asset / :Repo endpoints so each names exactly one rel table.
		Query: `
MATCH (lb:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE lb.type IN ['load_balancer', 'gcp_forwarding_rule', 'network_load_balancer']
  AND NOT (:Repo)-[:DeploysToService]->(lb)
RETURN lb
ORDER BY lb.score DESC
LIMIT 50`,
	},
	{
		Name:        "github_oidc_high_risk_chain",
		Description: "GitHub repos with OIDC access to a role that can assume a high-risk role (risk score >= 60, 2-hop)",
		Params:      []string{},
		// Two explicit MATCH hops — no variable-length path, no multi-label edge return.
		Query: `
MATCH (repo:Repo)-[:FederatedAccess]->(role:IamRole)
MATCH (role)-[:CanAssume]->(target:IamRole)
WHERE target.score >= 60
RETURN repo, role, target
LIMIT 25`,
	},
	{
		Name:        "exposed_assets_with_high_risk_roles",
		Description: "Internet-exposed assets executing as high-risk IAM roles (risk score >= 70)",
		Params:      []string{},
		// exposed (INT32). ExecutesAs and HasRole are Asset->IamRole.
		Query: `
MATCH (a:Asset)-[:ExecutesAs|HasRole]->(r:IamRole)
WHERE a.exposed = 1 AND r.score >= 70
RETURN a, r
LIMIT 30`,
	},
	{
		Name:        "two_hop_privesc_from_internet",
		Description: "2-hop escalation chain: internet entry point -> IAM role -> high-risk role (risk score >= 70)",
		Params:      []string{},
		// Three explicit MATCH hops. No variable-length paths — each hop is a
		// separate MATCH statement.
		Query: `
MATCH (entry:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (entry)-[:ExecutesAs|HasRole]->(role:IamRole)
MATCH (role)-[:CanAssume]->(target:IamRole)
WHERE target.score >= 70
RETURN entry, role, target
LIMIT 25`,
	},

	// --- graph-unique queries (attack-path correlation no generic asset-
	// inventory tool without a native graph engine can express) ---
	// These leverage the enriched risk scores, SBOM, KEV signals, and multi-cloud
	// correlation that flat per-account asset lists cannot express.

	{
		Name:        "prioritised_scan_targets",
		Description: "Internet-exposed assets ranked by risk score instead of blind 'scan everything'",
		Params:      []string{},
		// This query orders by enriched risk score so the highest-blast-radius,
		// KEV-affected, publicly-exploited assets get scanned first, rather than
		// scanning all exposed assets in flat per-account lists.
		Query: `
MATCH (a:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE a.score > 0
RETURN a
ORDER BY a.score DESC
LIMIT 100`,
	},
	{
		Name:        "unprotected_internet_facing_lbs",
		Description: "Load balancers and forwarding rules exposed to the internet with no security group or firewall protection",
		Params:      []string{},
		// We detect this by checking for absence of ConnectedViaSG/ProtectedBy outbound edges —
		// works for both AWS (SG) and GCP (firewall tag) in one query.
		// NOT patterns use a typed :Asset destination so each names exactly one rel table.
		Query: `
MATCH (lb:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE lb.type IN ['load_balancer', 'gcp_forwarding_rule']
  AND NOT (lb)-[:ConnectedViaSG]->(:Asset)
  AND NOT (lb)-[:ProtectedBy]->(:Asset)
RETURN lb
ORDER BY lb.score DESC
LIMIT 50`,
	},
	{
		Name:        "zombie_lbs",
		Description: "Zombie load balancers: DNS resolves to them, internet-exposed, but no IaC repo owns them and no SG/firewall protection — scan-only traffic pattern",
		Params:      []string{},
		// Four-signal zombie pattern (any one is suspicious; all four together = almost certainly dead):
		//   1. DnsPointsTo: a DNS record resolves to this LB — it is reachable by name
		//   2. ExposedToInternet: the LB accepts inbound traffic from the internet node
		//   3. NOT DeploysToService inbound: no tracked repo deploys to it — no IaC owner
		//   4. NOT ConnectedViaSG/ProtectedBy outbound: no SG or cert attached
		// Legitimate LBs normally have at minimum a repo and a security group. Zombies have DNS
		// but no owner — they sit collecting scanner probes, not legitimate requests.
		// NOT patterns use typed :Asset/:Repo endpoints so each names exactly one rel table.
		Query: `
MATCH (dns:Asset)-[:DnsPointsTo]->(lb:Asset)
MATCH (lb)-[:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE lb.type IN ['load_balancer', 'gcp_forwarding_rule', 'network_load_balancer']
  AND NOT (:Repo)-[:DeploysToService]->(lb)
  AND NOT (lb)-[:ConnectedViaSG]->(:Asset)
  AND NOT (lb)-[:ProtectedBy]->(:Asset)
RETURN dns, lb
ORDER BY lb.score DESC
LIMIT 50`,
	},
	{
		Name:        "kev_packages_on_exposed_assets",
		Description: "Packages with CISA KEV CVEs running on internet-exposed assets, joined via our SBOM data",
		Params:      []string{},
		// Accesses is Asset->Asset only — Package cannot be its source.
		// RunsPackage (Asset->Package) is the correct rel for asset-to-package traversal.
		// Package.has_kev (INT32) is populated by supply-chain feeds.
		Query: `
MATCH (app:Asset)-[:RunsPackage]->(pkg:Package)
MATCH (app)-[:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE pkg.has_kev = 1
RETURN app, pkg
ORDER BY app.score DESC
LIMIT 50`,
	},
	{
		Name:        "expiring_certs_on_exposed_services",
		Description: "TLS certificates expiring within 14 days",
		Params:      []string{},
		// No collector ever emits a service->cert edge — ProtectedBy is exclusively
		// instance-protected-by-firewall, never cert-protects-service. Certs stand
		// alone as Asset nodes with their own expiring_soon/days_until_expiry — query
		// those directly instead of joining through a relationship that doesn't exist.
		Query: `
MATCH (cert:Asset)
WHERE cert.type IN ['k8s_certificate', 'acm_certificate', 'gcp_ssl_certificate']
  AND cert.days_until_expiry <= 14
  AND cert.days_until_expiry >= 0
RETURN cert
ORDER BY cert.days_until_expiry ASC
LIMIT 50`,
	},
	{
		Name:        "oidc_to_secret_attack_path",
		Description: "GitHub repos that can access GCP secrets via OIDC federation — full CI/CD to secret exfiltration path",
		Params:      []string{},
		// Requires AccessesSecret edges from GCP secret IAM collector.
		// Cross-domain path: GitHub Actions -> GCP service account -> secret.
		// This OIDC->SA->secret chain requires native graph traversal to express.
		// Two explicit MATCH hops (not chained) — consistent with every other multi-hop query here.
		Query: `
MATCH (repo:Repo)-[f:FederatedAccess]->(sa:IamRole)
MATCH (sa)-[s:AccessesSecret]->(sec:Asset)
WHERE sec.type = 'gcp_secret'
RETURN repo, f, sa, s, sec
ORDER BY sa.score DESC
LIMIT 50`,
	},
	{
		Name:        "cross_cloud_iam_lateral_movement",
		Description: "AWS Lambdas whose IAM role can assume a GCP service account — cross-cloud lateral movement path",
		Params:      []string{},
		Query: `
MATCH (workload:Asset)-[:ExecutesAs]->(awsRole:IamRole)
MATCH (awsRole)-[:CanAssume]->(gcpSA:IamRole)
WHERE workload.provider = 'aws'
  AND workload.type = 'lambda_function'
  AND gcpSA.provider = 'gcp'
RETURN workload, awsRole, gcpSA
ORDER BY gcpSA.score DESC
LIMIT 30`,
	},

	// ── Attack Chains ─────────────────────────────────────────────────────────
	// Multi-hop traversal queries that express full end-to-end attacker paths.
	// All use explicit MATCH chains, one MATCH per hop.

	{
		Name:        "full_blast_radius_3hop",
		Description: "3-hop blast radius from a seed asset: all nodes reachable via three explicit outbound hops",
		Params:      []string{"id"},
		// Go-orchestrated like "blast_radius" above (same blastRadiusGraph,
		// hops=3) — the Query string below is documentation only, not
		// executed. See "blast_radius"'s comment for why.
		// Three explicit MATCH hops over the populated Asset outbound rel types.
		// $id is substituted by substituteParams before execution.
		Query: `
MATCH (seed:Asset {id: $id})-[r1:ExecutesAs|HasRole|Accesses|DnsPointsTo|ProtectedBy|Binds]->(hop1:Asset)
MATCH (hop1)-[r2:ExecutesAs|HasRole|Accesses|DnsPointsTo|ProtectedBy|Binds]->(hop2:Asset)
MATCH (hop2)-[r3:ExecutesAs|HasRole|Accesses|DnsPointsTo|ProtectedBy|Binds]->(hop3:Asset)
RETURN seed, r1, hop1, r2, hop2, r3, hop3
LIMIT 100`,
	},
	{
		Name:        "internet_to_high_risk_role_3hop",
		Description: "Attack chain: internet-exposed asset → the IAM role it executes as → a high-risk role (risk score >= 70) that role can assume",
		Params:      []string{},
		// Three explicit MATCH hops: internet → exposed entry → its execution role → target.
		Query: `
MATCH (entry:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (entry)-[r1:ExecutesAs|HasRole]->(role:IamRole)
MATCH (role)-[r2:CanAssume]->(target:IamRole)
WHERE target.score >= 70
RETURN entry, r1, role, r2, target
ORDER BY target.score DESC
LIMIT 25`,
	},
	{
		Name:        "supply_chain_risk",
		Description: "Repos that deploy to internet-exposed k8s workloads (supply chain compromise path)",
		Params:      []string{},
		// Repo → DeploysTo → K8sWorkload WHERE exposed = 1.
		// exposed is INT32 — use = 1 not = true.
		// DeploysTo is Repo→K8sWorkload; no multi-hop variable-length path needed.
		// Returns the repo and the exposed workload for graph rendering.
		Query: `
MATCH (repo:Repo)-[d:DeploysTo]->(asset:K8sWorkload)
WHERE asset.exposed = 1
RETURN repo, d, asset
ORDER BY asset.score DESC
LIMIT 30`,
	},
	{
		Name:        "github_to_k8s_to_exposed",
		Description: "GitHub repos -> deploy -> k8s workload -> internet-exposed service (full CI/CD supply chain blast path)",
		Params:      []string{},
		// Three-hop path requiring native graph traversal: source repo -> what it deploys -> what exposes it.
		// Useful for: 'if this repo is compromised, what internet-facing services are affected?'
		// The svc-selector-match hop uses AccessesK8sWorkload (Asset->K8sWorkload),
		// not the generic Accesses (Asset->Asset), which would drop every
		// k8s_deployment/k8s_pod destination. app is typed :K8sWorkload directly
		// (DeploysTo's dst; the label already constrains type).
		Query: `
MATCH (repo:Repo)-[:DeploysTo]->(app:K8sWorkload)
MATCH (svc:Asset)-[:AccessesK8sWorkload]->(app)
MATCH (svc)-[:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE svc.type = 'k8s_service'
RETURN repo, app, svc
ORDER BY svc.score DESC
LIMIT 30`,
	},
	{
		Name:        "high_blast_radius_exposed",
		Description: "Internet-exposed assets and the assets one hop downstream of them, highest-risk entries first",
		Params:      []string{},
		// Enumerates explicit outbound rel types instead of untyped (entry)-[]->(reached)
		// so only the intended rels count as "downstream". InVPC, ConnectedViaSG,
		// AllowsFrom and AccessesK8sWorkload are deliberately excluded: InVPC's
		// destination types are all NeverSyncTypes so the table is always empty;
		// ConnectedViaSG is SG membership and AllowsFrom points against attacker
		// movement (see lateral_movement_via_sg for the security-group path); and
		// AccessesK8sWorkload's destination is K8sWorkload-labeled, so it can never
		// bind against `reached:Asset`.
		// ORDER BY uses the entry's score directly, not a per-entry blast count.
		Query: `
MATCH (entry:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (entry)-[:ExecutesAs|HasRole|Accesses|DnsPointsTo|ProtectedBy|Binds]->(reached:Asset)
RETURN entry, reached
ORDER BY entry.score DESC
LIMIT 30`,
	},
	{
		Name:        "blast_radius_deep",
		Description: "Internet-exposed assets ranked by how many nodes they reach within 3 hops of attacker movement",
		Params:      []string{},
		// The movement rels are the set the former blast_radius_count function
		// walked (Asset hops plus IamRole CanAssume/CanEscalateTo/AccessesSecret),
		// minus ExposedToInternet, whose only destination is the internet sentinel,
		// InVPC, which is never loaded, and AllowsFrom, which an attacker moves
		// against (a one-direction path cannot follow it).
		Query: `
MATCH (n:Asset)
WHERE n.exposed = 1
MATCH (n)-[:ExecutesAs|HasRole|ConnectedViaSG|DnsPointsTo|ProtectedBy|RunsPackage|RunsImage|Binds|Accesses|CanAssume|CanEscalateTo|AccessesSecret*1..3]->(m)
WITH n, count(DISTINCT m) AS reach
RETURN n
ORDER BY reach DESC, n.id
LIMIT 20`,
	},
	{
		Name:        "attack_path_check",
		Description: "Shortest attacker-movement path (up to 4 hops) from one node to another, by ID — empty when none exists",
		Params:      []string{"src_id", "dst_id"},
		Query: `
MATCH p = (src {id: $src_id})-[:ExposedToInternet|ExecutesAs|HasRole|ConnectedViaSG|DnsPointsTo|ProtectedBy|RunsPackage|RunsImage|Binds|Accesses|CanAssume|CanEscalateTo|AccessesSecret* SHORTEST 1..4]->(dst {id: $dst_id})
RETURN p`,
	},
	{
		Name:        "internet_exposed_assets",
		Description: "Internet-exposed assets, highest risk first",
		Params:      []string{},
		// exposed (INT32) — use = 1 not = true.
		Query: `
MATCH (n:Asset)
WHERE n.exposed = 1
RETURN n
ORDER BY n.score DESC
LIMIT 30`,
	},
	{
		Name:        "sensitive_data_exposed",
		Description: "DSPM toxic combination: internet-exposed or public data stores holding sensitive data (PII/PCI/health/financial/credentials)",
		Params:      []string{},
		Query: `
MATCH (a:Asset)-[r:ContainsData]->(dc:DataClass)
WHERE dc.id <> 'dataclass:internal' AND (a.exposed = 1 OR a.public = 1)
RETURN a, r, dc
ORDER BY a.score DESC
LIMIT 100`,
	},
	{
		Name:        "unencrypted_sensitive_data",
		Description: "DSPM: sensitive data stores with no encryption-at-rest — data exposure if the storage layer is compromised",
		Params:      []string{},
		Query: `
MATCH (a:Asset)-[r:ContainsData]->(dc:DataClass)
WHERE dc.id <> 'dataclass:internal' AND a.encrypted = 0
RETURN a, r, dc
ORDER BY a.score DESC
LIMIT 100`,
	},
	{
		Name:        "sensitive_data_reachable_by_escalating_role",
		Description: "DSPM data attack path: a role that can escalate to a high-risk role (risk score >= 60) also holds access to a secret store with sensitive data",
		Params:      []string{},
		Query: `
MATCH (role:IamRole)-[a:AccessesSecret]->(store:Asset)
MATCH (store)-[c:ContainsData]->(dc:DataClass)
MATCH (role)-[e:CanEscalateTo]->(target:IamRole)
WHERE dc.id <> 'dataclass:internal' AND target.score >= 60
RETURN role, a, store, c, dc, e, target
ORDER BY target.score DESC
LIMIT 50`,
	},
}
