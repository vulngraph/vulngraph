// The graph query library — the single catalogue of canned queries the Explore
// page offers. Two flavours:
//
//   • PresetQuery  — a structured GraphQuerySpec run via POST /api/graph/query
//                    (safe, bounded; no Cypher knowledge needed).
//   • CypherExample — a raw read-only Cypher snippet that populates the console
//                     (POST /api/graph/cypher).
//
// Cypher examples RETURN nodes + relationships (e.g. `RETURN n, r, m`) so the
// result renders as a graph, not a scalar table. Node labels (Asset, IamRole,
// Repo, Package) and relationship types mirror the Ladybug schema DDL in
// internal/app/graphstore/repo.go — keep them in sync.
//
// QUERY CONSTRAINTS (LadybugDB v0.21.2, ADR 095) — keep in sync with the named
// queries in internal/app/graphstore/named_queries.go:
//   - Read-only Cypher only; the API's read-only guard rejects writes.
//   - Boolean flags (exposed, has_kev, exploitable, toxic_combo) are INT32 —
//     compare with = 1, never = true or a bare boolean.
//   - Labels that are Cypher reserved words (e.g. Group) need backticks:
//     (:`Group`). See graphstore schema.go cypherReservedLabels.
//   - Prefer the (:Asset)-[:ExposedToInternet]->({id:'internet'}) edge pattern
//     over filtering on the `exposed` property: the edge is the computed
//     reachability verdict.
//   - There is no SecurityGroup node label — use (:Asset {type: 'security_group'}).
//   - RETURN node/relationship objects for graph shape, OR an aggregate
//     (count/sum/avg AS alias) for a scalar/table result — execCypher maps both.
//   - NOT loaded into Ladybug (ladybugRelSpec in copy_load.go): AllowsAction,
//     HasPolicy, PeeredWith, RunsImage, InSubnet, MemberOfZone, Owns, RunsIn.
//     A preset traversing any of these renders EMPTY — those edges live only in
//     ClickHouse. Do not add presets for them. (ContainsData IS loaded.)
//   - Use RunsPackage (Asset->Package) for asset-to-package traversals; runs_in
//     rows map to Accesses, which is Asset->Asset only.
//   - ProtectedBy is (compute/LB:Asset)-[:ProtectedBy]->(sg:Asset). No collector
//     links a service to the certificate it serves.
//   - Exposed K8s workloads use ExposedToInternetK8sWorkload (src :K8sWorkload),
//     not ExposedToInternet (src :Asset).

import type { GraphQuerySpec } from "./api";
import { SCORE_THRESHOLDS } from "./format";

// Node labels called out in the schema-constraints comment above — the same
// vocabulary the Ladybug DDL (repo.go) exposes. Kept as a real array (not just
// prose) so the editor and NLQBar can eventually share one source of truth
// for autocomplete. Not wired to autocomplete yet.
export const NODE_LABELS: string[] = ["Asset", "IamRole", "Repo", "Package"];

export type PresetQuery = {
  id: string;
  label: string;
  desc: string;
  icon: string;
  spec: GraphQuerySpec;
};

export type CypherExample = {
  id: string;
  label: string;
  desc: string;
  cypher: string;
  category: string; // groups the example in the console library
};

export type PresetCategory = {
  name: string;
  presets: PresetQuery[];
};

// PRESET_CATEGORIES groups the structured presets by the security question they
// answer. Rendered as a compact grouped menu (not 30 buttons in a row).
export const PRESET_CATEGORIES: PresetCategory[] = [
  {
    name: "Exposure",
    presets: [
      {
        id: "internet-exposed",
        label: "Internet exposed",
        desc: "Public-facing assets and what sits behind them",
        icon: "📡",
        spec: { seed: { types: ["load_balancer", "gcs_bucket", "s3_bucket"] }, traverse: [{ max_hops: 1 }], max_nodes: 300 },
      },
      {
        id: "dns",
        label: "DNS targets",
        desc: "DNS records and what they resolve to",
        icon: "🔍",
        spec: { seed: { types: ["dns_record"] }, traverse: [{ max_hops: 1 }], max_nodes: 300 },
      },
    ],
  },
  {
    name: "Identity & privilege",
    presets: [
      {
        id: "iam",
        label: "IAM roles",
        desc: "Roles and what can assume them",
        icon: "🔑",
        spec: { seed: { types: ["iam_role"] }, traverse: [{ max_hops: 1 }], max_nodes: 300 },
      },
    ],
  },
  {
    name: "Network",
    presets: [
      {
        id: "aws-network",
        label: "AWS network",
        desc: "EC2 instances → security groups → subnets",
        icon: "🌐",
        spec: { seed: { types: ["ec2_instance"] }, traverse: [{ max_hops: 2 }], max_nodes: 300 },
      },
      {
        id: "gcp-network",
        label: "GCP network",
        desc: "GCE instances → VPC networks",
        icon: "☁",
        spec: { seed: { types: ["gce_instance"] }, traverse: [{ max_hops: 2 }], max_nodes: 300 },
      },
      {
        id: "k8s-topology",
        label: "K8s services",
        desc: "Services and the workloads behind them",
        icon: "☸",
        // k8s_namespace is in asset.NeverSyncTypes (pure topology, excluded at the SQL
        // fetch level) so it can never exist as a Ladybug node — this seed could never
        // return a single row. k8s_service is the closest real, populated seed to
        // "K8s services".
        spec: { seed: { types: ["k8s_service"] }, traverse: [{ max_hops: 2 }], max_nodes: 300 },
      },
      {
        id: "k8s-exposed",
        label: "Exposed K8s services",
        desc: "LoadBalancer/NodePort services reachable from internet",
        icon: "🔓",
        spec: { seed: { types: ["k8s_service"] }, traverse: [{ edge_types: ["ExposedToInternet"], max_hops: 1 }], max_nodes: 200 },
      },
    ],
  },
];

// ALL_PRESETS flattens the categories for lookup by id (the active-preset state).
export const ALL_PRESETS: PresetQuery[] = PRESET_CATEGORIES.flatMap((c) => c.presets);

// CYPHER_EXAMPLES populate the console's example chips.
//
// Curated to queries that obey the Ladybug constraints above and need no
// placeholder ids. Whether a given example returns rows depends on which
// collectors and signals are populated in your deployment.
//
// Each RETURNs node + rel objects so execCypher maps them to the graph view.
export const CYPHER_EXAMPLES: CypherExample[] = [
  // ── Internet exposure ─────────────────────────────────────────────────────
  {
    id: "exposed-high-risk",
    label: "High-risk exposed",
    desc: `Internet-facing assets with score ≥ ${SCORE_THRESHOLDS.high} — your highest-priority attack surface`,
    category: "Internet exposure",
    cypher: `MATCH (a:Asset)-[e:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE a.score >= ${SCORE_THRESHOLDS.high}
RETURN a, e
ORDER BY a.score DESC
LIMIT 50`,
  },
  {
    id: "all-exposed",
    label: "All internet-exposed",
    desc: "Every asset reachable from the internet — your complete external footprint",
    category: "Internet exposure",
    cypher: `MATCH (a:Asset)-[e:ExposedToInternet]->(:Asset {id: 'internet'})
RETURN a, e
ORDER BY a.score DESC
LIMIT 50`,
  },
  {
    id: "exposed-with-privesc-role",
    label: "Exposed → high-risk role",
    desc: "Internet-facing assets running as high-risk IAM roles — the most dangerous combination",
    category: "Internet exposure",
    cypher: `MATCH (a:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (a)-[r:ExecutesAs|HasRole]->(role:IamRole)
WHERE role.score >= 70
RETURN a, r, role
ORDER BY role.score DESC
LIMIT 30`,
  },

  // ── IAM privilege escalation ──────────────────────────────────────────────
  {
    id: "ciem-escalation",
    label: "CIEM escalation paths",
    desc: "Permission-based escalation: CreatePolicyVersion, PassRole, SSM SendCommand, and 60+ more CIEM techniques",
    category: "IAM / Privilege escalation",
    cypher: `MATCH (a:IamRole)-[r:CanEscalateTo]->(b:IamRole)
RETURN a, r, b
ORDER BY b.score DESC
LIMIT 50`,
  },
  {
    id: "ciem-full-chain",
    label: "CIEM + CanAssume chain",
    desc: "Workloads whose role can escalate to or assume another role via CIEM escalation or trust-policy assumption — highest-risk target first",
    category: "IAM / Privilege escalation",
    cypher: `MATCH (w:Asset)-[r1:ExecutesAs|HasRole]->(role:IamRole)
MATCH (role)-[r2:CanEscalateTo|CanAssume]->(target:IamRole)
RETURN w, r1, role, r2, target
ORDER BY target.score DESC
LIMIT 30`,
  },
  {
    id: "privesc-chains",
    label: "CanAssume chains",
    desc: "IAM trust policy chains — one role using another as a lateral-movement launchpad",
    category: "IAM / Privilege escalation",
    cypher: `MATCH (a:IamRole)-[r:CanAssume]->(b:IamRole)
RETURN a, r, b
ORDER BY b.score DESC
LIMIT 50`,
  },
  {
    id: "cross-account-chains",
    label: "Cross-account escalation",
    desc: "Roles assuming other-account roles — trust boundaries crossed across AWS accounts",
    category: "IAM / Privilege escalation",
    cypher: `MATCH (a:IamRole)-[r:CanAssume]->(b:IamRole)
WHERE a.account_id <> b.account_id AND b.account_id <> ''
RETURN a, r, b
ORDER BY b.score DESC
LIMIT 50`,
  },
  {
    id: "workload-roles",
    label: "Workloads as IAM roles",
    desc: "Compute, containers, and serverless running as IAM roles — the machine identity surface",
    category: "IAM / Privilege escalation",
    cypher: `MATCH (a:Asset)-[r:ExecutesAs|HasRole]->(role:IamRole)
RETURN a, r, role
ORDER BY role.score DESC
LIMIT 50`,
  },
  {
    id: "high-risk-roles",
    label: "High-risk roles",
    desc: `IAM roles with risk score ≥ ${SCORE_THRESHOLDS.page} — ranked by findings, escalation paths and neighbouring risk, not by the permissions they hold`,
    category: "IAM / Privilege escalation",
    cypher: `MATCH (r:IamRole)
WHERE r.score >= ${SCORE_THRESHOLDS.page}
RETURN r
ORDER BY r.score DESC
LIMIT 50`,
  },
  {
    id: "shared-iam-identity",
    label: "Shared IAM identity",
    desc: "IAM roles used by more than one workload — compromise one, you own everything sharing it",
    category: "IAM / Privilege escalation",
    // A pairwise self-join (w1,w2 both -[:ExecutesAs|HasRole]->role) enumerates every
    // (executor, executor) pair before LIMIT applies — on a role with hundreds
    // of executors that cross-product exhausts Ladybug's
    // buffer pool. Aggregate the executor list per role instead (linear, no
    // pairwise blowup), filter/sort/limit on the aggregate, then unwind.
    cypher: `MATCH (role:IamRole)<-[:ExecutesAs|HasRole]-(w:Asset)
WITH role, collect(w) AS workloads
WHERE size(workloads) > 1
WITH role, workloads
ORDER BY role.score DESC
LIMIT 30
UNWIND workloads AS w
RETURN role, w`,
  },

  // ── OIDC / CI-CD attack paths ─────────────────────────────────────────────
  {
    id: "repo-cloud-access",
    label: "Repos with cloud access",
    desc: "GitHub Actions and CI/CD pipelines that can assume cloud roles via OIDC federation",
    category: "OIDC / CI-CD",
    cypher: `MATCH (repo:Repo)-[f:FederatedAccess]->(role:IamRole)
RETURN repo, f, role
ORDER BY role.score DESC
LIMIT 50`,
  },
  {
    id: "gcp-oidc",
    label: "GCP Workload Identity",
    desc: "Repos federating into GCP service accounts via Workload Identity Federation",
    category: "OIDC / CI-CD",
    cypher: `MATCH (repo:Repo)-[f:FederatedAccess]->(sa:IamRole)
WHERE sa.type = 'gcp_service_account' OR sa.provider = 'gcp'
RETURN repo, f, sa
ORDER BY sa.score DESC
LIMIT 50`,
  },
  {
    id: "repos-ci-assumes-roles",
    label: "Repos → roles their CI assumes",
    desc: "GitHub Actions workflows that assume AWS roles / GCP SAs, from workflow config (not just trust policies)",
    category: "OIDC / CI-CD",
    cypher: `MATCH (r:Repo)-[e:FederatedAccess]->(role:IamRole)
WHERE e.provenance IN ['gh_workflow', 'gh_workflow+live']
RETURN r.name AS repo, role.name AS role, e.provenance AS source
ORDER BY repo LIMIT 200`,
  },
  {
    id: "oidc-escalation-chain",
    label: "OIDC → role → escalation target",
    desc: "CI/CD pipelines whose role can escalate to or assume another role — via permission-based escalation (PassRole/AssumeRole) or trust-policy assumption — highest-risk target first",
    category: "OIDC / CI-CD",
    cypher: `MATCH (repo:Repo)-[f:FederatedAccess]->(role:IamRole)
MATCH (role)-[c:CanEscalateTo|CanAssume]->(target:IamRole)
RETURN repo, f, role, c, target
ORDER BY target.score DESC
LIMIT 30`,
  },

  // ── Full attack chains ─────────────────────────────────────────────────────
  {
    id: "internet-to-escalation",
    label: "Internet → workload → IAM → escalation target",
    desc: "End-to-end attack path: internet entry point through an IAM role that can escalate to or assume another role — highest-risk target first",
    category: "Attack chains",
    cypher: `MATCH (entry:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (entry)-[r1:ExecutesAs|HasRole]->(role:IamRole)
MATCH (role)-[r2:CanEscalateTo|CanAssume]->(target:IamRole)
RETURN entry, r1, role, r2, target
ORDER BY target.score DESC
LIMIT 25`,
  },
  {
    id: "sg-lateral",
    label: "Exposed → datastores via SG",
    desc: "Internet-exposed assets whose security group a database's or cache's security group admits",
    category: "Attack chains",
    // Sharing a security group is not a network path: the target's SG must
    // admit the entry's SG. AllowsFrom runs permitting SG → admitted SG, and is
    // a self-loop when an SG admits its own members.
    cypher: `MATCH (entry:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (entry)-[c1:ConnectedViaSG]->(src:Asset)
MATCH (dst:Asset)-[a:AllowsFrom]->(src)
MATCH (db:Asset)-[c2:ConnectedViaSG]->(dst)
WHERE db.id <> entry.id AND db.type IN ['rds_instance', 'elasticache_cluster', 'redshift_cluster']
RETURN entry, c1, src, a, dst, c2, db
ORDER BY db.score DESC
LIMIT 40`,
  },
  {
    id: "highest-blast-radius",
    label: "Widest blast radius",
    desc: "Internet-facing assets with the most reachable neighbours — biggest impact if compromised",
    category: "Attack chains",
    cypher: `MATCH (entry:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (entry)-[r:ConnectedViaSG|ExecutesAs|HasRole|Accesses|DnsPointsTo|ProtectedBy|Binds]->(reached)
RETURN entry, r, reached
ORDER BY entry.score DESC
LIMIT 30`,
  },

  // ── Supply chain / Deployments ───────────────────────────────────────────
  {
    id: "repos-deploying-to-exposed-k8s",
    label: "Repos → exposed K8s",
    desc: "GitHub repos deploying directly to internet-exposed Kubernetes workloads",
    category: "Supply chain",
    cypher: `MATCH (r:Repo)-[d:DeploysTo]->(w:K8sWorkload)
MATCH (w)-[:ExposedToInternetK8sWorkload]->(:Asset {id: 'internet'})
RETURN r, d, w
ORDER BY w.score DESC
LIMIT 40`,
  },
  {
    id: "repos-deploying-to-exposed-services",
    label: "Repos → exposed services",
    desc: "Repos deploying to internet-exposed ECS, Lambda, or Cloud Run services",
    category: "Supply chain",
    cypher: `MATCH (r:Repo)-[d:DeploysToService]->(s:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
RETURN r, d, s
ORDER BY s.score DESC
LIMIT 40`,
  },
  {
    id: "supply-chain-full-attack-chain",
    label: "Full supply chain chain",
    desc: "Repo → deploy → exposed workload → IAM role — the complete supply chain attack surface",
    category: "Supply chain",
    cypher: `MATCH (repo:Repo)-[d:DeploysTo]->(w:K8sWorkload)-[x:ExecutesAsK8sWorkload]->(role:IamRole)
RETURN repo, d, w, x, role
ORDER BY role.score DESC
LIMIT 30`,
  },
  {
    id: "repos-with-cloud-access-all",
    label: "Repos with IAM exposure",
    desc: "All repos with IAM role exposure via deployment pipelines",
    category: "Supply chain",
    cypher: `MATCH (r:Repo)-[:DeploysTo]->(w:K8sWorkload)
MATCH (w)-[:ExecutesAsK8sWorkload]->(role:IamRole)
RETURN r, w, role
ORDER BY role.score DESC
LIMIT 40`,
  },

  // ── K8s security ─────────────────────────────────────────────────────────
  {
    id: "k8s-internet-exposed-services",
    label: "Exposed K8s services",
    desc: "LoadBalancer and Ingress services directly reachable from the internet",
    category: "Kubernetes",
    cypher: `MATCH (svc:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE svc.type IN ['k8s_service', 'k8s_ingress']
RETURN svc
ORDER BY svc.score DESC
LIMIT 40`,
  },
  {
    id: "k8s-workloads-with-iam",
    label: "K8s workloads → IAM roles",
    desc: "Pods and deployments running as cloud IAM roles via IRSA or Workload Identity",
    category: "Kubernetes",
    cypher: `MATCH (w:K8sWorkload)-[e:ExecutesAsK8sWorkload]->(role:IamRole)
RETURN w, e, role
ORDER BY role.score DESC
LIMIT 50`,
  },
  {
    id: "k8s-exposed-workload-to-iam-escalation",
    label: "Exposed K8s → IAM escalation",
    desc: "Exposed pods whose cloud role can escalate to or assume another role — highest-risk target first",
    category: "Kubernetes",
    cypher: `MATCH (w:K8sWorkload)-[:ExecutesAsK8sWorkload]->(role:IamRole)
MATCH (role)-[:CanEscalateTo|CanAssume]->(target:IamRole)
MATCH (w)-[:ExposedToInternetK8sWorkload]->(:Asset {id: 'internet'})
RETURN w, role, target
ORDER BY target.score DESC
LIMIT 30`,
  },

  // ── Data / DSPM ───────────────────────────────────────────────────────────
  {
    id: "exposed-databases",
    label: "Databases reachable from internet",
    desc: "Databases whose security group admits an internet-exposed asset's security group",
    category: "Data",
    // Sharing a security group is not a network path: the target's SG must
    // admit the entry's SG. AllowsFrom runs permitting SG → admitted SG, and is
    // a self-loop when an SG admits its own members.
    cypher: `MATCH (entry:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (entry)-[c1:ConnectedViaSG]->(src:Asset)
MATCH (dst:Asset)-[a:AllowsFrom]->(src)
MATCH (db:Asset)-[c2:ConnectedViaSG]->(dst)
WHERE db.id <> entry.id AND db.type IN ['rds_instance', 'redshift_cluster']
RETURN entry, c1, src, a, dst, c2, db
ORDER BY db.score DESC
LIMIT 40`,
  },

  // ── Permissions & Secrets ─────────────────────────────────────────────────
  {
    id: "roles-accessing-secrets",
    label: "Roles that can read secrets",
    desc: "IAM roles with access to Secrets Manager, SSM Parameter Store, or GCP Secret Manager",
    category: "Permissions & Secrets",
    cypher: `MATCH (r:IamRole)-[s:AccessesSecret]->(secret:Asset)
RETURN r, s, secret
ORDER BY r.score DESC
LIMIT 50`,
  },
  {
    id: "exposed-workload-to-secret",
    label: "Exposed workload → role → secret",
    desc: "Internet-exposed compute that can read secrets via its IAM role — data exfiltration path",
    category: "Permissions & Secrets",
    cypher: `MATCH (w:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (w)-[:ExecutesAs|HasRole]->(r:IamRole)
MATCH (r)-[:AccessesSecret]->(secret:Asset)
RETURN w, r, secret
ORDER BY w.score DESC
LIMIT 30`,
  },

  // ── Network ───────────────────────────────────────────────────────────────
  {
    id: "sg-open-to-internet",
    label: "Security groups open to 0.0.0.0/0",
    desc: "Internet-exposed assets and the security group responsible for that exposure",
    category: "Network",
    // `exposed` is an Asset property, not a SecurityGroup one (SecurityGroup only
    // carries id/name/type/provider/region/account_id/score — see graphstore
    // schema.go) and AllowsFrom is Asset→Asset, never SecurityGroup→Asset, so the
    // old query threw a Binder exception on every run. World-open (0.0.0.0/0)
    // ingress is what actually produces ExposedToInternet (see correlate/
    // reachability.go), so surface it via that edge + the SG that connects the
    // asset, which is the graph-expressible form of "why is this exposed".
    cypher: `MATCH (a:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (a)-[c:ConnectedViaSG]->(sg:Asset {type: 'security_group'})
RETURN a, c, sg
ORDER BY a.score DESC
LIMIT 50`,
  },
  {
    id: "lateral-via-sg",
    label: "Lateral movement via SG rules",
    desc: "Internet-exposed assets and every asset whose security group admits theirs — lateral movement inside the VPC",
    category: "Network",
    // Sharing a security group is not a network path: the target's SG must
    // admit the entry's SG. AllowsFrom runs permitting SG → admitted SG, and is
    // a self-loop when an SG admits its own members.
    cypher: `MATCH (a:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (a)-[c1:ConnectedViaSG]->(src:Asset)
MATCH (dst:Asset)-[r:AllowsFrom]->(src)
MATCH (b:Asset)-[c2:ConnectedViaSG]->(dst)
WHERE b.id <> a.id
RETURN a, c1, src, r, dst, c2, b
ORDER BY b.score DESC
LIMIT 40`,
  },

  // ── Blast radius ──────────────────────────────────────────────────────────
  {
    id: "high-blast-radius-exposed",
    label: "Highest blast radius",
    desc: `Internet-exposed assets scoring ≥ ${SCORE_THRESHOLDS.pipeline} — widest potential impact if compromised`,
    category: "Blast radius",
    cypher: `MATCH (n:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE n.score >= ${SCORE_THRESHOLDS.pipeline}
RETURN n
ORDER BY n.score DESC
LIMIT 20`,
  },
  {
    id: "expiring-certs-on-exposed",
    label: "Expiring TLS certificates",
    desc: "TLS certificates expiring soon — outage risk",
    category: "Blast radius",
    // `expiring_soon` only ever appears on cert-typed assets (acm_certificate,
    // gcp_ssl_certificate) themselves — never on the service in front of them, so
    // filtering it on the ExposedToInternet node could never match. No collector
    // links a cert to the service it protects (ProtectedBy points at security
    // groups, see the header), so "on exposed services" isn't expressible. Show the certs
    // directly instead of a join that can never return anything.
    cypher: `MATCH (a:Asset)
WHERE a.expiring_soon = 1
RETURN a
ORDER BY a.days_until_expiry ASC
LIMIT 30`,
  },

  // ── IAM Users (human identities — iam_user maps to IamRole node) ────────────
  {
    id: "iam-users-all",
    label: "All IAM users",
    desc: "Every human IAM user in the graph — see who has cloud access and at what risk score",
    category: "IAM / Privilege escalation",
    cypher: `MATCH (u:IamRole)
WHERE u.type = 'iam_user'
RETURN u
ORDER BY u.score DESC
LIMIT 50`,
  },
  {
    id: "iam-users-risky",
    label: "High-risk IAM users",
    desc: `IAM users with score ≥ ${SCORE_THRESHOLDS.high} — human identities with detected security issues`,
    category: "IAM / Privilege escalation",
    cypher: `MATCH (u:IamRole)
WHERE u.type = 'iam_user' AND u.score >= ${SCORE_THRESHOLDS.high}
RETURN u
ORDER BY u.score DESC
LIMIT 30`,
  },
  {
    id: "iam-user-assume-paths",
    label: "IAM users → role chains",
    desc: "Human users who can assume roles — map the privilege escalation paths from human access",
    category: "IAM / Privilege escalation",
    cypher: `MATCH (u:IamRole)-[r:CanAssume]->(role:IamRole)
WHERE u.type = 'iam_user'
RETURN u, r, role
ORDER BY role.score DESC
LIMIT 50`,
  },

  // ── DNS (loads after correlate sweep) ─────────────────────────────────────
  {
    id: "dns-points-to",
    label: "DNS resolution chains",
    desc: "DNS records and what they resolve to — track your external DNS footprint",
    category: "DNS",
    cypher: `MATCH (d:Asset)-[r:DnsPointsTo]->(t:Asset)
RETURN d, r, t
ORDER BY t.score DESC
LIMIT 50`,
  },
  {
    id: "dns-to-exposed",
    label: "DNS → exposed targets",
    desc: "DNS records pointing to internet-exposed assets — your externally-resolvable attack surface",
    category: "DNS",
    cypher: `MATCH (d:Asset)-[r:DnsPointsTo]->(target:Asset)
MATCH (target)-[:ExposedToInternet]->(:Asset {id: 'internet'})
RETURN d, r, target
ORDER BY target.score DESC
LIMIT 40`,
  },

  // ── Org exposure ─────────────────────────────────────────────────────────
  {
    id: "org-exposed-assets",
    label: "Org exposed assets",
    desc: "Internet-exposed assets and the repo (any org) that deploys to them",
    category: "Internet exposure",
    // Two bugs: (1) Repo.name is the bare repo name ("webapp") — the "org/repo"
    // form lives on Repo.id, so `r.name STARTS WITH` could never match anything.
    // (2) a hardcoded org prefix only matches one org (e.g. example-org), so
    // even fixing (1) with the right id wouldn't reliably match. Show all orgs —
    // r.id is still returned so the owning org is visible per row.
    cypher: `MATCH (r:Repo)-[:DeploysTo]->(w:K8sWorkload)
MATCH (w)-[:ExposedToInternetK8sWorkload]->(:Asset {id: 'internet'})
RETURN r, w
ORDER BY w.score DESC
LIMIT 50`,
  },

  // ── Load balancers ────────────────────────────────────────────────────────
  {
    id: "iac-orphan-lbs",
    label: "IaC-orphan LBs",
    desc: "Internet-exposed load balancers not deployed-to by any source repo — no IaC ownership, potential dead weight",
    category: "Load balancers",
    cypher: `MATCH (lb:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE lb.type IN ['load_balancer', 'gcp_forwarding_rule', 'network_load_balancer']
OPTIONAL MATCH (repo:Repo)-[:DeploysToService]->(lb)
WITH lb, count(repo) AS owners
WHERE owners = 0
RETURN lb
ORDER BY lb.score DESC
LIMIT 50`,
  },
  {
    id: "zombie-lbs",
    label: "Zombie LBs",
    desc: "DNS resolves to them, internet-exposed, but no IaC repo owns them and no SG protection — scanner-only traffic",
    category: "Load balancers",
    cypher: `MATCH (dns:Asset)-[p:DnsPointsTo]->(lb:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE lb.type IN ['load_balancer', 'gcp_forwarding_rule', 'network_load_balancer']
OPTIONAL MATCH (r:Repo)-[:DeploysToService]->(lb)
WITH dns, p, lb, count(r) AS deployers
WHERE deployers = 0
OPTIONAL MATCH (lb)-[:ProtectedBy]->(waf:Asset)
WITH dns, p, lb, count(waf) AS protections
WHERE protections = 0
RETURN dns, p, lb
ORDER BY lb.score DESC
LIMIT 50`,
  },

  // ── SSO / Access (Group → PermissionSet → CloudAccount) ──────────────────
  {
    id: "sso-groups-with-admin",
    label: "Groups with admin, and where",
    desc: "Every group that holds an admin permission set and the accounts it covers",
    category: "SSO / Access",
    // `Group` is a Cypher/LadybugDB reserved keyword (collides with GROUP BY) and MUST be
    // backtick-escaped, or the query fails to parse (HTTP 500). The `group`
    // alias collides the same way, so return it as `grp`. See graphstore
    // schema.go cypherReservedLabels.
    cypher: `MATCH (g:\`Group\`)-[:AssignedTo]->(ps:PermissionSet)-[:GrantsAdmin]->(a:CloudAccount)
RETURN g.name AS grp, ps.name AS permission_set, collect(a.name) AS accounts
ORDER BY grp`,
  },
  {
    id: "sso-blast-radius",
    label: "Blast radius of a group",
    desc: "Which permission sets a group holds and which accounts they reach",
    category: "SSO / Access",
    cypher: `MATCH (g:\`Group\` {name: 'Cloud Admins'})-[:AssignedTo]->(ps:PermissionSet)-[:GrantsAccessTo]->(a:CloudAccount)
RETURN g, ps, a`,
  },

  // ── IaC / Ownership (live asset → repo that declares it) ─────────────────
  {
    id: "iac-workload-owner",
    label: "k8s workloads → owning repo (from manifests)",
    desc: "Live k8s workloads and the repo whose manifest declares them, with match confidence.",
    category: "IaC / Ownership",
    cypher: `MATCH (w:K8sWorkload)-[e:DefinedInK8sWorkload]->(r:Repo)
RETURN w.name AS workload, w.type AS kind, r.name AS repo, e.confidence AS confidence, e.provenance AS provenance
ORDER BY confidence DESC, repo`,
  },
  {
    id: "iac-service-owner",
    label: "k8s services → owning repo (from manifests)",
    desc: "Live k8s Services declared in a repo's manifests.",
    category: "IaC / Ownership",
    cypher: `MATCH (s:Asset)-[e:DefinedInAsset]->(r:Repo)
WHERE s.type = 'k8s_service'
RETURN s.name AS service, r.name AS repo, e.confidence AS confidence
ORDER BY repo`,
  },
  {
    id: "iac-exposed-owned-workloads",
    label: "internet-exposed workloads and who defines them",
    desc: "Exposed k8s workloads joined to the repo that declares them — triage 'who fixes this?'.",
    category: "IaC / Ownership",
    cypher: `MATCH (w:K8sWorkload)-[:DefinedInK8sWorkload]->(r:Repo)
MATCH (w)-[:ExposedToInternetK8sWorkload]->(:Asset {id: 'internet'})
RETURN w.name AS workload, r.name AS repo
ORDER BY workload`,
  },
  {
    id: "iam-roles-owner",
    label: "IAM roles → owning repo",
    desc: "IAM roles declared in a repo (Terraform state, or the role's ARN written in repo text), tied to the repo that declares them",
    category: "IaC / Ownership",
    cypher: `MATCH (role:IamRole)-[e:DefinedInIamRole]->(r:Repo)
RETURN role.name AS role, r.name AS repo, e.confidence AS confidence, e.provenance AS source
ORDER BY repo LIMIT 200`,
  },
  {
    id: "tf-resource-owner",
    label: "Terraform-managed resources → owning repo",
    desc: "Live resources whose Terraform (S3 state) declares them, tied to the owning repo (authoritative, high confidence)",
    category: "IaC / Ownership",
    cypher: `MATCH (a)-[e:DefinedInAsset|DefinedInIamRole]->(r:Repo)
WHERE e.provenance = 'iac_terraform'
RETURN a.name AS resource, a.type AS type, r.name AS repo, e.confidence AS confidence
ORDER BY repo LIMIT 200`,
  },
]
