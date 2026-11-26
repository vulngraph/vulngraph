# Query cookbook

The Graph page lists 46 ready-made queries: 38 Cypher queries, shown below, and 8 point-and-click
presets. Pick one from **Browse all queries**, or paste it into any MCP client's `run_cypher` tool.
They are read-only and run against the graph Vulngraph builds from your connectors. Node labels are
`Asset`, `IamRole`, `Repo` and `K8sWorkload`; [`architecture.md`](architecture.md) describes the graph.
Score thresholds are the current bands (page 81, high 61, pipeline 50).

The queries are extracted from `frontend/src/lib/queryLibrary.ts`; change them there.

Package inventory is queried on demand. Use the structured graph query/expand
API with `depends_on` and `runs_package`. Internal graph API clients can use the
named queries `package_source_repos` and `package_running_workloads` with a `name`
parameter.
These memberships and Package nodes are not available to raw Cypher. Package
findings remain available in inventory; runtime reachability is evaluated through
the workloads that use them. The resident risk score includes the highest package
inventory risk score as a floor before graph propagation.

Package named queries start with at most 100 seeds and return at most 2,000 nodes
and 5,000 edges. A `truncated` response is a partial view; use a specific package
name or ID to narrow the investigation.

## Internet exposure

### High-risk exposed

Internet-facing assets with score ≥ 61 — your highest-priority attack surface

```cypher
MATCH (a:Asset)-[e:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE a.score >= 61
RETURN a, e
ORDER BY a.score DESC
LIMIT 50
```

### All internet-exposed

Every asset reachable from the internet — your complete external footprint

```cypher
MATCH (a:Asset)-[e:ExposedToInternet]->(:Asset {id: 'internet'})
RETURN a, e
ORDER BY a.score DESC
LIMIT 50
```

### Exposed → high-risk role

Internet-facing assets running as high-risk IAM roles — the most dangerous combination

```cypher
MATCH (a:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (a)-[r:ExecutesAs|HasRole]->(role:IamRole)
WHERE role.score >= 70
RETURN a, r, role
ORDER BY role.score DESC
LIMIT 30
```

## IAM / Privilege escalation

### CIEM escalation paths

Permission-based escalation: CreatePolicyVersion, PassRole, SSM SendCommand, and 60+ more CIEM techniques

```cypher
MATCH (a:IamRole)-[r:CanEscalateTo]->(b:IamRole)
RETURN a, r, b
ORDER BY b.score DESC
LIMIT 50
```

### CIEM + CanAssume chain

Workloads whose role can escalate to or assume another role via CIEM escalation or trust-policy assumption — highest-risk target first

```cypher
MATCH (w:Asset)-[r1:ExecutesAs|HasRole]->(role:IamRole)
MATCH (role)-[r2:CanEscalateTo|CanAssume]->(target:IamRole)
RETURN w, r1, role, r2, target
ORDER BY target.score DESC
LIMIT 30
```

### CanAssume chains

IAM trust policy chains — one role using another as a lateral-movement launchpad

```cypher
MATCH (a:IamRole)-[r:CanAssume]->(b:IamRole)
RETURN a, r, b
ORDER BY b.score DESC
LIMIT 50
```

### Cross-account escalation

Roles assuming other-account roles — trust boundaries crossed across AWS accounts

```cypher
MATCH (a:IamRole)-[r:CanAssume]->(b:IamRole)
WHERE a.account_id <> b.account_id AND b.account_id <> ''
RETURN a, r, b
ORDER BY b.score DESC
LIMIT 50
```

### Workloads as IAM roles

Compute, containers, and serverless running as IAM roles — the machine identity surface

```cypher
MATCH (a:Asset)-[r:ExecutesAs|HasRole]->(role:IamRole)
RETURN a, r, role
ORDER BY role.score DESC
LIMIT 50
```

### High-risk roles

IAM roles with risk score ≥ 81 — ranked by findings, escalation paths and neighbouring risk, not by the permissions they hold

```cypher
MATCH (r:IamRole)
WHERE r.score >= 81
RETURN r
ORDER BY r.score DESC
LIMIT 50
```

### All IAM users

Every human IAM user in the graph — see who has cloud access and at what risk score

```cypher
MATCH (u:IamRole)
WHERE u.type = 'iam_user'
RETURN u
ORDER BY u.score DESC
LIMIT 50
```

### High-risk IAM users

IAM users with score ≥ 61 — human identities with detected security issues

```cypher
MATCH (u:IamRole)
WHERE u.type = 'iam_user' AND u.score >= 61
RETURN u
ORDER BY u.score DESC
LIMIT 30
```

### IAM users → role chains

Human users who can assume roles — map the privilege escalation paths from human access

```cypher
MATCH (u:IamRole)-[r:CanAssume]->(role:IamRole)
WHERE u.type = 'iam_user'
RETURN u, r, role
ORDER BY role.score DESC
LIMIT 50
```

## OIDC / CI-CD

### Repos with cloud access

GitHub Actions and CI/CD pipelines that can assume cloud roles via OIDC federation

```cypher
MATCH (repo:Repo)-[f:FederatedAccess]->(role:IamRole)
RETURN repo, f, role
ORDER BY role.score DESC
LIMIT 50
```

### GCP Workload Identity

Repos federating into GCP service accounts via Workload Identity Federation

```cypher
MATCH (repo:Repo)-[f:FederatedAccess]->(sa:IamRole)
WHERE sa.type = 'gcp_service_account' OR sa.provider = 'gcp'
RETURN repo, f, sa
ORDER BY sa.score DESC
LIMIT 50
```

### Repos → roles their CI assumes

GitHub Actions workflows that assume AWS roles / GCP SAs, from workflow config (not just trust policies)

```cypher
MATCH (r:Repo)-[e:FederatedAccess]->(role:IamRole)
WHERE e.provenance IN ['gh_workflow', 'gh_workflow+live']
RETURN r.name AS repo, role.name AS role, e.provenance AS source
ORDER BY repo LIMIT 200
```

### OIDC → role → escalation target

CI/CD pipelines whose role can escalate to or assume another role — via permission-based escalation (PassRole/AssumeRole) or trust-policy assumption — highest-risk target first

```cypher
MATCH (repo:Repo)-[f:FederatedAccess]->(role:IamRole)
MATCH (role)-[c:CanEscalateTo|CanAssume]->(target:IamRole)
RETURN repo, f, role, c, target
ORDER BY target.score DESC
LIMIT 30
```

## Attack chains

### Internet → workload → IAM → escalation target

End-to-end attack path: internet entry point through an IAM role that can escalate to or assume another role — highest-risk target first

```cypher
MATCH (entry:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (entry)-[r1:ExecutesAs|HasRole]->(role:IamRole)
MATCH (role)-[r2:CanEscalateTo|CanAssume]->(target:IamRole)
RETURN entry, r1, role, r2, target
ORDER BY target.score DESC
LIMIT 25
```

### Widest blast radius

Internet-facing assets with the most reachable neighbours — biggest impact if compromised

```cypher
MATCH (entry:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (entry)-[r:ConnectedViaSG|ExecutesAs|HasRole|Accesses|DnsPointsTo|ProtectedBy|Binds]->(reached)
RETURN entry, r, reached
ORDER BY entry.score DESC
LIMIT 30
```

## Supply chain

### Repos → exposed K8s

GitHub repos deploying directly to internet-exposed Kubernetes workloads

```cypher
MATCH (r:Repo)-[d:DeploysTo]->(w:K8sWorkload)
MATCH (w)-[:ExposedToInternetK8sWorkload]->(:Asset {id: 'internet'})
RETURN r, d, w
ORDER BY w.score DESC
LIMIT 40
```

### Repos → exposed services

Repos deploying to internet-exposed ECS, Lambda, or Cloud Run services

```cypher
MATCH (r:Repo)-[d:DeploysToService]->(s:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
RETURN r, d, s
ORDER BY s.score DESC
LIMIT 40
```

### Full supply chain chain

Repo → deploy → exposed workload → IAM role — the complete supply chain attack surface

```cypher
MATCH (repo:Repo)-[d:DeploysTo]->(w:K8sWorkload)-[x:ExecutesAsK8sWorkload]->(role:IamRole)
RETURN repo, d, w, x, role
ORDER BY role.score DESC
LIMIT 30
```

### Repos with IAM exposure

All repos with IAM role exposure via deployment pipelines

```cypher
MATCH (r:Repo)-[:DeploysTo]->(w:K8sWorkload)
MATCH (w)-[:ExecutesAsK8sWorkload]->(role:IamRole)
RETURN r, w, role
ORDER BY role.score DESC
LIMIT 40
```

## Kubernetes

### Exposed K8s services

LoadBalancer and Ingress services directly reachable from the internet

```cypher
MATCH (svc:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE svc.type IN ['k8s_service', 'k8s_ingress']
RETURN svc
ORDER BY svc.score DESC
LIMIT 40
```

### K8s workloads → IAM roles

Pods and deployments running as cloud IAM roles via IRSA or Workload Identity

```cypher
MATCH (w:K8sWorkload)-[e:ExecutesAsK8sWorkload]->(role:IamRole)
RETURN w, e, role
ORDER BY role.score DESC
LIMIT 50
```

### Exposed K8s → IAM escalation

Exposed pods whose cloud role can escalate to or assume another role — highest-risk target first

```cypher
MATCH (w:K8sWorkload)-[:ExecutesAsK8sWorkload]->(role:IamRole)
MATCH (role)-[:CanEscalateTo|CanAssume]->(target:IamRole)
MATCH (w)-[:ExposedToInternetK8sWorkload]->(:Asset {id: 'internet'})
RETURN w, role, target
ORDER BY target.score DESC
LIMIT 30
```

## Permissions & Secrets

### Roles that can read secrets

IAM roles with access to Secrets Manager, SSM Parameter Store, or GCP Secret Manager

```cypher
MATCH (r:IamRole)-[s:AccessesSecret]->(secret:Asset)
RETURN r, s, secret
ORDER BY r.score DESC
LIMIT 50
```

### Exposed workload → role → secret

Internet-exposed compute that can read secrets via its IAM role — data exfiltration path

```cypher
MATCH (w:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (w)-[:ExecutesAs|HasRole]->(r:IamRole)
MATCH (r)-[:AccessesSecret]->(secret:Asset)
RETURN w, r, secret
ORDER BY w.score DESC
LIMIT 30
```

## Blast radius

### Highest blast radius

Internet-exposed assets scoring ≥ 50 — widest potential impact if compromised

```cypher
MATCH (n:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE n.score >= 50
RETURN n
ORDER BY n.score DESC
LIMIT 20
```

## DNS

### DNS resolution chains

DNS records and what they resolve to — track your external DNS footprint

```cypher
MATCH (d:Asset)-[r:DnsPointsTo]->(t:Asset)
RETURN d, r, t
ORDER BY t.score DESC
LIMIT 50
```

### DNS → exposed targets

DNS records pointing to internet-exposed assets — your externally-resolvable attack surface

```cypher
MATCH (d:Asset)-[r:DnsPointsTo]->(target:Asset)
MATCH (target)-[:ExposedToInternet]->(:Asset {id: 'internet'})
RETURN d, r, target
ORDER BY target.score DESC
LIMIT 40
```

## Load balancers

### IaC-orphan LBs

Internet-exposed load balancers not deployed-to by any source repo — no IaC ownership, potential dead weight

```cypher
MATCH (lb:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE lb.type IN ['load_balancer', 'gcp_forwarding_rule', 'network_load_balancer']
OPTIONAL MATCH (repo:Repo)-[:DeploysToService]->(lb)
WITH lb, count(repo) AS owners
WHERE owners = 0
RETURN lb
ORDER BY lb.score DESC
LIMIT 50
```

### Zombie LBs

DNS resolves to them, internet-exposed, but no IaC repo owns them and no SG protection — scanner-only traffic

```cypher
MATCH (dns:Asset)-[p:DnsPointsTo]->(lb:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE lb.type IN ['load_balancer', 'gcp_forwarding_rule', 'network_load_balancer']
OPTIONAL MATCH (r:Repo)-[:DeploysToService]->(lb)
WITH dns, p, lb, count(r) AS deployers
WHERE deployers = 0
OPTIONAL MATCH (lb)-[:ProtectedBy]->(waf:Asset)
WITH dns, p, lb, count(waf) AS protections
WHERE protections = 0
RETURN dns, p, lb
ORDER BY lb.score DESC
LIMIT 50
```

## SSO / Access

### Blast radius of a group

Which permission sets a group holds and which accounts they reach

```cypher
MATCH (g:\`Group\` {name: 'Cloud Admins'})-[:AssignedTo]->(ps:PermissionSet)-[:GrantsAccessTo]->(a:CloudAccount)
RETURN g, ps, a
```

## IaC / Ownership

### k8s workloads → owning repo (from manifests)

Live k8s workloads and the repo whose manifest declares them, with match confidence.

```cypher
MATCH (w:K8sWorkload)-[e:DefinedInK8sWorkload]->(r:Repo)
RETURN w.name AS workload, w.type AS kind, r.name AS repo, e.confidence AS confidence, e.provenance AS provenance
ORDER BY confidence DESC, repo
```

### k8s services → owning repo (from manifests)

Live k8s Services declared in a repo's manifests.

```cypher
MATCH (s:Asset)-[e:DefinedInAsset]->(r:Repo)
WHERE s.type = 'k8s_service'
RETURN s.name AS service, r.name AS repo, e.confidence AS confidence
ORDER BY repo
```

### internet-exposed workloads and who defines them

Exposed k8s workloads joined to the repo that declares them — triage 'who fixes this?'.

```cypher
MATCH (w:K8sWorkload)-[:DefinedInK8sWorkload]->(r:Repo)
MATCH (w)-[:ExposedToInternetK8sWorkload]->(:Asset {id: 'internet'})
RETURN w.name AS workload, r.name AS repo
ORDER BY workload
```

### IAM roles → owning repo

IAM roles declared in a repo (Terraform state, or the role's ARN written in repo text), tied to the repo that declares them

```cypher
MATCH (role:IamRole)-[e:DefinedInIamRole]->(r:Repo)
RETURN role.name AS role, r.name AS repo, e.confidence AS confidence, e.provenance AS source
ORDER BY repo LIMIT 200
```

### Terraform-managed resources → owning repo

Live resources whose Terraform (S3 state) declares them, tied to the owning repo (authoritative, high confidence)

```cypher
MATCH (a)-[e:DefinedInAsset|DefinedInIamRole]->(r:Repo)
WHERE e.provenance = 'iac_terraform'
RETURN a.name AS resource, a.type AS type, r.name AS repo, e.confidence AS confidence
ORDER BY repo LIMIT 200
```
