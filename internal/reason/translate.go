package reason

import (
	"context"
	"fmt"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/graphschema"
	"github.com/vulngraph/vulngraph/internal/llm"
)

// GraphTranslator turns a natural-language question into a validated
// explore.GraphQuerySpec via the configured LLM. It implements explore.Translator. The spec
// is returned for the user to review/edit — it is never executed here.
type GraphTranslator struct {
	doer messageDoer
}

func NewGraphTranslator(client llm.Client) *GraphTranslator {
	return &GraphTranslator{doer: &llmDoer{client: client}}
}

// CypherTranslator turns a natural-language security question into a raw
// Ladybug Cypher query. It implements explore.CypherTranslator. The generated
// Cypher is validated by graphquery.IsReadOnly before execution — the LLM
// output never reaches Ladybug unvalidated.
type CypherTranslator struct {
	doer messageDoer
}

func NewCypherTranslator(client llm.Client) *CypherTranslator {
	return &CypherTranslator{doer: &llmDoer{client: client}}
}

// cypherSystemPrompt is assembled at init: the relationship-table section is
// generated from the graphschema registry so the prompt can never advertise
// an unloaded rel (a rel that exists in the DDL but is not loaded returns
// zero rows silently). TestCypherPromptRelsAreLoaded pins the examples too.
var cypherSystemPrompt = cypherPromptHead + RelSchemaBlock() + cypherPromptTail

const cypherPromptHead = `You are a Ladybug graph database expert. Convert the security analyst's natural-language question into a valid Ladybug Cypher query.

SCHEMA — Node tables:
  Asset(id, name, type, provider, region, account_id, score INT,
        exposed INT32, has_kev INT32, exploitable INT32, toxic_combo INT32,
        privesc_count INT32, expires_at STRING, days_until_expiry INT32, expiring_soon INT32)
    Common types: ec2_instance, rds_instance, s3_bucket, lambda_function, load_balancer,
    gce_instance, cloudsql_instance, cloudrun_service, cloud_function,
    azure_vm, azure_webapp, azure_sql_server, k8s_pod, k8s_deployment, k8s_service,
    security_group, gcp_firewall, dns_record, elastic_ip, ecs_service,
    k8s_certificate, acm_certificate, gcp_ssl_certificate
  K8sWorkload(id, name, type, provider, region, account_id, score INT)
  IamRole(id, name, provider, account_id, score INT, type, region)
    Types: iam_role, iam_user, iam_group, gcp_service_account, azure_service_principal
  Repo(id, name, provider)
  DataClass(id, classification)  — DSPM sensitivity classes; ids like 'dataclass:pii'
  ` + "`Group`" + `(id, name, provider)  — SSO groups (e.g. Okta groups). RESERVED label: MUST be escaped as ` + "`Group`" + `
  PermissionSet(id, name, provider, account_id, grants_admin INT32)  — AWS Identity Center permission sets
  CloudAccount(id, name, provider, account_id)  — an AWS account; the target SSO access is granted to

Special sentinel: Asset {id: 'internet'} — the internet node (target of ExposedToInternet edges)

`

const cypherPromptTail = `
EXAMPLES:
Q: show all internet-exposed assets with high risk
A: MATCH (a:Asset)-[r:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE a.score >= 61
RETURN a, r
ORDER BY a.score DESC LIMIT 50

Q: which github repos can assume AWS roles via OIDC
A: MATCH (repo:Repo)-[f:FederatedAccess]->(role:IamRole)
RETURN repo, f, role
ORDER BY role.score DESC LIMIT 50

Q: blast radius — what can an asset reach in 2 hops
A: MATCH (seed:Asset {id: 'REPLACE_ID'})-[r1:ExecutesAs|HasRole|Accesses|DnsPointsTo|ProtectedBy|Binds]->(hop1:Asset)
MATCH (hop1)-[r2:ExecutesAs|HasRole|Accesses|DnsPointsTo|ProtectedBy|Binds]->(hop2:Asset)
RETURN seed, r1, hop1, r2, hop2 LIMIT 100

Q: workloads that can assume high-risk IAM roles
A: MATCH (a:Asset)-[r1:ExecutesAs|HasRole]->(role:IamRole)
MATCH (role)-[r2:CanAssume]->(target:IamRole)
WHERE target.score >= 70
RETURN a, r1, role, r2, target
ORDER BY target.score DESC LIMIT 30

Q: databases reachable from internet-exposed assets through security groups
A: MATCH (entry:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (entry)-[:ConnectedViaSG]->(src:Asset)
MATCH (dst:Asset)-[a:AllowsFrom]->(src)
MATCH (db:Asset)-[:ConnectedViaSG]->(dst)
WHERE db.id <> entry.id
  AND db.type IN ['rds_instance','elasticache_cluster','redshift_cluster']
RETURN entry, src, a, dst, db
ORDER BY db.score DESC LIMIT 50

Q: certificates expiring in the next 30 days
A: MATCH (a:Asset)
WHERE a.type IN ['k8s_certificate','acm_certificate','gcp_ssl_certificate'] AND a.expiring_soon = 1
RETURN a
ORDER BY a.days_until_expiry ASC LIMIT 100

Q: public-facing services deployed from github repos
A: MATCH (r:Repo)-[d:DeploysToService]->(a:Asset)
MATCH (a)-[:ExposedToInternet]->(:Asset {id: 'internet'})
RETURN r, d, a
ORDER BY a.score DESC LIMIT 50

Q: GitHub repos with OIDC access that can assume high-risk roles (risk score >= 60)
A: MATCH (repo:Repo)-[:FederatedAccess]->(role:IamRole)
MATCH (role)-[:CanAssume]->(target:IamRole)
WHERE target.score >= 60
RETURN repo, role, target
ORDER BY target.score DESC LIMIT 30

Q: kubernetes services exposed to the internet
A: MATCH (s:Asset)-[r:ExposedToInternet]->(:Asset {id: 'internet'})
WHERE s.type = 'k8s_service'
RETURN s, r
ORDER BY s.score DESC LIMIT 50

Q: show top risky assets with KEV findings
A: MATCH (n:Asset)
WHERE n.has_kev = 1
RETURN n
ORDER BY n.score DESC LIMIT 50

Q: how many repositories deploy to public-facing assets?
A: MATCH (r:Repo)-[:DeploysToService]->(a:Asset)
WHERE a.exposed = 1
RETURN count(DISTINCT r) AS repo_count

Q: count internet-exposed assets by provider
A: MATCH (a:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
RETURN a.provider AS provider, count(*) AS n
ORDER BY n DESC LIMIT 50

Q: internet-exposed stores holding sensitive data (DSPM toxic combination)
A: MATCH (a:Asset)-[c:ContainsData]->(dc:DataClass)
WHERE a.exposed = 1 AND dc.id <> 'dataclass:internal'
RETURN a, c, dc
ORDER BY a.score DESC LIMIT 50

Q: which SSO groups grant admin, and to which AWS accounts
A: MATCH (g:` + "`Group`" + `)-[:AssignedTo]->(ps:PermissionSet)
MATCH (ps)-[:GrantsAdmin]->(a:CloudAccount)
RETURN g.name AS grp, ps.name AS permission_set, collect(a.name) AS accounts
ORDER BY grp

RULES:
- Return ONLY the Cypher query — no explanation, no markdown fences
- For "how many"/"count"/"total"/"average" questions, use an aggregate (count/sum/avg/min/max) with an AS alias and RETURN the scalar — do NOT return whole nodes. Aggregate results come back as a table, not a graph. An aggregate RETURN needs no LIMIT
- To break a count down by a dimension, RETURN the grouping key plus the aggregate (e.g. RETURN a.provider AS provider, count(*) AS n)
- Always add LIMIT (max 200) for queries that RETURN nodes/edges
- Use ORDER BY score DESC unless another sort is more meaningful
- score is 0–100 (higher = more risk)
- Boolean/signal fields (exposed, has_kev, exploitable, toxic_combo, expiring_soon) are INT32 — use = 1 not = true
- Variable-length paths need an explicit upper bound of at most 6, e.g. (a:IamRole)-[:CanAssume*1..3]->(b:IamRole). The engine caps path depth at 6: a larger upper bound is rejected, and a bare [*] stops at 6 hops
- Prefer explicit rel types, e.g. -[:CanAssume|CanEscalateTo]->, over untyped (n)-[]->(m) patterns — typed traversal is cheaper and states the question's intent
- ExposedToInternet rel is Asset→Asset only — EC2 instances and security groups are :Asset nodes (filter by type); for a k8s workload source use ExposedToInternetK8sWorkload
- The Group node label is a Ladybug RESERVED keyword — ALWAYS write it backtick-escaped: (g:` + "`Group`" + `), never bare (g:Group), which fails to parse. Never use "group" as a RETURN alias or ORDER BY key either — alias it (e.g. AS grp)
- ProtectedBy direction is (instance|load_balancer)-[:ProtectedBy]->(security_group/NSG) — the protected resource is the source node
- Never use CREATE, MERGE, SET, DELETE, DROP, COPY, ALTER, CALL, or any write operation`

// TranslateToCypher converts a natural-language security question to Ladybug Cypher.
func (t *CypherTranslator) TranslateToCypher(ctx context.Context, nl string) (string, error) {
	if strings.TrimSpace(nl) == "" {
		return "", fmt.Errorf("TranslateToCypher: empty question")
	}
	cypher, err := t.doer.do(ctx, cypherSystemPrompt, nl)
	if err != nil {
		return "", fmt.Errorf("TranslateToCypher: %w", err)
	}
	// Strip markdown code fences if the model added them despite instructions.
	cypher = strings.TrimSpace(cypher)
	if strings.HasPrefix(cypher, "```") {
		lines := strings.Split(cypher, "\n")
		var inner []string
		for _, l := range lines {
			if strings.HasPrefix(l, "```") {
				continue
			}
			inner = append(inner, l)
		}
		cypher = strings.TrimSpace(strings.Join(inner, "\n"))
	}
	return cypher, nil
}

// graphSystemPrompt advertises exactly the rel tables the structured expand
// path can traverse (the registry's Expand set) — a rel outside that set
// would silently return nothing on both the Ladybug path and the ClickHouse
// fallback.
var graphSystemPrompt = `You translate a security analyst's question about a cloud asset graph into a JSON GraphQuerySpec. Respond with ONLY the JSON object:
{"seed":{"ids":[],"types":[],"provider":""},"traverse":[{"edge_types":[],"direction":"out|in|both","max_hops":1}],"max_nodes":500,"max_edges":2000}
- seed selects starting assets: by explicit "ids", or by "types" (e.g. ec2_instance, security_group, gce_instance, github_repo, vpc_network) and/or "provider" (aws|gcp|github). At least one of ids/types/provider is required.
- traverse is ordered hops; edge_types must use exact PascalCase rel table names: ` + expandRelNames() + `. Omit edge_types to follow any of these edges.
- Keep max_hops small (1-3). Omit fields you don't need.
Examples:
  "which security groups protect my EC2 instances?" → {"seed":{"types":["ec2_instance"],"provider":"aws"},"traverse":[{"edge_types":["ProtectedBy"],"direction":"out","max_hops":1}],"max_nodes":500,"max_edges":2000}
  "what can this role access?" → {"seed":{"ids":["<role-id>"],"types":[]},"traverse":[{"edge_types":["Accesses"],"direction":"out","max_hops":2}],"max_nodes":500,"max_edges":2000}
  "what runs inside this VPC?" → {"seed":{"types":["vpc_network"],"provider":"gcp"},"traverse":[{"edge_types":["Accesses"],"direction":"in","max_hops":1}],"max_nodes":500,"max_edges":2000}
  "which assets execute as this role?" → {"seed":{"ids":["<role-id>"],"types":[]},"traverse":[{"edge_types":["ExecutesAs","HasRole"],"direction":"in","max_hops":1}],"max_nodes":500,"max_edges":2000}`

// expandRelNames renders the structured-expand rel set for graphSystemPrompt.
func expandRelNames() string {
	var names []string
	for _, r := range graphschema.ExpandRels() {
		names = append(names, r.Name)
	}
	return strings.Join(names, ", ")
}

func (t *GraphTranslator) Translate(ctx context.Context, nl string) (explore.GraphQuerySpec, error) {
	if strings.TrimSpace(nl) == "" {
		return explore.GraphQuerySpec{}, fmt.Errorf("Translate: empty query")
	}
	text, err := t.doer.do(ctx, graphSystemPrompt, nl)
	if err != nil {
		return explore.GraphQuerySpec{}, fmt.Errorf("Translate: %w", err)
	}
	return parseSpec(text)
}

// parseSpec extracts and validates the spec JSON from the model's reply,
// using decodeJSONReply (reason.go) — the same parser used by
// parsePlan/parseVerdict, since GraphTranslator is exposed to the same
// stray-prose-around-JSON failure mode as those callers. parseSpec goes
// through do() (schema=nil), so it deliberately does not gain adaptive
// thinking or the larger token budget — those stay scoped to doJSON's
// callers.
func parseSpec(text string) (explore.GraphQuerySpec, error) {
	var spec explore.GraphQuerySpec
	if err := decodeJSONReply(text, &spec); err != nil {
		return explore.GraphQuerySpec{}, fmt.Errorf("parseSpec: %w", err)
	}
	if len(spec.Seed.IDs) == 0 && len(spec.Seed.Types) == 0 && spec.Seed.Provider == "" {
		return explore.GraphQuerySpec{}, fmt.Errorf("parseSpec: %w", explore.ErrNoSeed)
	}
	return spec, nil
}
