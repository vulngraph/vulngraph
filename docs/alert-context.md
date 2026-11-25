# Alert context for SIEM and SOC agents

An alert carries IPs, ARNs, instance ids, hostnames and emails. It does not
carry Vulngraph asset ids. `get_alert_context` (MCP) and `POST /api/context/alert`
(REST) take those raw identifiers, resolve them to assets in the graph, and
return one bounded context per asset in a single call.

Read-only. Any authenticated role may call it, including an API key with
`read` scope (the MCP endpoint is `POST /api/mcp`, authenticated like every
other tool).

## Identifiers and resolution

Send up to 10 identifiers of any mix. Each is resolved independently and every
one appears in the response, resolved or not.

| Identifier | `match_type` | `confidence` | Notes |
|---|---|---|---|
| Asset id | `id` | `exact` | |
| IAM / other ARN | `arn` | `exact` | |
| STS assumed-role session ARN | `arn` | `exact` or `high` | Collapses to the role ARN (`normalized` shows it). A role under a path (`/service-role/`) has an id the session ARN cannot reproduce, so it also matches by role name within the same account (`high`). |
| EC2 instance id (`i-...`) | `instance_id` | `exact` | |
| Public IP | `ip` | `high` | |
| Private / loopback / link-local IP | `ip` | `medium` | Private ranges repeat across VPCs and accounts; expect several matches. |
| Hostname / DNS name | `dns` | `high` | Matches asset name, domain, or endpoint host. |
| Email | `email` | `high` | Human identities (Okta, Google Workspace) and service-account emails. |
| Kubernetes `namespace/name` | `k8s` | `medium` | Kubernetes assets only. |
| Bare name | `name` | `low` | Names are not unique. |

Identifier status is `resolved`, `unresolved` (a successful lookup found
nothing live), or `lookup_failed` (the lookup errored, so absence is not
proven; retry). Only live inventory resolves: dead pods and IaC declarations do
not.

## Per-asset context

For each resolved asset (at most 5 are expanded; the rest are listed in
`omitted_assets`): type, provider, account, region, `environment` and `owner`
when tagged, `risk_score`; direct internet exposure; attacker-direction blast
radius (count, counts by type, top reachable assets by risk); open findings (by
severity, must-fix with `must_fix_reason`, top by score); and, for identities,
whether privilege-escalation paths exist (`can_escalate`, CIEM technique ids).
A deterministic `summary` string is included per asset and for the whole
response.

### Known-ness

Every section has `known`. `known: false` plus `unavailable_reason` means the
section was not measured because its lookup failed. Its other fields are zero
values and are not evidence of safety. The `summary` says "unmeasured" for such
sections. Treat `blast_radius.count: 0` as meaningful only when
`known: true`.

### Bounds

At most 10 identifiers, 5 expanded assets, 5 matches per identifier, 5 entries
per top list, 10 asset types in `by_type`. `truncated: true` means something was
cut: a list, the blast-radius walk, or the findings fetch (counts are then lower
bounds). Free-text fields come from cloud data and are untrusted; over MCP the
whole result is fenced like every other tool.

## Example for a SIEM agent

MCP call:

```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
 "params": {"name": "get_alert_context",
            "arguments": {"identifiers": [
              "arn:aws:sts::123456789012:assumed-role/deploy/i-0123456789abcdef0",
              "203.0.113.7",
              "alice@example.com"]}}}
```

The same through REST:

```sh
curl -sS -X POST "$GRAPH_URL/api/context/alert" \
  -H "Authorization: Bearer $GRAPH_API_KEY" -H "Content-Type: application/json" \
  -d '{"identifiers": ["203.0.113.7", "alice@example.com"]}'
```

Abridged response:

```json
{
  "summary": "2 of 2 identifiers resolved to 2 assets.",
  "truncated": false,
  "identifiers": [
    {"input": "203.0.113.7", "normalized": "203.0.113.7", "status": "resolved",
     "more_matches": false,
     "matches": [{"asset_id": "i-0123456789abcdef0", "match_type": "ip", "confidence": "high"}]}
  ],
  "assets": [
    {"asset": {"id": "i-0123456789abcdef0", "type": "ec2_instance", "environment": "prod", "risk_score": 71},
     "exposure": {"known": true, "exposed_to_internet": true},
     "blast_radius": {"known": true, "count": 14, "by_type": {"rds_instance": 2}, "top_reachable": [], "truncated": false},
     "findings": {"known": true, "total": 5, "by_severity": {"critical": 1, "high": 2}, "must_fix": [], "top": [], "truncated": false},
     "summary": "ec2_instance web-1 (aws, 123456789012, eu-west-1, env prod); risk score 71/100; directly exposed to the internet; blast radius 14 assets; 5 open findings (1 critical, 2 high)."}
  ],
  "omitted_assets": []
}
```

A reasonable triage loop: call `get_alert_context` with everything the alert
names; for each identifier that is `unresolved`, treat the entity as unknown to
Vulngraph rather than clean; for each `known: false` section, retry or fall back to
`investigate_resource` / `run_cypher`; use `must_fix` and `exposed_to_internet`
to prioritise. Pivot to `get_finding_context` for a specific finding.
