# ADR 079: The identity census is computed server-side, and every narrowing is reported

**Status:** accepted (2026-08-21)

## Context

The Identity page's three headline numbers were arithmetic done in the browser
on `/api/assets/summary`'s `by_type` counts:

```ts
const humanCount   = (byType.human_identity ?? 0) + (byType.iam_user ?? 0);
const machineCount = byType.gcp_service_account ?? 0;
const roleCount    = byType.iam_role ?? 0;
```

`by_type` is a count of asset ROWS. Each of those three lines asks a question
rows cannot answer, and two of the three could be wrong in both directions at
the same time.

**"N human identities" overstated and understated simultaneously.** The
`iam_user` population mixes several things that are not people:

- account **root** principals (`arn:…:root`);
- access-key-only service users (`console_access = false`) — CI systems and
  other programmatic integrations;
- console-capable, non-root principals, where a row is still not a person: the
  same human typically holds an IAM user in every AWS account they work in, and
  may appear under an email-shaped username, a bare username, and differing
  casing.

At the same time the tile counted federated humans as zero whenever
`human_identity` was empty, even though AWS Identity Center (permission sets,
groups and `AWSReservedSSO_*` landing roles) is a common way people reach the
cloud. `internal/app/chat/service.go` at the time told the LLM that "The platform
collects NO human identities" (since removed).

**"N workload identities" was one cloud under a cross-cloud label.** It was
`gcp_service_account` and nothing else. The cross-cloud population also includes
K8s service accounts, Azure service principals, and the AWS IAM roles that the
graph *already proves* a workload runs as — Lambda and ECS roles behind
`executes_as` edges, IRSA roles behind `federated_access`.

**The IAM role count was correct under a misleading label.** It reconciles
exactly (raw rows → `uniqExact(id)` across accounts, no double-count), but the
population is not one thing:

| class | meaning |
| --- | --- |
| `unattributed` | no workload edge, no plumbing marker |
| `workload` | proven by `executes_as` / `federated_access` |
| `platform` | service-linked, `service-role/`, CDK, CloudFormation, Control Tower |
| `human_federation` | `AWSReservedSSO_*` |

So the **human** federation surface sat in a machine-role tile, workload roles
were missing from the workload tile, and stale roles (not seen in over 30 days,
for example because an account's collection stopped) were counted as current.

The tab badge compounded this: `machineCount + roleCount` added two populations
that overlap, because those AWS roles ARE the AWS workload identities.

## Decision

**1. The census is a backend measure, not browser arithmetic.**
New domain `internal/app/identity` serving `GET /api/identity/summary`. It
computes distinct people, cross-cloud workload identities, and the role split
from principal metadata (`console_access`, `inactive`) plus the graph's
`executes_as` / `federated_access` edges — inputs the browser does not have and
should not be reconstructing. `by_type` stays what it is: a filter-UI row count.

Classification and dedup are pure functions over fetched rows
(`identity/classify.go`, `census.go`), table-tested against examples of each
shape, rather than a `multiIf` buried in SQL. ClickHouse supplies rows and
aggregates; Go supplies the judgements. The result is cached for 5 minutes
(`identity.cacheTTL`).

**2. One person is one person.** The dedup key is the lowercased local part of an
email-shaped name, else the lowercased name — so an email-shaped username and its
bare form collapse. It deliberately stops short of stripping separators, which
would merge some additional variants of the same name but would also merge
genuinely different people whose names differ only by punctuation. On a security
platform an over-merge silently deletes an identity from the census, so the
conservative key is the right trade: residual duplicates inflate the count rather
than hide an account.

**3. Every narrowing is reported, never dropped.** This is the binding
constraint, not a nicety — under-counting identities hides attack surface.
`root_principals + programmatic + console_principals` equals the raw `iam_user`
count by construction, and that invariant is a test. The distinct programmatic
IAM users excluded from "people" appear as `workloads.programmatic_iam_users`;
the Google auto-created default service accounts are counted in the workload
total AND broken out; the roles a live workload edge points at with no inventory
row are reported as a coverage hole.

**4. Staleness is exposed, not silently applied.** `staleness.stale_accounts`
names every account whose *newest* identity sighting is already past the 30-day
threshold (`identity.StaleAfter`), ranked by size and capped at 20
(`maxStaleAccounts`). The census does not quietly filter them out — a "current"
figure that shrinks without explanation is as untrustworthy as one that is
inflated. The UI turns that into a banner: "N identities above are last-known
state, not current."

This is orthogonal to ADR 078's `inventoryReadCond`. No identity asset type is
ephemeral (`k8s_pod`/`container`/`k8s_job`) or `declared_*`, so that gate is a
no-op here and the two surfaces agree; the census's own 30-day measure is
stricter, and reported rather than enforced.

**5. Workload roles come from live edges only.** The workload-role set applies
`graphschema.EdgeFreshnessCond`. Edges are never deleted, only left un-restamped
until TTL, so without the filter a deleted Lambda's role would stay "assumed by a
workload" indefinitely.

**6. Federated humans are collected by expanding GROUP membership.** The
`human_identity` emitter in `internal/collect/aws/identitycenter.go` fired only on
`PrincipalTypeUser` account assignments, so it was unreachable in any
organization that assigns permission sets exclusively to groups. `collectSSO` now
walks `identitystore:ListGroupMemberships` for every group that holds a
permission set and emits each member as a `human_identity` keyed on its resolved
primary email.

Assets only, no edges. A group→user relationship needs a new `graphschema` rel
and a `SchemaVersion` bump; pointing it at an existing rel whose declared
From/To labels do not match would silently drop every row at Ladybug load — a
recurring label-promotion defect class in this graph. The asset is what the
census counts, and `correlate`'s `HumanIdentityFederation` joins these people to
roles and repos by email without needing a direct edge. The group is kept as
`sso_group` metadata so *why* a person has cloud access stays auditable.

Membership lookup is best-effort per group: an `AccessDenied` on one group
records on the resolver's existing fallback counter (logged at WARN with the
first error) instead of losing every other group's members. The collector role
needs `identitystore:ListGroupMemberships`; without it the collector logs why and
yields no members, which is a stated absence rather than a silent zero.

## Consequences

- Three honest tiles, each carrying its own decomposition and its own excluded
  population. The role tile shows purpose, not a single number implying a single
  machine-identity count.
- The tab badge shows `workloads.total` — one deduplicated figure — instead of
  summing two overlapping populations.
- The People tab's list header is relabelled "Principals": it is one row per
  (identity, account), including root and key-only service users, with the
  deduplicated headcount stated alongside.
- Where group membership is collected, `chat/service.go`'s prompt line "The
  platform collects NO human identities" was false. Follow-up, since done: the
  line has been removed from the prompt.
- `unattributed` roles are deliberately *not* presented as a safe residue. The
  class is the honest "we do not know who assumes this", which makes it the one
  most worth investigating.
