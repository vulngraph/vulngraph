# ADR 089 — Ownership and routing: one owner per asset, stamped on findings, routed by channel scope

**Status:** accepted (2026-10-08) · amended 2026-10-09 (alerts that reached no channel)

## Context

A finding answers "what is wrong"; a team that can fix it needs "whose is it" and "where does
it run". Vulngraph had pieces of both and no single answer:

- The remediation reasoner read an owner from five hard-coded tag keys
  (`respond/contextpack.go`), and enrich picked a declaring repo from `defined_in` edges for the
  fix hint (`bestIaCOwner`, `enrich/safety.go`). Each read its evidence its own way, so the fix
  hint and the reasoner could name different repos for the same resource, and neither result was
  stored anywhere a list could filter on.
- Environment was classified per asset (`asset.ClassifyEnvironment`, ADR 080's fail-closed
  reading for anything that guards a change), but only the asset page showed it. Findings, which
  live in ClickHouse beside but apart from assets, had neither.
- Alert channels routed on event type, severity and score. A payments team could not get only
  its own findings, and a finding nobody owned went everywhere or nowhere.
- The finding detail endpoint did not return its suppression state, so the panel's
  Suppress/Unsuppress toggle always offered "Suppress".

## Decision

### 1. One owner resolver, with a source and a confidence

`asset.ResolveOwnership` is the only resolver. Tiers, strongest first, the first that answers
wins:

1. **Explicit tags**: `owner`, `Owner`, `team`, `Team`, `app.kubernetes.io/part-of`, with the
   operator's `OWNER_TAG_KEYS` consulted before them. Confidence high.
2. **A repo's own CODEOWNERS** catch-all rule, for findings keyed to a `github_repo`.
3. **The repo that declares the resource** (`defined_in`, emitted by the tf/k8s-manifest/image/
   declared-identity ownership correlators), refined to a team by that repo's CODEOWNERS
   rule for the declaring file's path. A claim with no path (tfstate knows addresses, not files)
   meets only the catch-all rule and is capped at medium. With no matching rule the repo itself is
   the owner (`repo:org/name`). Confidence is the edge's.
4. Otherwise **unowned**: `source = none`. Unowned is a real, visible state.

CODEOWNERS refines the IaC claim instead of competing with it as a separate tier: it can only be
reached through the declaring repo, and routing needs a team, not a repo. Owners are normalised
(lower-case, `@org/team` reduced to `team`) so a CODEOWNERS handle meets the same team's tag.

The resolver's zero value is "unresolved", kept distinct from `none`. A failed graph read is an
error and stays unresolved; it is never reported as unowned (CLAUDE.md, "a zero value is not a
measurement"). `respond` reads the tag tier through `asset.TagOwner` and enrich's fix hint picks
its repo through `asset.BestDefiningEdge`, so all three consumers agree. `respond` keeps the raw,
un-normalised tag value because it feeds the reason fingerprint, which must not churn.

The GitHub collector stamps each repo's CODEOWNERS onto the repo asset
(`metadata.codeowners`), batched over GraphQL like branch protection. A file that is oversized
or truncated by the API is dropped, not cut: CODEOWNERS is last-match-wins, so a truncated tail
would hand its paths to broader rules and name the wrong team.

### 2. Owner and environment are denormalised onto findings, in `finding_enrichment`

Option (a), stamped columns, was chosen over (b), a join to `assets` at query time. The list's
filters are already post-aggregation over every finding id (CLAUDE.md, "LIMIT bounds a result
set, not an aggregation"); joining `assets` with `inventoryReadCond` on every page read would add
a second whole-table aggregation to the hot path, for values that change rarely.

The columns (`owner_team`, `owner_source`, `owner_confidence`, `environment`) live in
`finding_enrichment`, not `findings`. Producers rewrite the whole findings row on every
observation and know nothing about owners, so a column there would be reset to empty by the next
sync (the shape ADR 075 removed for scores). Enrich is that table's only writer. It stamps both
values beside the score, from the asset it already fetched for the safety and must-fix
assessments. The KEV refresh carries them forward from its `ByIDs` re-read like every other
enrichment output.

The list filters on them inside the `finding_enrichment` subquery (`HAVING argMax(…)` with an
INNER JOIN) rather than adding columns to the outer per-id aggregation, which keeps the page
selection as narrow as before. `GET /api/findings/summary` gains `by_owner` and
`by_environment` facets. Both keep the empty "not yet resolved" bucket apart from `unowned` and
`unknown`.

**Backfill and staleness.** An `enrichcache.LogicVersion` bump triggers the existing full
re-enrichment pass (ADR 069), which stamps the open corpus. After that, a finding re-stamps on
every enrich: at ingest, after correlate, and at least every `ENRICH_MAX_AGE` (24h). A tag or
CODEOWNERS change therefore reaches a finding's owner within a day.

### 3. Channels route by owner and environment scope

Alert channels gain `owner_teams`, `environments` and `route_unowned`, alongside event
type, severity and minimum score. All rules AND together. An empty scope admits everything, as
with event types. A scoped channel admits only notifications that carry the dimension it is
scoped on: an owner-scoped channel never receives phishing or approval events, which have no
owner. This is the same rule as the severity filter, where an unmeasured field is not the
permissive case. `route_unowned` makes a channel the default for unowned findings. Findings whose
owner is unresolved route as unowned too, so an alert always reaches someone. `unknown` is a
listable environment and is not folded into `prod`: a prod-scoped channel that also received
every untagged resource would drown in them.

Finding alerts route on the owner and environment enrich just persisted (returned on
`enrich.Score`); decision alerts route on the values stored on the finding.

### 4. Finding detail returns suppression standing

`GET /api/findings/{id}` returns `is_suppressed`, `exception_expired`, `suppression_expires_at`,
reason and actor, and `suppression_known`. When the suppression store cannot be read,
`suppression_known` is false and the UI offers no toggle rather than a guess.

## Consequences

- One function answers "who owns this" for the reasoner, the fix hint, the asset page, the
  findings list and alert routing.
- Until that pass reaches a finding, its owner is unresolved: it counts in the facet's empty
  bucket, matches no owner filter, and routes as unowned.
- Owner changes reach findings on enrich cadence, not instantly.
- CODEOWNERS adds GraphQL queries to each GitHub sync, at 50 repos per query.

## Rejected

- **A query-time join to `assets`** for the list's filters: a second unprunable aggregation on
  every page read.
- **Columns on `findings`**: reset by every producer write.
- **CODEOWNERS as a tier above the IaC repo**: CODEOWNERS can only be reached through the
  declaring repo, so it refines that claim rather than competing with it.
- **Treating `unknown` environment as prod for routing**: prod routing would fill with untagged
  noise. Change-guarding paths keep reading it fail-closed (`TreatAsProd`).

## Amendment (2026-10-09) — alerts that reached no channel

- **An owner no channel is scoped to routes as unowned.** IaC-tier owners (`repo:org/x`) and
  tagged teams without a channel matched no owner-scoped channel and, having an owner, were
  skipped by `route_unowned` defaults too. Dispatch now treats an owner absent from every
  enabled channel's `owner_teams` as unowned for routing; the owner stays on the message.
- **An unclassified environment routes as `unknown`.** A failed seed read left it `""`, which
  every environment-scoped channel rejected.
- **Package findings route to their runners.** A purl has no tags or `defined_in`, so every
  package finding resolved to unowned/unknown. Enrich now resolves the owner of what runs or
  depends on the package — the most common owner among its internet-exposed runners, else among
  any (at most five owner lookups) — keeping the runner's tier, capped at medium confidence,
  with `runner:<id>` in the evidence; the environment is the most production-like among the
  same runners. A failed read leaves routing unresolved, never unowned.
- **A notification no channel accepts is counted** (`graph_notify_delivery_total` with status
  `no_recipient` and an empty channel) and logged at warn.
