# ADR 050 — Signal fidelity: confirmed-vs-possible exposure + IAM inbound assumability

**Status:** accepted (implemented 2026-07-10) · amended 2026-08-09 (§1 "only confirmed produces an edge" reversed)

## Context

Many collector-born signals asserted a conclusion that only a *different* sensor
could actually prove. Two cases illustrate this:

- **"public" conflated two different facts.** An S3 bucket with no public-access
  block was flagged identically to a world-readable one; an RDS/CloudSQL/Azure
  SQL instance that is merely network-reachable (credentials still required) was
  flagged as internet exposure; Cloud Run/Functions with open ingress were
  flagged "unauthenticated" though an `allUsers` IAM binding (never collected) is
  what actually decides that. Every one of these emitted an
  `exposed_to_internet` edge and a high-severity finding.
- **Privilege-escalation ignored who can get in.** A role scored on its
  `sts:AssumeRole`-family permissions regardless of whether it was assumable by
  anyone, by one cross-account principal, or only through IdP SAML federation
  (e.g. Okta, IAM Identity Center). The trust policy — the inbound half — was collected but never
  reached the scorer, the graph, or the narrative.

Both are the same mistake: trusting the config-collector alone to assert
reachability/exploitability it can't observe.

## Decision

Grade the signal at the source and carry the grade through the whole pipeline.

1. **`public_access` tier** (`asset.PublicAccessConfirmed` / `Possible`, `""`).
   Collectors set it alongside `public`: *confirmed* = observed unauthenticated
   access (public bucket policy/ACL, `allUsers` grant, no-auth function URL,
   network entry point); *possible* = configuration permits but does not prove
   it (unlocked-but-not-public bucket, API behind optional authorizers, a
   network-reachable but credential-gated database). Only *confirmed* produces an
   `exposed_to_internet` edge (`correlate`); `graphstore.assetPublicTier` maps the
   tier onto the `Asset.public_tier` Ladybug column. CSPM exposure checks fire on
   either tier but grade severity by it (`Check.SeverityFor` +
   `tieredExposureSeverity`) — a public resource still surfaces, just not as
   severe when auth stands in the way.

2. **`trust_entry` class** on `iam_role`, derived from the trust policy:
   `public` (unconditioned wildcard) / `mixed` / `federated` (IdP-only —
   Okta/Identity Center/OIDC) / `cross_account` / `same_account` / `service`,
   with `trust_principals` evidence. `public_trust` is Condition-aware (a
   wildcard scoped by a condition that pins the caller, such as
   `aws:PrincipalOrgID`, is not public; one gated only by TLS, MFA or
   `sts:ExternalId` still is, and MFA on such a path is no control). CIEM
   caps the privesc score bump by inbound assumability (federated/service/MFA →
   medium band, specific-principal → just under high); enrich's must-fix and
   identity-hygiene treat federated/mfa/service entry as a compensating control;
   the chat prompt documents `trust_entry` so narratives weigh SSO-gating.

Ladybug `SchemaVersion` bumped (adds `public_tier` + `trust_entry` columns).

## Consequences

- The confirmed/possible distinction is the platform's first explicit statement
  of **evidence tier** — the seed of the verification-fabric model (ADR 051):
  *possible* = one sensor (config) asserts it; *confirmed* = corroborated.
- Exposure findings and DSPM tiles stop screaming high on auth-gated resources;
  the amber `PUBLIC?` badge keeps them visible without the false urgency.
- IdP-gated privesc (e.g. an admin role assumable only through SSO federation)
  is demoted in score and narrated as controlled, using data already collected.
- Auth-gated services and directly-federated roles are common, so both changes
  materially reduce false urgency in exposure and privesc findings.

## Amendment 2026-08-09 — §1's "only confirmed produces an edge" clause is reversed

`correlate/domain.go` now emits `exposed_to_internet` for **both** tiers, not
confirmed-only.

Reason: `exposed_to_internet` is the only seed of the reachability BFS
(`graphstore/reach.go`). Under the confirmed-only rule, a resource the collector
could not prove unauthenticated — which includes every resource whose collector
does not fetch the extra API the proof needs — was not merely scored lower; it
sat at infinite distance from the internet along with everything downstream of
it. Resource types such as `api_gateway`, `lambda_function` and `cloud_function`
commonly carry `possible`, so the rule removed them from reachability entirely,
and the loss was invisible (nothing counts an edge that was never created). The
`possible`/`confirmed` distinction still travels on the edge as the
`public_access` property and still grades CSPM severity exactly as §1 describes;
it no longer gates graph construction.

§1's text is corrected here rather than rewritten in place, so the history of
what changed and why stays legible — see `correlate/domain.go`'s comment at the
`publicManaged` append for the code-adjacent version of this note.

Cites ADR 043/044 (must-fix / compensating controls this extends), 047 (DSPM
layer), 048 (graphschema), 049 (edge freshness). Superseded-by-extension: the
tier vocabulary generalizes into ADR 051.
