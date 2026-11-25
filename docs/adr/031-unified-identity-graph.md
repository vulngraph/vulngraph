# ADR 031 — Unified identity graph (human identities)

**Status:** accepted

## Context

The graph modelled machine identities (IAM roles/users, service accounts) but not the
*humans* behind them. The most valuable security questions cross that boundary: "which person
can reach this admin role," "who owns the repo that deploys this exposed workload," "this
breached role — whose laptop/SSO is behind it." Cloud and code already federate to human
IdPs (Okta, Google Workspace, GitHub), so the join exists in the world — it just wasn't in
the graph. Without human identities, every attack path dead-ended at a role.

## Decision

Human identities are first-class graph nodes, collected from the IdPs and federated into the
existing identity edges.

- **Collectors:** `internal/collect/okta` (Okta users + group membership via the REST API)
  and `internal/collect/google` (Google Workspace users via the Admin SDK, domain-wide
  delegated SA JWT auth). Each emits `Asset{Type: "human_identity", Provider: okta|google}`
  with email in the `Domain` field. Registered as connector types `okta` / `google_workspace`.
- **Correlation** (`HumanIdentityFederation`): links humans to repos they own (email→GitHub
  login) via `Owns`, and to cloud roles via `FederatedAccess` (OIDC subject ↔ email). The
  correlate `Graph` indexes `human_identity` by lowercased email so matching is O(records).
- **Surface:** an Investigate → Identity tab (humans by provider, admin/suspended flags,
  last-login, click-through to the asset/blast-radius), plus Cypher over the new edges.

## Consequences

- Attack paths and blast radius now extend to people: "human → FederatedAccess → role →
  CanEscalateTo → admin" is a single query — the cause behind a compromised role is reachable,
  extending lineage beyond what a cloud-only graph can express.
- Human identities are stored as `Asset` (type `human_identity`), not a bespoke node table —
  reuses the whole asset/finding/graph pipeline; a dedicated Ladybug `HumanIdentity` label is
  not built (it would be a SchemaVersion bump for marginal gain).
- **Trade-off:** federation matching is heuristic (email prefix ↔ GitHub login, OIDC
  subject ↔ email). High-precision but not guaranteed; mismatched email conventions miss
  edges. Azure AD / Entra users are not yet collected (Okta + Google + GitHub only).

Cites ADR 026 (graph schema — humans reuse the Asset node), 025 (reachability — humans extend
blast radius), 016 (OIDC auth model that makes the federation edges meaningful).
