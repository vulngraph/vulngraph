# ADR 066: SCP + permission-boundary caps for CIEM effective permissions

**Status:** accepted (2026-07-19) · amended same day (post-acceptance correction: reversed-wildcard intersection fix)

## Context

The CIEM evaluator (`internal/app/ciem/evaluator.go`) has always been able to
intersect an identity's permissions with a **permission boundary** and a
**Service Control Policy** (`EvaluateEffectivePermissions`, the `PolicyBoundary`
/ `PolicySCP` cases) — but the AWS collector only ever wrote `identity` and
`trust` policies, so both intersection paths were dead code. Every privesc /
admin finding was therefore computed from the identity policy alone and
**overstated** whenever the grant was actually capped by a boundary or denied by
an SCP: a role with `Allow *` behind a boundary that permits only `s3:*`, or a
`iam:PassRole` grant denied org-wide by an SCP, still fired a Critical.

Two collection realities shape the design:

- **Permission boundaries are per-principal** but `ListRoles`/`ListUsers` do not
  return them — only `GetRole`/`GetUser` do (the same quirk as `RoleLastUsed`).
- **SCPs are per-account and org-scoped.** Only the management or a
  delegated-admin account can call the Organizations API; a member account gets
  `AccessDenied`. But CIEM runs **per-connector** on each account's own
  principals — so the SCPs a member account is subject to are never in that
  connector's collect result.

## Decision

**Permission boundaries** (`internal/collect/aws/iam.go`): capture the boundary
ARN from the `GetRole` call the collector already makes for admin-ish roles (zero
extra API calls) and via a scoped `GetUser` for admin-ish users. Resolve the
document through the existing managed-policy cache and store it as a
`type:"boundary"` `policyDoc`. `isAdminish` skips `boundary`/`scp` types so a
boundary named/containing `AdministratorAccess` can't self-flag a constrained
principal as admin.

**SCPs** (`internal/collect/aws/scp.go`): a new best-effort collector that runs
on every AWS connector but cleanly no-ops on any account that can't `ListRoots`
(exactly the Identity Center pattern). On the management/delegated-admin account
it walks each member account's parent chain (account → OU… → root), collects the
distinct SCPs attached at every level, and emits **one `aws_scp_set` asset per
account** carrying them as `type:"scp"` `policyDoc`s. `aws_scp_set` is in
`NeverSyncTypes` — it is CIEM analysis input, never a Ladybug node.

**Consumption** (`internal/jobs/sync.go` + `internal/app/ciem/service.go`): the
sync worker fetches the `aws_scp_set` asset for each account in the sweep
(`aws_scp:<accountID>`) and hands them to `AnalyzeIAMAssets`, which appends the
account's SCP policies to each AWS principal. The evaluator then intersects them
exactly like a boundary. Fail-open throughout: a missing boundary or SCP asset
means no cap — the prior behaviour.

**Deliberate simplification:** the evaluator unions SCP allows across OU levels
then intersects once, rather than AWS's true per-level intersection. This can
only **over-permit** (never over-suppress a finding), so it is conservative in
the safe direction — a finding the real SCP chain would have blocked might still
fire, but a finding the real chain allows is never hidden.

## Consequences

- Boundary-capped and SCP-denied privesc/admin findings stop being overstated;
  the most common SCP pattern (`FullAWSAccess` + targeted `Deny` SCPs)
  works the moment the documents arrive, because Deny statements from any policy
  type already flow into the evaluator's `allDenies`.
- A boundary/SCP document that fails to parse now **fails open** (skip the cap)
  rather than erroring the whole principal's evaluation — a malformed cap must
  never make a genuine admin finding vanish.
- Freshness: the `aws_scp_set` asset refreshes on the management connector's
  sweep; a member sweep in between caps against slightly-older SCPs, which is
  acceptable and visible via the asset's `LastSeen`.
- Out of scope: RCPs (resource control policies), per-level intersection
  fidelity, and reading boundaries for non-admin-ish principals (they don't
  produce the admin/privesc findings a boundary would demote).

**Post-acceptance correction (same day):** the initial
implementation did not actually hold the "a finding the real chain allows is
never hidden" guarantee above — `intersectPermissions`
(`internal/app/ciem/evaluator.go`) had a reversed wildcard match, so an
identity holding `Allow *` intersected against a *specific* boundary action
(e.g. `s3:*`) never matched, collapsing to **empty effective permissions** and
silently suppressing every privesc finding on any boundaried admin principal —
the opposite of the intended fail-safe direction. Fixed same-day. Two related
collection hardenings landed alongside it: the `ListRoots` eligibility probe
in `internal/collect/aws/scp.go` now no-ops only on `AccessDenied` /
`OrganizationsNotInUse` (any other transient error previously no-opped too,
which could trigger deletion-reconciliation and wipe every `aws_scp_set`
asset), and the org **management account** is now explicitly excluded from
SCP capping (via `DescribeOrganization`), since SCPs never apply to it.
