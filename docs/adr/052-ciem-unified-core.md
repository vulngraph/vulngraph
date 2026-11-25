# ADR 052 — One CIEM core: collapse the two privesc engines

**Status:** accepted (implemented 2026-07-10) · amended 2026-07-30 (Azure RBAC evaluated per role assignment)

## Context

There are two independent privilege-escalation engines that share nothing — not
the rule catalogue, not the policy evaluator, not the wildcard matcher:

- **System A** (`internal/app/ciem/`) — bumps asset `RiskScore` and emits
  `can_escalate_to` edges. 66 techniques (28 AWS + 18 GCP + 20 Azure). Full
  evaluator: explicit Deny, boundaries, SCPs, `NotAction`, resource pairs, the
  Azure deny model. Trust-aware (`entryCap` caps the score by `trust_entry`).
- **System B** (`internal/checks/ciem.go`) — emits the `ciem_privesc` **findings**
  at fixed severity. 41 techniques (23 AWS + 18 GCP, **no Azure**). Minimal
  evaluator: allow-minus-exact-deny only; no `NotAction`, no boundaries/SCPs, no
  resource scoping, deny not wildcard-expanded.

Consequences of the split:
- **Findings under-detect.** Azure (all 20) and AWS techniques 24-28 exist only
  in System A, which emits no findings — so they never reach `PrivescCount`,
  `ToxicCombo`, or enrich bucketing.
- **Findings over-detect.** System B's one-directional deny means `Allow "*"` +
  `Deny "iam:PassRole"` still fires PassRole privesc (System A's `subtractDenies` has the same
  wildcard-direction bug).
- **Trust-awareness is half-wired.** System A caps the *RiskScore*; the
  *finding severity* (System B) is fixed, blind to `trust_entry`. The user-facing
  score is moderated only because enrich's `IdentityHygiene` demotes it
  separately — coincidental coverage, not design.

## Decision

Collapse to a single privesc core, System A as the base (strict superset, fuller
evaluator — its deny handling is corrected by decision 3), and have it drive **both**
outputs.

1. **One catalogue, one evaluator.** Delete System B's duplicate rules,
   `effectivePermissions`, `hasAllActions`, `wildcardMatch`. `checks/ciem.go` is removed
   entirely (not converted to an adapter): the core `internal/app/ciem` emits `ciem_privesc`
   findings directly (`AnalysisResult.Findings`), which the sync job maps onto `finding.Finding`.
2. **The core emits findings + edges + score together**, so Azure and AWS 24-28
   finally produce findings, and `can_escalate_to` edges and `PrivescCount` come
   from the same detection.
3. **Fix deny to intersection semantics** — an explicit Deny removes an Allow
   whenever the two *overlap* (bidirectional wildcard match), honoring AWS
   explicit-deny-always-wins. Kills the `Allow "*"` + specific-`Deny` false
   positive.
4. **Trust-corroboration scales finding severity, not just RiskScore.** The
   `entryCap` grade (ADR 050's `trust_entry`) becomes the corroboration sensor
   (ADR 051) for the privesc claim: an IdP-only-assumable escalation path is a
   lower-severity finding, consistently across score, edge, and finding.

## Consequences

- One rule set to maintain; the two catalogues can no longer drift.
- Findings gain 25 techniques (Azure + AWS 24-28) and lose the deny false
  positives — both correctness wins.
- `trust_entry` demotion becomes intrinsic rather than dependent on a separate
  enrich source happening to fire.
- One-time risk: consolidating changes finding volume and scores; ship behind the
  usual correlate-sweep validation and watch `PrivescCount`/`ToxicCombo` deltas.

Cites ADR 050 (`trust_entry` it consumes), 051 (corroboration model it
instantiates for privesc). Amends the implicit two-engine design in
`internal/jobs/sync.go`.

## Amendment 2026-07-30 — Azure RBAC is evaluated per role assignment

Decision 3 ("fix deny to intersection semantics") settled how a Deny meets an
Allow, but not *which* Allows a Deny is entitled to meet. For AWS the answer is
"all of them" — an explicit Deny wins account-wide. Azure is different: RBAC
evaluates each role assignment independently, so an action is granted if some
role's `Actions` match it **and that same role's** `NotActions` do not.

The Azure collector flattened every assignment of a principal into one
`(permissions, not_permissions)` pair, which makes those two questions
indistinguishable. Contributor's exclusion of the whole `Microsoft.Authorization`
namespace therefore cancelled a genuine `Microsoft.Authorization/*` grant from a
stacked User Access Administrator, and the principal read as unable to write role
assignments. Effect: a managed identity holding both roles fired none of
azure-privesc-01/-02/-15.

- The collector now also writes each assignment whole, as a JSON array of
  `ciem.AzureRoleGrant` in `Metadata["role_grants"]`. The flattened pair stays as
  display data and as the read path for principals collected before this existed.
- `EffectivePermission.Grant` names the independently-evaluated grant an entry came
  from. A Deny neutralises only same-`Grant` Allows; an empty `Grant` (AWS, GCP)
  still applies to everything, so nothing about AWS deny semantics changes.
- Intersecting `NotActions` across assignments was rejected as the fix: it trades
  this false negative for a false positive on every single-role Contributor.

The same wildcard exposed a second defect in the other direction. Seven Azure
techniques (azure-privesc-08..14) require **Microsoft Graph** application
permissions — `Application.ReadWrite.All` and friends — not ARM actions. ARM RBAC
and the Entra ID directory are separate authorization planes, but `"*"` matches any
string, so every wildcard ARM role fired all seven at critical severity,
outranking the real ARM findings on the same principal. `azureRulesInScope` now
drops them while every permission a principal holds came from ARM RBAC
(`SourcePolicy: "azure-rbac"`). Nothing collects Graph permissions yet, so they go
correctly dark instead of uniformly wrong, and light up unchanged once a Graph
collector emits permissions from that plane. The plane is declared per rule ID
rather than inferred from the action string: a GCP permission
(`resourcemanager.projects.setIamPolicy`) has the same dotted-no-slash shape, and
guessing would have silenced GCP.

One consequence outside Azure's read path: `principalTier` (the ADR 044
privilege-delta cap) treated any wildcard `Allow` as already-admin, ignoring
denies. Contributor's `Actions: ["*"]` therefore capped every Contributor privesc
finding at low despite Contributor being unable to grant itself a role. A wildcard
now confers admin only where a self-grant route survives the principal's denies.
AWS is deliberately exempt — its self-grant actions *are* the required actions of
aws-privesc-01/05/06, so probing them would cap those rules by their own predicate.
