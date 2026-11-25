# ADR 086 — First-party agents and the closed loop: exposure hunter, triage, least privilege, fix verifier, query authoring

**Status:** proposed (2026-10-07; design only, nothing implemented; depends on ADR 085)

## Context

ADR 085 proposes the runtime, which is not implemented. This ADR proposes what the first
agents would do; none of them ships. The goal is the product loop: **fewer findings, each
with evidence, and a fix that is proven.** A finding should arrive as one root cause with the
attack path that makes it matter. Anything that changes state reaches a human as a proposal
with the evidence attached. A fix counts only once the platform has observed it.

Every agent below uses only ADR 085's machinery: an allowlist from the toolbox, proposals
for anything that changes state, fenced inputs, cited entity ids, and run budgets. "Tools"
means toolbox names. Where a tool does not exist yet, it is marked *new* and is a read or
propose tool over an existing service.

## Decision

### 1. Exposure hunter

**Purpose.** When a CVE becomes known-exploited (or an admin names a high-profile CVE),
answer "are we exposed, where, and through what path" in **one brief per CVE**, not one
finding per package instance.

- **Trigger:** event `kev.added`; manual with `{cve}`; reconcile schedule hourly (KEV CVEs
  with matching open findings and no brief).
- **Tools:** `list_findings` (needs a CVE filter, *new* param, backed by the existing
  `finding.Filter.CVEIn`), `get_finding_context`, `get_asset`, `run_cypher`,
  `blast_radius` (*new*, over `asset.BlastRadius`), `propose_brief`, `propose_group`.
- **Instructions sketch:** "List every finding for the CVE. Group the affected packages by
  where they run: container image digest, VM, or function. For each group, establish
  internet reachability with fixed-hop Cypher over `RunsPackage`/`RunsImage`,
  `ExposedToInternet` and `DnsPointsTo`. Then find what identity the workload holds and whether that
  identity reaches an admin-equivalent role (`ExecutesAs` → `CanAssume`/`CanEscalateTo`). Name
  the root cause, for example the base image or a shared package version, and the fixed
  version. Report what you could not measure as unknown, never as zero. Cite every claim with
  an entity id from a tool result."
- **Output contract `exposure_brief`:** CVE; affected counts by host class, each paired with
  `<Count>Known`; the reachable subset with path evidence (node and edge ids); identity paths
  to admin; root-cause groups; recommended fix; an explicit `unknowns` list (for example
  "14 images never scanned", "Ladybug not ready").
- **Approval points:** the brief is `observe` and auto-published to the UI and to notify
  channels. `propose_group` (collapse the per-instance findings under the root cause) is a
  `modify` proposal for human approval.
- **Metrics:** time from KEV flag to brief (target under 1h); briefs per KEV CVE (target 1);
  reachable-claim precision on human spot checks; fraction of affected hosts that were
  `unknown`.

Caller-supplied Cypher caps variable-length paths at depth 6 in the engine (ADR 095), so
"reaches admin" is a bounded path query (`*1..N`, N ≤ 6) plus `blast_radius`. The brief states
the hop bound it used.

### 2. Triage agent

**Purpose.** Shrink the open queue without hiding anything: collapse duplicates by root
cause, propose suppressions with evidence and an expiry, and route each finding to an owner.

- **Trigger:** schedule every 6h; event `finding.opened`, batched by the River unique key
  per tick window.
- **Tools:** `list_findings`, `get_finding_context`, `get_asset`, `run_cypher`,
  `propose_group`, `propose_suppression`, `propose_route`.
- **Instructions sketch:** "Work open findings oldest-first within the budget. Group findings
  that share a cause you can cite: the same image digest, IAM policy, security group, or IaC
  declaration (`DefinedIn*` edges, ADRs 061/065/070). Propose a suppression only for an
  observed compensating control, a non-production scope proven by tags or account, or a
  documented design. Give the evidence and an expiry of at most 90 days. Route to the owner
  that ownership edges, the defining repository or owner tags name. If no owner is evidenced,
  say so."
- **Output:** proposals only. A suppression proposal carries `reason_category`, evidence
  references and `expires_at` (default 30d, maximum 90d, matching
  `respond.PatternVerdictMaxAge`).
- **Approval points:** every proposal is `modify` and needs an admin. Approved suppressions go
  through `suppress.Service`, which already writes `suppress.suppress` audit rows, with the
  approver as actor and the proposal id in `Details`.
- **Metrics:** open queue items per root cause (should fall); proposal acceptance rate per
  kind; suppression regret (suppressions revoked early, or the finding escalating while
  suppressed); median time to owner.

### 3. Least-privilege agent

**Purpose.** For dormant or over-privileged identities, propose a concrete least-privilege
change with its blast-radius delta. Nothing executes without approval.

- **Trigger:** weekly schedule; event `finding.opened` for dormant-identity and privesc check
  ids.
- **Inputs it reads:** identity metadata (`inactive`, `password_last_used_days`,
  `active_key_count`, `sa_last_auth_days`); AWS Access Advisor
  (`aa_services_granted`/`aa_services_used`/`aa_used_services`/`aa_last_used_days`, from
  `collect/aws/iam.go`, best-effort); CIEM effective permissions with SCP and boundary caps
  (ADR 066); privesc edges.
- **Tools:** `get_asset`, `run_cypher`, `list_findings`, `blast_radius`, `whatif_blast_radius`
  (*new*), `propose_remediation`.
- **Output contract `privilege_diff`:** current grants → proposed grants (policy document
  diff, or a role-binding diff on GCP/Azure); evidence window; blast radius before and after;
  confidence; and `UsageKnown`. **Missing Access Advisor keys mean unknown usage, never
  unused.** Without usage evidence the agent may propose only removing privesc-enabling
  actions, never "remove everything unused".
- **Approval points:** `remediate`, class `modify`, mode never above `jit`, executed by
  `executor` with the approving admin as principal. The executor has no IAM-policy edit
  action today (`iam_key_disable` is the only IAM action). The first deliverable is therefore
  the diff plus an IaC patch suggestion for the owning repository. An executor action comes
  later, inside the two-person destructive subset.
- **Metrics:** permissions removed per approved proposal; blast-radius reduction; breakage
  rate (rollback or access-denied regressions within 14 days; needs §7 to measure).

### 4. Fix verifier

**Purpose.** Close the loop. After a remediation, prove the fix from observation and feed
the outcome ledger. Otherwise, reopen the work.

- **Trigger:** events `remediation.executed`, `proposal.decided` (approved `remediate`), and
  `finding.state_changed` (resolved with `ReasonFixed`); reconcile schedule daily for
  remediations with no verdict.
- **Tools:** `get_finding_context`, `get_asset`, `run_cypher`, `blast_radius`;
  `live_aws_describe` when `AGENT_LIVE_TOOLS` is on; `propose_verification`.
- **Procedure:** wait for the next completed sync of the affected scope. A partial sweep is
  not evidence (ADR 054/083). Then check that the finding resolved with `ReasonFixed`, that
  the resource state matches the remediation (live read if allowed), and that the paths cited
  in the original brief or decision are gone.
- **Output `verification`:** `verified_fixed` | `not_fixed` | `unknown`, with the evidence
  ids. `unknown` (sync incomplete, resource unreadable, graph not ready) is a first-class
  verdict and never rounds to either side.
- **Approval points:** the verdict is `observe` and auto-published. The verifier never writes
  finding state: resolution remains sync-driven (ADR 054). `not_fixed` notifies the approver
  and re-queues the original proposal.
- **Learning:** `verified_fixed` → `memory.Outcome{Success: true, DecidedBy: "verifier",
  DedupeKey: <execution id>}`; `not_fixed` → `Success: false`; `unknown` → nothing. It
  confirms that a fix the executor ran actually held. It never makes execution autonomous
  (ADR 087).
- **Metrics:** verification latency; `unknown` fraction; regressions caught (a fix reverted
  within 30d).

### 5. Saved-query authoring

**Purpose.** Turn "alert me when a public bucket holds PII" into a reviewed, standing
detection. The loop mirrors `nuclei.TemplateGenerator.Generate`.

- **Trigger:** manual, from the saved-query UI, with a natural-language description.
- **Loop (max 3 attempts, like `maxGenerationAttempts`):** draft Cypher, validate it with
  `graphquery.IsReadOnly` + `UnsafePattern` + a required `LIMIT`, then dry-run it against the
  current graph. On a validation error, an engine error, or zero results the agent judges
  implausible, it gets a correction turn carrying the error.
- **Dry run needs a preview path.** `savedquery.Service.Run` always records a run row and
  updates the change-detection baseline. A preview mode that records nothing is a
  prerequisite.
- **Output:** a `saved_query` proposal with the Cypher, the match count, sample hits (node
  ids and names, fenced), a suggested schedule, and `alert_on_change`. The approving admin
  becomes `CreatedBy`.
- **Scope:** Go `checks.Check` predicates are compiled code and cannot be authored at
  runtime. Check authoring is limited to saved queries. A saved query alerts through notify.
  It does not create findings.
- **Metrics:** drafts approved unedited; attempts per accepted draft; post-approval false
  alerts (queries disabled within 14d).

### 6. Optional evidence port

Agents 3 and 4 are better with activity evidence, but neither requires it. ADR 085's
runtime gets an optional, vendor-neutral read port in a new domain:

```go
// ActivitySource summarises observed activity. Nil disables it.
type ActivitySource interface {
    PrincipalActivity(ctx context.Context, principalID string, window time.Duration) (Activity, error)
    ResourceActivity(ctx context.Context, resourceID string, window time.Duration) (Activity, error)
}
// Activity is a summary: actions used, last seen, denied-call counts. Known=false
// means the source could not answer, never that nothing happened.
```

Adapters summarise cloud audit logs (provider audit-log services) or forward to an external
SIEM over a generic query adapter. OCSF is the normalisation target. The platform does not
become a log store: adapters return summaries, never raw events.

- **Agent 3:** action-level usage replaces service-level Access Advisor, which allows a
  tighter diff, and it covers GCP and Azure where no Access Advisor key exists.
- **Agent 4:** denied-call spikes after a change reveal breakage, and post-fix activity on the
  removed path confirms nothing still depends on it.
- **Without the port:** both agents report `UsageKnown=false` and narrow their proposals
  (§3). The existing chat `get_cloudtrail_events` (72h LookupEvents) is an investigation
  tool and is not a usage source.

### 7. Phased implementation

1. **Prerequisites.** Token usage on `llm.Response` and the `llm_usage` ledger; loop
   extraction to `internal/llm/toolloop` with chat behaviour pinned; the toolbox; the
   `internal/app/agent` domain, tables, `agent` queue, run-log API and UI.
2. **First release: runtime + exposure hunter + triage, observe only.** Briefs publish. Triage
   proposals are recorded in **shadow** (stored and reviewable in the run log, but kept out of
   the approval queue) so acceptance can be measured by sampling before anyone is asked. The
   KEV diff (`kev.added`) ships with it.
3. **Triage live.** Proposals reach the queue; suppression expiry, finding grouping and
   owner routing land in their domains; saved-query authoring with the preview path.
4. **Fix verifier**, feeding memory.
5. **Least privilege:** diffs and IaC patches first, then an executor IAM action under the
   two-person rule.
6. **Evidence port** adapters, opt-in per connector.

Each phase ships with its `-tags=eval` replay suite. A phase is done when the previous
phase's metrics show the agent is accepted. Shipping the code alone does not finish a phase.

## Alternatives considered

- **Per-instance findings plus a summary.** Rejected. The queue stays as large as before,
  and the root cause is the unit a human can act on.
- **Auto-applying triage suppressions above a confidence.** Rejected. A suppression hides
  risk, and no outcome signal exists to calibrate it. Every suppression is human-approved and
  expires.
- **An agent that resolves findings itself.** Rejected. Resolution is an observation
  (ADR 054). An agent asserting "fixed" is exactly the zero-value-as-measurement failure
  ADR 080 forbids.
- **Making the evidence port required.** Rejected. Many self-hosted deployments have no
  centralised audit logs, and the posture loop must work on configuration alone.

## Consequences

- The first release is useful without risk: briefs and shadow proposals change nothing.
- The closed loop depends on agent 4. Until it runs, the platform can propose fixes but
  cannot claim them.
- Gaps in existing code, beyond ADR 085's list:
  - Findings have no owner field and no root-cause or grouping model.
  - Suppressions have no expiry and are hard-deleted on unsuppress.
  - The executor has no IAM-policy edit action.
  - `asset.BlastRadius` has no what-if (edge-removed) variant.
  - `savedquery` has no non-recording preview.
  - The chat `list_findings` tool has no CVE filter.
  - `govern.Resolve` records an approval as a successful memory outcome, which is a governor
    judgment and not an observed result. Agent-proposal approvals must not use that path
    (ADR 085 §11).
