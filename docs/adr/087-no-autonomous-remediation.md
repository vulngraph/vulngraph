# ADR 087 — No autonomous remediation: Vulngraph proposes, a person says yes

**Status:** accepted (2026-10-07) · amended 2026-10-08 (approve and run) · supersedes in part ADR 005, 006, 030, 080, 082 and 085

## Context

The decision pipeline (ADR 030) was built to act on its own once it earned the right to.
`agent.rego` granted `allow_auto` to a non-destructive action at high confidence with a
measured blast radius of 10 or fewer assets. The automation policy added an `auto` mode per
action class, with `auto_threshold` and `blast_radius_cap`, and the governor queue relabelled
qualifying items `auto_executed`. The enrich band at score 61–80 was called `auto`, "an
auto-remediation candidate".

None of this ever changed a cloud account. `respond.ExecutionsAreSimulated` was `true`: an
`auto_executed` decision was recorded, notified and written to the outcome ledger as a
simulated success, and nothing ran. The real mutations only ever happened through the
executor's two transports, the admin HTTP endpoints and the MCP `execute_action` tool, each
driven by a person.

The project's decision is that this stays true permanently, and is no longer a matter of a
flag:

> Vulngraph must never automatically execute a remediation (any cloud or state mutation). It
> provides guidance; a remediation runs only after an explicit human yes. Read-only actions
> and non-mutating outputs may still run on their own. The two-person approval rule and the
> executor's approval and grant flow are how the human yes happens, and stay unchanged.

A capability that exists but is switched off is still a capability. One flipped constant, a
policy row set to `auto`, or a new worker could turn it on. The aim is that no such path exists.

## Decision

**No state-changing action proceeds without a person.** Concretely:

1. **The gate grants autonomy only to `observe`.** `policy.Decide` grants `AllowAuto` in one
   case, conditioned on `in.ActionClass == classObserve` (`"observe"`). Every other class is
   `NeedsApproval`, or `Escalate` on low or insufficient confidence. The gate no longer reads
   blast radius, and `policy.Input` no longer carries it. The gate weighs nothing about the
   estate, so it has no evidence fields to pair. The known-ness convention (ADR 080) still
   applies to any field added later. `TestAutoExecuteGateRequiresKnownEvidence` fails on any
   `AllowAuto` grant that is not in a `Decide` case conditioned on exactly observe (the gate was
   rego when this ADR was written; ADR 006's 2026-10-24 amendment records the move to Go). `TestGate_NoStateChangingInputIsAutonomous` sweeps every
   class, including unknown ones, against every confidence band.
2. **No outcome claims an execution.** An observe plan resolves to `observed`; the other
   outcomes are `parked_for_approval`, `escalated` and `suppressed_by_verdict`, and none of
   them means something ran. A decision carries no `simulated` flag, and neither does the
   decision webhook. Its `action` is `parked_for_approval` or `escalated`, a proposal and
   never an authorisation.
3. **Memory learns only from people.** The simulated auto-success write in `respond.Decide`
   is deleted, and `respond.NewService` no longer takes an outcome recorder, so the pipeline
   cannot vouch for itself. The only writer of `action_outcomes` is a human verdict
   (`govern.Resolve`) — and, since the approve-and-run amendment below, only a denial there;
   successes come from fixes that actually ran (`govern.RecordExecution`). The queue
   (`POST /api/queue/resolve`) refuses an API key, so a verdict comes from a signed-in
   session or a confirmed email link, never from a key an agent may hold. Confidence
   decides how urgently a person is asked (park or escalate), never whether one is asked.
4. **The policy has no autonomy knobs.** `ModeAuto`, `auto_threshold` and `blast_radius_cap`
   are removed from the domain, the API and the settings UI. The modes are `jit` ("Requires
   approval") and `disabled` ("Guidance only"), and a write naming `auto` is rejected with a
   400. The policy has no `auto_threshold` or `blast_radius_cap` columns.
5. **No background path can execute.** The never-wired `ExecutorWorker`/`ExecutorArgs` River
   job is deleted rather than left waiting for a producer. `executor.Service.Execute` refuses a
   real execution when no authenticated principal is on the context (`ErrNoPrincipal`). This
   check runs before the grant check, the intent audit row and the cloud call. Both transports
   a person drives attach one, and a job, sweep or pipeline call would not.
   `TestOnlyHumanTransportsBuildExecutionRequests` walks the module and fails if an
   `ExecutionRequest` is built anywhere except `executor/handler.go` and the MCP
   `execute_action` tool, and it requires the MCP request to keep `RequireGrant: true`.
6. **Every proposal carries its guidance.** Each decision in `GET /api/decisions` carries a
   `remediation` block from `executor.GuideFor`. The block gives the same plan text the dry run
   and the grant bind to, whether a second admin is needed, a rollback (or, for the rule
   deletes, what to save first), and the equivalent `aws`/`gcloud`/`az` command. It also
   carries the finding's must-fix evidence and the source's own fix advice. The decision detail
   panel shows all of this next to the approval buttons.
7. **The 61–80 score band is the high-urgency tier.** Its Go name is `BandHigh` and its
   stored and wire value is `high`; no code path keys execution off it.

## What "a person said yes" means

For a non-destructive action, it is an admin in a signed-in session calling the executor's
HTTP endpoints. For the destructive subset, for **every** action requested over MCP, and for
**every** action requested with an API key (an LLM client or agent may hold an admin key), it is
also a grant minted by a **different** admin from a signed-in session (whose account is at least
a day old by default), bound to the exact plan text (ADR 015 and `executor/approval.go`).
The destructive subset is the actions that destroy state nothing in the request or audit row
can restore (`ec2_stop`, `iam_key_disable` with `delete_key`, `gcp_firewall_remove`,
`azure_nsg_rule_remove`) or that undo a containment (`ec2_start`). Being able to cause an
outage is not the test: revoking world ingress, disabling a key and blocking public bucket
access can each break a dependent service, but each is undone exactly from its request and
audit row (`s3_block_public` records the bucket's earlier block before it changes it, and
refuses when it cannot read it; a revoked ingress rule's free-text description is not kept), so
one admin's request runs them (`executor/plan.go` `never`, pinned by
`TestDestructiveSubset_IsExactlyTheIrreversibleActions`). An API
key can never mint a grant (`Service.Approve` refuses it, whatever the action). Approving a decision in the governor queue records the verdict and
hands the fix to the configured approval notifier. Vulngraph does not run the fix itself at that
point; running it in Vulngraph is a separate, explicit executor call — today the decision panel's
approve-and-run below.

### Approve and run

*Amendment (2026-10-08).* A person's yes should be enough to run the fix. The
decision detail panel's "Approve & run" does that through the executor's existing path —
`Execute`, `Approve`, the grant, the intent row — with no second execution path:

- **Which connector.** The one enabled connector whose sync currently collects the resource
  (`connector_asset_hashes`). None, several, a connector of the wrong type, a read-only one or
  one without an execution role makes the plan *guidance only*, with the reason. Vulngraph never
  picks between owners.
- **What runs.** The decision's resource fixes the parameters the finding carries; a person
  types only the rest (a rule's protocol and CIDR, a key id), and cannot override the others.
  A dry run shows the exact plan text before anything else.
- **Confirmation.** A destructive or irreversible fix is confirmed by typing what it changes
  (the instance id, the rule name); the server checks it, not only the UI.
- **Two people.** The first admin's approval mints the grant (`Approve`, so their account must
  meet the age floor), bound to the plan, and parks the decision. A **different** admin's
  confirmation runs it as the executor (`Verify` refuses the same person and flags a shared
  address); the age floor is applied to the confirming admin too, so a fresh second account
  cannot be the second person. The grant lives only server-side, for its 10-minute lifetime.
- **Guards.** Requests are still built only in `executor/handler.go`: the service takes a
  builder from the transport, so `TestOnlyHumanTransportsBuildExecutionRequests` keeps its
  allowlist. `TestRunDecision_RefusesWithoutAPersonOrSecondAdmin` holds the panel to the same
  line as `Execute`.
- **Outcomes.** The decision's run state lives in `decision_executions`.
  Only a fix the executor actually ran is recorded as the decision's outcome
  (`govern.RecordExecution`: verdict approved, a trail row, one success sample). Approving a
  decision no longer writes a success sample — it is a yes to try, not evidence the fix worked
  — which corrects item 3 above and the "real outcomes only" conflict noted in ADR 085.
  Denials still write a negative sample.

## Alternatives considered

- **Keep the autonomy machinery behind `ExecutionsAreSimulated`.** Rejected. The flag made
  autonomy one constant away. The machinery also produced records ("auto_executed",
  "simulated success") that read as actions, and every reader had to discount them.
- **Keep `auto` as a policy mode that behaves like `jit`.** Rejected. A setting whose name
  promises autonomy and whose behaviour denies it misleads whoever reads the policy. It also
  invites someone to "fix" it later.
- **Rename the stored band value.** Rejected: the value is opaque on the wire and the UI
  labels it "high", so a rename would touch every reader of `score_band` for a label.
- **Gate the HTTP execute endpoint on a grant for every action.** Taken for API keys only. A
  signed-in admin's explicit request is the yes described above, and for a session the
  two-person rule is scoped to the destructive subset (ADR 015). A request on an API key needs a
  different admin's grant for every action (`viaAPIKey` in `executor/service.go`), because the
  key may be held by an automation with no person behind it.

## Consequences

- There is no `auto` policy rule to set: a write naming `auto` is rejected with a 400
  (decision 4), every state-changing remediation waits in the approval queue for a person,
  and no decision is recorded as `auto_executed`.
- The decision webhook carries no `simulated` field and never sends `action: auto_executed`.
- The respond package no longer depends on memory for writes. Only govern feeds the ledger.
- Read-only work still runs unattended: observe decisions, briefs, scans, enrichment and
  notifications. These are outputs, not mutations.

## Supersedes in part

- **ADR 005:** "high = autonomous (still OPA-gated)". The high band now parks for approval
  like medium. Confidence routes between park and escalate only.
- **ADR 006:** the gate decides how a proposal reaches a person, not whether it runs. The rego
  no longer has a `destructive_actions` set, because with no state-changing autonomy there is
  nothing for it to exempt.
- **ADR 030:** step 3's `auto` mode, auto threshold and blast-radius cap, and step 4's
  execute-class River jobs. Execution happens only on a person's request through the executor
  transports.
- **ADR 080:** the instance it fixed, the blast radius in `policy.Input` gating `allow_auto`,
  is gone with the rule itself. The convention and its guard remain for any future evidence
  field.
- **ADR 082:** the references to "auto-execution" as the path an APPROVED pattern must not
  open. An APPROVED pattern still only annotates.
- **ADR 085:** an agent definition's per-kind `autonomy` may be `auto` only for observe-class
  kinds (briefs, verifications, notes). Every state-changing proposal kind, including group,
  route, suppress, saved_query and remediate, is `jit` or `disabled`, whatever the definition
  says.
