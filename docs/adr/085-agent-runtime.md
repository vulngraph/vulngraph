# ADR 085 — Agent runtime: declarative, budgeted, audited agents on the existing tool loop and governance gate

**Status:** proposed (2026-10-07; runtime not implemented; the §4 step 1 loop extraction, the §7 ledger and global cap, and the `kev.added` record landed 2026-10-08 — see Consequences) · **superseded in part by [ADR 087](087-no-autonomous-remediation.md)** (`auto` autonomy only for observe-class kinds)

## Context

Vulngraph ships as a cloud exposure and posture platform: collectors and scanners build the
graph, an advisory LLM proposes fixes, and a human approves every consequential action.
It is not a SIEM. This ADR proposes adding agents that work the finding queue under the same
rule; no agent runtime ships today. Several building blocks an agent runtime would reuse
already exist, but they are spread across separate places:

- **One tool loop.** `chat.Service.Stream` (`internal/app/chat/service.go`) is a
  provider-neutral (ADR 084) multi-turn tool loop. It has an iteration ceiling
  (`maxChatIterations`), a positive tool allowlist (`readOnlyTools`, `TestToolsAreReadOnly`,
  ADR 045), live tools that are role-gated and audited before the call
  (`live_gate.go`: `liveAllowed`, `liveGate`, `chat.live_read` audit row, refuse if the audit
  write fails), and every tool result fenced (`fencedToolResult` → `pkg/promptfence`).
- **A second tool catalogue.** `internal/app/mcp` exposes a larger, differently-named set
  (`get_asset_context`, `get_finding_context`, `investigate_resource`, `search_assets`, …),
  fences every result, and has two admin-gated writes. One of them is `execute_action`
  (`tools_cloud.go`), which needs a grant from a *different* admin
  (`executor.Approver`, `ApprovalTTL` = 10m).
- **A fixed per-finding pipeline.** `respond.Decide` runs reason → policy gate
  (`internal/policy`, `policy.Decide`, evidence `<Field>Known` pairing per ADR 080) → CoVe →
  outcome. Parked and escalated outcomes cluster in `govern.Queue`. `govern.Resolve` writes the
  verdict, the audit row and the pattern verdict (ADR 082). No decision executes on its own
  (ADR 087): a state-changing fix runs only through the executor, after a person's approval.
- **LLM sweeps on River.** `internal/jobs/adjudicate.go` is a periodic singleton on its own
  queue with a 20-minute `Timeout`, dark behind a flag because it spends budget.
  `internal/scanner/nuclei/template_generator.go` is a generate → validate → correct loop.
  `internal/app/savedquery` runs scheduled read-only Cypher and alerts on result-hash change.
- **An outcome ledger.** `internal/app/memory` (ADR 005) computes confidence only from human
  denials and fixes the executor actually ran (ADR 087). `internal/app/belief` (ADR 053) forms
  severity beliefs only through the corroboration gate.

What is missing is a way to run a goal-directed, cross-finding piece of work unattended. Such
a run needs a stated scope, a budget and a reviewable record, and must not create a second
path around govern/executor. Without a runtime, every new "agent" becomes another bespoke
sweep with its own prompt, its own loop and its own idea of safety. That is how the chat and
MCP catalogues already drifted apart.

## Decision

An **agent** is a declarative definition that the runtime executes on the shared tool loop,
inside River, under a budget. Its only writes are **proposals** that existing domains carry
out after a human approves them. Agents add no new authority. They add a scheduler, a scope
and a record around authority that already exists.

### 1. Definition

New domain `internal/app/agent` (four-file layering). The `Definition` domain type:

| Field | Meaning |
|---|---|
| `name` | slug, unique; the audit actor is `agent:<name>` |
| `instructions` | natural-language task. This is the only trusted prompt text besides the runtime's own system block |
| `trigger` | `schedule` (cron), `event` (one of §2's kinds plus an optional filter), or `manual` |
| `tools` | allowlist of tool names from the shared catalogue (§4) |
| `autonomy` | per proposal kind (§5): `auto` / `jit` / `disabled`. Missing means `disabled` |
| `output` | name of a registered output contract (JSON Schema), validated in Go (ADR 004/084 rule) |
| `budget` | per-run caps (§7) |
| `enabled` | per-agent kill switch |

First-party definitions (ADR 086) are embedded in the binary and read-only. Operator-authored
definitions live in Postgres and are writable only by admins through `auth.RequireRole`. When
a definition is loaded, every tool name is checked against the catalogue and every autonomy
key against the known proposal kinds. An unknown name **rejects the definition**. It is never
silently dropped. Every run records the SHA-256 of the definition it ran under, so editing a
definition cannot rewrite the history of past runs.

### 2. Triggers

- **schedule**: cron, evaluated the way `jobs/saved_query.go` already does (per-minute tick,
  stale ticks skipped).
- **event**: a closed set of kinds, each emitted at an existing chokepoint after its write
  succeeds:
  `kev.added` (`KEVWorker.flag`, findings newly flagged), `finding.opened` and
  `finding.state_changed` (the `RecordObserved`/`Resolve` lifecycle writers, ADR 054),
  `savedquery.changed` (the branch of `savedquery.Service.Run` that calls `AlertQueryChange`),
  `proposal.decided`, `remediation.executed` (executor execute audit). The ClickHouse writes
  are not transactional with River, so delivery is at-least-once: the run is inserted after
  the write, and the unique key (§6) dedupes it.
- **manual**: `POST /api/agents/{name}/runs` with an optional subject.

Events can be lost when a pod dies between the write and the insert. For that reason every
event-triggered agent also declares a **reconcile schedule**, which is a sweep for subjects
with no run (for example, KEV-flagged findings with no brief). An event source that errors is
logged and counted, never read as "nothing happened".

### 3. Execution on River

One kind, `AgentRunArgs{Agent, Subject}`, on a new queue `agent` with an explicit worker count
(2) in `queueWorkerCounts`. It is consumed by the worker pod and never shares `respond`. Agent
work must never starve decide or executor jobs (CLAUDE.md, Jobs). Rules:

- **Uniqueness**: `UniqueOpts{ByArgs, ByState: uniqueStates}` with `Subject` as the key. This
  gives at most one live run per (agent, subject). A schedule's subject is the tick window.
- **MaxAttempts: 1.** A run spends budget, and its proposals are not idempotent. A failure is
  recorded, and the next trigger is a new run.
- **Timeout**: the worker's `Timeout()` returns the definition's wall-clock budget, capped
  at 15 minutes (the `adjudicate.go` pattern).
- **Cancellation**: `POST /api/agents/runs/{id}/cancel` → River job cancel. The loop checks
  `ctx` before every model call and every tool call. A cancelled run keeps its partial
  transcript and its status is `cancelled`.
- **Global switch**: `AGENTS_ENABLED` (default off, like `ADJUDICATOR_ENABLED`). With no LLM
  configured, agents are off, which matches ADR 084's degradation.

### 4. One loop, one catalogue (the refactor seam)

There is no second tool loop. The refactor has two steps, and each lands with its tests:

1. **Extract the loop.** Move it from `chat.Service.Stream` into `internal/llm/toolloop`:
   `Run(ctx, client, req, Dispatcher, Limits, Observer) (Transcript, error)`. `Dispatcher` is
   `Tools() []llm.Tool` plus `Call(ctx, name, input) (string, bool)`. `Limits` holds
   iterations, tool calls, tokens and the deadline. `Observer` receives each text delta,
   model turn and tool step. Fencing moves into the loop, so no caller can forget it.
   `Stream` becomes a thin caller (`Observer` emits text, `maxChatIterations` = 12), and the
   chat tests pin unchanged behaviour. The package depends only on `internal/llm`.
2. **Extract the catalogue.** Move chat's `toolDefs`/`callTool`/`readOnlyTools`/`liveTools`
   into a tool catalogue, `internal/app/toolbox`. Each entry is `{Name, Class, Def, Call}`,
   where `Class` is `read`, `live` or `propose`. Two tests carry over and get stronger.
   `TestToolsAreReadOnly` becomes: every class is one of the three, and a `propose` tool's
   only side effect is inserting a proposal row. `liveGate` becomes a wrapper applied to
   `live` entries. Chat takes `read`+`live` entries, and agents take exactly their allowlist.
   MCP keeps its names. New tools are added to the toolbox only, and MCP adopts toolbox
   entries over time. Merging MCP fully is out of scope.

**There is no `execute` class.** Of all the tools in the platform, only MCP's `execute_action`
mutates the cloud, and the toolbox never offers it to an agent.

### 5. Autonomy maps onto the existing gate

Agents write only through `propose` tools, which create rows in `agent_proposals`.

| Kind | Carried out by (after approval) | Action class |
|---|---|---|
| `brief`, `verification`, `note` | published by the runtime | `observe` |
| `group` (root-cause collapse), `route` (owner) | `finding` metadata writer | `modify` |
| `suppress` (with evidence + expiry) | `suppress.Service` | `modify` |
| `saved_query` | `savedquery.Service.Create` | `modify` |
| `remediate` (executor action + dry-run plan) | `executor.Service.Execute` | the plan's class |

The effective mode is the **most restrictive** of three: the definition's autonomy for the
kind, `policy.Policy.ActionRules[class]`, and `policy.Gate.Evaluate` on a `policy.Input`
built from measured evidence (with its `Known` pairing). Only `observe` can be `auto` in
practice. `remediate` is never auto (ADR 087), and the
destructive subset always needs the two-person grant (`executor/approval.go`). The approving
admin is the principal on the executing context. The agent can never be the approver or the
executor, and the run and proposal ids go into the audit `Details`. Remediation proposals
reuse `govern.PatternVerdict` (ADR 082), so a pattern a human already denied is not
re-proposed.

### 6. Storage

Postgres (goose migrations, written with the implementation):
`agent_definitions` (operator-authored only), `agent_runs` (agent, subject, trigger,
definition hash, status, token and tool-call counters, error, timestamps) and
`agent_proposals` (kind, payload JSONB, evidence JSONB, cited entity ids, status
`pending|approved|denied|expired|superseded`, `expires_at`, `decided_by`). Proposals are
mutable state, and approving one must `river.InsertTx` the follow-up job in the same
transaction, so they belong in Postgres.

ClickHouse: `agent_run_steps` is an audit table (plain `MergeTree`, 7-year TTL). It holds one
row per model turn and per tool call: tool, input (truncated to `maxAuditedInput`), result
size and hash, `is_error`, tokens and duration. Run start, run end and each proposal also
write a row to the shared `audit_events` with actor `agent:<name>`.

### 7. Budgets, fail closed

- **Per run**: iterations, tool calls, input+output tokens and wall clock, from the
  definition, each clamped to a platform maximum. When any cap is reached, the run ends with
  status `budget_exhausted`. A partial run publishes no proposal unless its output contract
  validates.
- **Global monthly cap**: `AGENT_MONTHLY_TOKEN_BUDGET`, with tier prices configured to show
  cost. Every LLM call, from any feature, appends to an `llm_usage` ledger (feature, run id,
  model, tokens). Agents check the ledger **before** each model call. Over the cap, runs stop
  starting and in-flight runs end at their next call. Interactive chat keeps its per-user rate
  limit (`auth.RateLimitPerUser`) and is not cut off by agent spend.
- **Wrap-up before the cap** (`toolloop.Limits.WrapUp`). Once any cap is that fraction spent,
  the next model call carries an extra system block telling the model to answer from what it
  has, and tool calls it still asks for are answered without running. The tool list is left
  unchanged so the prompt cache still hits. Chat uses 0.8.
- **Parallel reads, bounded queries.** One turn's independent tool calls run together
  (`toolloop.Limits.MaxParallelTools`, results kept in order); a Dispatcher marks tools that
  must run alone (`toolloop.Serial`: chat's live tools, so gate checks and audit rows keep
  their order). Every database query a chat tool call triggers carries a
  `pkg/querybudget` budget: `internal/db` adds a client timeout, a server-side
  `max_execution_time` (only ever tightening a caller's own) and a `query_id`, so an
  expensive question cannot hold a ClickHouse slot for minutes. Parallel calls still share
  the per-process ClickHouse semaphore, which bounds query count, not bytes.
- **Unknown usage counts as used.** If a provider reports no usage, the request's
  `MaxTokens` is charged. If the ledger cannot be read, the run is refused with status
  `budget_unknown`. An unknown spend is never read as zero spend (ADR 080).

### 8. Run log

`GET /api/agents/runs`, `GET /api/agents/runs/{id}` (transcript from `agent_run_steps`, plus
the run's proposals), and a frontend run view built through `api.ts`/`queries.ts`. Shapes
go in `openapi/domains/agent.yaml`. Writes (run, cancel, approve, deny, definition CRUD) are
admin-gated, and each gets a `TestXxx_NonAdmin_403`.

### 9. Safety

- **Fencing.** Every tool result and every trigger payload (a finding title, a CVE
  description) is fenced inside the loop. The system block repeats chat's untrusted-data
  instruction (ADR 042).
- **No self-widening.** The allowlist, autonomy and budget come from the pinned definition,
  never from model output. No tool reads or writes agent definitions, and a test pins it. A
  proposal kind that is not in the agent's autonomy map is refused at insert time.
- **Grounding.** Every proposal lists cited entity ids, and each must appear in a tool result
  from the same run. This is the `respond/grounding.go` rule. An ungrounded proposal is
  rejected and logged as a run-quality failure.
- **Principal.** A run carries a synthetic principal `agent:<name>` with role `analyst`,
  never admin. `live` tools additionally need `AGENT_LIVE_TOOLS=true`, and they assume the
  connector's `readonly_role_arn` (ADR 045) when one is set.
- **Read tools vs write tools.** Write tools are proposals. Raw Cypher stays behind
  `graphquery.IsReadOnly` + `UnsafePattern` (ADR 036).

### 10. Evaluation

- **Unit tests** script a fake `llm.Client` and a fake `Dispatcher`. They cover budget stops,
  cancellation, refused tools, ungrounded proposals and output-contract rejection, and they
  run in normal CI.
- **Replay.** `-tags=eval` suites per first-party agent (`internal/app/agent/eval_test.go`),
  in the style of ADR 038 (`internal/reason/eval_test.go`). Recorded tool results become a
  fixture `Dispatcher`, and assertions run on the structured output, never on prose. A change
  to a first-party agent's instructions ships only with a passing eval against the configured
  provider.
- **Operator replay.** For operator definitions, `POST /api/agents/{name}/replay` re-runs
  the definition against the recorded tool results of past runs and reports output diffs.
  It creates no proposals.

### 11. Agents and the learning loop

Agent output never writes `memory.Outcome` or `belief` rows. An agent judging that something
"looks fixed" or "looks like a duplicate" is not an outcome. Approvals and denials of agent
proposals feed **per-agent quality metrics** (acceptance rate per kind), not autonomy
confidence. Only real-world sources write to the ledger: a person's denial (`govern.Resolve`),
a fix the executor ran (`govern.RecordExecution`), and the fix verifier's observed verdict
(ADR 086), recorded with a `DedupeKey` of the execution id.

## Alternatives considered

- **An external agent framework or a sidecar runtime.** Rejected. It would mean a second
  language and process next to the single binary (ADR 001), outside depguard, the fencing,
  the audit trail and the role model. External agents remain welcome as **clients** over MCP
  or the REST API, where they hit the same gates.
- **A second loop built for agents.** Rejected. The iteration cap, fencing and allowlist
  would drift between two loops. The chat and MCP catalogues show that this happens.
- **Giving agents write Cypher.** Rejected (ADR 036). Ladybug is also a disposable projection
  that is rebuilt from ClickHouse, so a write would be lost or would resurrect stale state.
- **Autonomous execution.** Rejected for now. Confidence trains only on real outcomes
  (ADR 005/030), and none exist yet. When execution becomes real, autonomy arrives through the
  existing gate, not through an agent setting.
- **Extending `respond.Decide`.** Rejected. It is a fixed per-finding pipeline whose
  determinism the eval gate relies on, while agents are goal-directed and work across many
  findings. Agents use it (pattern verdicts, context packs) and leave it unchanged.

## Consequences

- Each agent is about one page of configuration plus an output contract. Scope, cost and
  record are uniform and reviewable.
- Chat behaviour must not change during the loop extraction. Its tests are the regression
  pin.
- Prerequisites this design cannot ship without:
  - **Done (2026-10-08):** token usage and the spend cap. `llm.Response.Usage` carries
    disjoint input, output, cache-read and cache-write counts from both backends, streaming
    included, with `Reported=false` when the provider sent none. `internal/app/llmusage`
    records every call from every feature in `llm_usage` (Postgres) through
    a metering `llm.Client` that cmd/graph hands each consumer with its purpose
    (`TestLLMConsumersAreMetered`). Unknown usage is charged at `llm.ChargeableUsage`'s worst
    case. Two deviations from §7: the cap is in dollars (`LLM_MONTHLY_BUDGET_USD`, costed
    from the `LLM_PRICES` table), not `AGENT_MONTHLY_TOKEN_BUDGET`, because token prices
    differ by model and class; and "interactive chat is not cut off by agent spend" is a
    purpose policy. The global cap counts all spend and gates background purposes (reason,
    adjudicate, ct_triage, agent, and any purpose not on the interactive list), which an
    unreadable ledger refuses with `budget_unknown`. Interactive purposes (chat, nl_query,
    refine, template_gen) are gated only by the optional
    `LLM_INTERACTIVE_MONTHLY_BUDGET_USD` over their own spend, and proceed when the ledger
    is unreadable. `GET /api/llm/usage` (admin) and Settings > LLM Usage show it. The
    per-run `run_id` column waits for `agent_runs`.
  - **Done (2026-10-08):** the loop extraction (§4 step 1). `internal/llm/toolloop.Run`
    owns the loop, fencing (`FenceResult`), refusal of unoffered tool names, the
    iteration/tool-call/token/deadline caps and cancellation; `chat.Service.Stream` is a
    thin caller, pinned by `internal/app/chat/loop_test.go`. Step 2 (the toolbox) is open.
  - `audit_events` has no read API, so the run log needs its own.
  - **Done (2026-10-08):** the KEV diff. The catalog now keeps `dateAdded`, and
    `internal/app/kevwatch` diffs every refresh against `kev_catalog` (Postgres),
    writing one `kev_added_events` row per newly listed CVE, keyed by CVE for
    idempotency, committed with the catalog upsert. The first refresh seeds the back
    catalog and records only the previous 7 days. `GET /api/kev/additions` lists them.
    This diffs the catalog rather than the flagged set: a CVE joining KEV is the event even
    when no finding matches it yet, and the record carries the open-finding count at
    detection. River insertion of the triggered run is left to the runtime.
  - The govern queue is built from `reasoncache` entries only, so proposals need their own
    queue view.
