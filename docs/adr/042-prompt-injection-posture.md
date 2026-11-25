# ADR 042 — Prompt-injection posture

**Status:** accepted (documents the current posture and its limits) · amended by ADR 095

## Context

The platform feeds untrusted, attacker-influenceable text into LLMs: asset names and tags, finding
titles and descriptions, scanner output, resource metadata — all of it can be set by whoever
controls the cloud resource or the scanned target. Two LLM surfaces consume it: the reasoning path
(`internal/reason` + `respond.Decide`) and the chat/NL→Cypher path (`internal/app/chat`). A
prompt-injection posture had never been written down.

## Decision

Defense in depth, accepting that no single control is sufficient:

1. **Fenced untrusted text.** The reasoner gets a typed `ContextPack` and renders it into one
   prompt string through a fixed template in code (`buildPrompt`, `internal/reason/reason.go`):
   the labels and layout are Vulngraph's, and every attacker-influenceable string in it
   (finding title and description, check and resource IDs, CVE fields, peer-finding titles,
   repo IDs) is interpolated inside `<<<UNTRUSTED>>> … <<<END UNTRUSTED>>>` delimiters by
   `promptfence.Fence`, which neutralises any marker the text itself carries so it cannot close
   the fence. `TestBuildPrompt_EveryStringFieldIsFenced` seeds a canary through each listed field and fails if
   one appears unfenced. The system prompt tells the model that fenced text is data, never
   instructions; chat fences page context and tool results the same way. The model still reads
   one prose prompt, so fencing makes injection harder but does not prevent it: controls 2–6
   are the boundary.
2. **Grounding validation.** After the model returns a plan, any AWS type-prefixed resource ID
   (`i-`, `sg-`, `vol-`, …) or ARN it cites is checked against the ContextPack
   (`respond/grounding.go`); one the model was not given forces escalation to a human. GCP,
   Azure, Kubernetes and bare asset IDs are not checked.
3. **CoVe guardrails.** Chain-of-verification checks force escalation on high-blast/destructive/
   production shapes regardless of what the rationale claims (`respond/cove.go`).
4. **The model proposes, a person disposes.** Nothing executes on the model's say-so. The
   policy gate (`policy.Decide`) classifies each proposal (only `observe` may proceed without
   a person; ADR 087), and a state-changing action runs only when an admin calls the executor,
   which checks the role, any required second-admin grant and the connector mode itself
   (ADR 006, ADR 015). An injected
   "just remediate everything" yields a proposal parked for a person.
5. **Read-only, allowlisted Cypher.** LLM/NL-generated Cypher passes the single read-only guard
   (ADR 036) — no writes, no `LOAD`/`INSTALL`/`ATTACH`/`CALL`. Query-shape bans were lifted
   (ADR 095). Cost is bounded in the engine by `var_length_extend_max_depth =
   cypherMaxPathDepth` (6) on untrusted-Cypher connections
   (`internal/app/graphstore/ladybug_pool.go`), so a coerced query cannot mutate the graph, and
   a deep traversal is a binder error, not an outage.
6. **Scoped tool access.** Chat/MCP tools are role-scoped (`gph_` keys, session role); an injected
   instruction can only reach tools the caller already holds. State-changing actions (executor,
   respond decisions, suppressions) and live cloud reads from MCP and chat (`mcp.live_read` /
   `chat.live_read`) are written to `audit_events`. Ordinary read calls over REST, MCP and chat
   (findings, assets, Cypher) are not audited; they get only OpenTelemetry request spans, and only when OTLP export is configured.

## Consequences

- The blast radius of a successful injection is bounded to *read* actions the caller is already
  authorized for, plus one write: an MCP client on an admin key can call `suppress_finding`, which
  needs no second person but is limited to low-urgency findings (critical, must-fix, page/high-band
  and unscored findings are refused), expires within 30 days and is audited as `mcp:<user>`.
  Every other write needs a different admin's approval grant. No cloud resource is changed
  without a human approval; `suppress_finding` changes only Vulngraph's own finding state.
- **Limits:** the model's *rationale text* can still be manipulated (it is prose); we
  mitigate by never trusting it for authorization and by grounding the entities it cites. We do
  not run a dedicated injection classifier on inputs, and system prompts are not cryptographically
  isolated from context — the structural controls above are the defense, not input sanitization.
- New LLM surfaces must reuse these controls (fenced untrusted text + grounding + policy gate +
  read-only Cypher), not invent a parallel path.

Cites ADR 036 (read-only Cypher allowlist), 030 (policy gate + agentic pipeline),
005 (real-only autonomy confidence), 015 (scoped tool access).
