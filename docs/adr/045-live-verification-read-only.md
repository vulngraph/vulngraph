# ADR 045 — Live finding verification is read-only, by construction

**Status:** accepted (implemented 2026-07-09)

## Context

A finding is reasoned from the last sync — a snapshot. Analysts asked to *verify*
a finding against the current cloud state before acting ("is this over-privileged
IAM user still attached to that policy right now? is the key really unused?"). The
chat agent already has read-only live tools (`live_aws_describe`,
`get_cloudtrail_events` in `internal/app/mcp/live_aws.go`) that authenticate with a
connector's credentials, so a "Verify live" action on a finding (frontend
`lib/verify.ts`) simply opens the chat with a scoped verification prompt.

This puts an LLM in front of real cloud credentials. That is safe today only
because no mutating tool happens to be wired — safety by omission, not by design.
Two risks:

1. A future contributor could add a mutating tool to the chat path (a
   `terminate_instance` "cleanup" helper) and nothing would stop it.
2. The live path assumes the **collector's** connector role, which for a CSPM
   collector is often broader than read-only. The only thing between the agent and
   a write is that the Go code doesn't call one.

Writes already have a home: the executor + governance gate (ADR 006/030), where a
plan is policy-checked and human-approved. The chat/verify path must never be a
second, ungoverned write path.

## Decision

Make read-only a **positive, enforced property** on two layers of defense.

1. **Tool surface (application layer).** `readOnlyTools` in
   `internal/app/chat/service.go` is the allowlist of every tool the agent may
   invoke. `callTool` refuses any name not on it before dispatch, and
   `TestToolsAreReadOnly` fails if `toolDefs()` ever emits a tool not on the
   list — so adding a tool is a deliberate, reviewed act. Writes are explicitly
   directed to the executor + governance gate, never here.

2. **IAM ceiling (cloud layer).** A connector may declare an optional
   `readonly_role_arn` (+ optional `readonly_external_id`). When set, the live
   path (`liveRole` in `live_aws.go`) assumes *that* role instead of the collector
   `role_arn`. Scoped to AWS `ViewOnlyAccess`/`SecurityAudit`, the assumed role
   physically cannot mutate — so even a bug behind layer 1 can't. Falls back to
   the collector `role_arn` / static keys when unset, so existing connectors keep
   working. The collector authenticates separately
   (`internal/collect/aws/auth.go`) and is unaffected.

The verdict a verification produces is **advisory**: it never executes a fix. A
human still governs any change through the existing queue.

## Consequences

- The read-only guarantee is now testable and tested, not incidental.
- Operators who want the strongest posture add a `readonly_role_arn`; those who
  don't keep today's behavior (read-only tool surface, collector-role ceiling).
- New live capabilities are a conscious allowlist edit with a failing test until
  reviewed — the friction is the point.
