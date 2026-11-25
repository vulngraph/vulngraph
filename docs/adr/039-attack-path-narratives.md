# ADR 039 — Deterministic attack-path narratives

**Status:** accepted (implemented 2026-07-06)

## Context

The graph already knows *why* a finding does or doesn't matter — exposure, blast
radius, the identity chain, the deployed-vs-installed supply-chain path. But that
"why" was only available as structured fields the analyst had to read and assemble
themselves (or obtain by asking the chat assistant). A plain-English risk story
("internet → Lambda → admin role → N databases in blast radius") is far quicker to
act on; the signals existed but the sentence did not.

## Decision

Generate the risk story **deterministically from signals already in the
`ContextPack`** — no LLM call. `internal/app/findingctx/narrative.go`'s
`buildNarrative` composes ordered clauses (what/where + CVE exploitability →
exposure → reachability/blast → identity chain → supply-chain deployed-vs-
installed → a one-line verdict → fix location) into a few sentences. It is a
field on `findingctx.FindingContext`, so it is served by the finding-detail API
(`narrative` in the response) and returned by the MCP `get_finding_context` tool,
and rendered as the lead "Risk story" block on the finding-detail page.

Why deterministic templating, not an LLM:

- **Free and stable.** No token cost, no latency, no drift — the story is a pure
  function of the graph state, so it is unit-testable and never hallucinates.
- **The reasoner stays authoritative.** `respond.Decide`'s rationale remains the
  judgement of record (and is still shown, below the narrative). The narrative is
  the *framing*, not the decision — it never invents a verdict the signals don't
  support (the verdict clause is derived from exposure/blast/KEV/deployed flags).
- **It explains false positives.** When the signals show a KEV CVE that is present
  but not deployed and not reachable, the narrative says exactly that — a
  graph-grounded explanation of why the finding is low risk.

## Consequences

- Every finding gets a readable one-paragraph story, at no cost, everywhere the
  context is served (UI + MCP + any A2A client).
- The narrative and the API contract move together: the `narrative` field is in
  `openapi/domains/finding.yaml` and the generated frontend client, checked by the
  spec-drift gate.
- **Limit:** it is templated, so its expressiveness is bounded by the clauses
  coded. Richer, per-finding prose (if ever wanted) would be an LLM enhancement
  layered on top — but the deterministic base must always be present and free.

Cites ADR 025/026 (the graph signals it narrates), 030 (the reasoner whose
rationale it frames, not replaces), 021 (the ContextPack it reads).
