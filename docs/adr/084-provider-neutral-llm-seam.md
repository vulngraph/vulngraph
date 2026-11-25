# ADR 084 — Provider-neutral LLM seam (`internal/llm`)

**Status:** accepted (amends ADR 004)

## Context

ADR 004 chose to call the Anthropic Go SDK directly, deliberately sacrificing provider
flexibility for a single-tenant deploy. For a self-hosted open-source project it is a hard adoption barrier: operators have an existing
contract with OpenAI, Azure OpenAI, Google, or a gateway such as OpenRouter/LiteLLM, or must
keep all data on-prem with a local model (Ollama, vLLM). Seven call sites constructed their
own Anthropic client from `ANTHROPIC_API_KEY`, so "bring your own provider" meant editing
each one.

ADR 004 anticipated this: "reintroducing a gateway later is additive, not a rewrite." This
ADR is that addition — as an in-process interface, not a gateway service.

## Decision

1. **One seam.** `internal/llm` defines a small provider-neutral `Client` (`Complete`,
   `Stream`) over neutral request/response types: system blocks with a cache hint,
   multi-turn messages, tool calls/results, an optional JSON-Schema output constraint, an
   optional reasoning budget, and a model *tier* (`Default` / `Fast`). Every LLM feature —
   reasoner, adjudicator, NL→query translators, chat, plan refinement, CT triage, nuclei
   template generation — calls through it. depguard (`llm-quarantine`) forbids provider
   SDK imports anywhere else.
2. **Two backends.**
   - `anthropic` keeps everything ADR 004 bought: adaptive thinking (behind the model
     allowlist), prompt caching, server-side structured outputs, refusal stop details.
     An `ANTHROPIC_API_KEY`-only deploy is byte-for-byte the same request shape and the
     same default models as before.
   - `openai` speaks the Chat Completions wire format over plain `net/http`, which covers
     OpenAI, Azure OpenAI, OpenRouter, Gemini's OpenAI endpoint, Groq, LiteLLM, Ollama,
     vLLM and LM Studio via `LLM_BASE_URL`. No vendor SDK: the surface is small and the
     wire format is the compatibility contract.
3. **Features state needs, backends map them.** A schema-constrained caller asks for
   `JSONSchema` + `Reasoning`; Anthropic maps that to `output_config.format` + adaptive
   thinking, OpenAI-compatible servers to `response_format: json_schema` (non-strict) and
   optionally `reasoning_effort`. ADR 004's rule stands unchanged: behaviour-driving output
   is validated against its schema in our code regardless of what the provider enforces.
4. **Configuration** (`llm.FromEnv`): `LLM_PROVIDER`, `LLM_API_KEY`, `LLM_BASE_URL`,
   `LLM_MODEL`, `LLM_FAST_MODEL`, `LLM_REASONING_EFFORT`; `ANTHROPIC_API_KEY` /
   `OPENAI_API_KEY` alone still work. No configuration = LLM features off (unchanged
   degradation: 503s and heuristic triage). A configuration that names a provider but is
   unusable fails startup.

## Consequences

- The reasoning-quality gate (ADR 038, `-tags=eval`) now runs against whichever provider
  is configured — it is the instrument for deciding whether a non-Anthropic model is good
  enough for remediation decisions. Prompts were tuned on Claude; other models are
  supported, not equally validated. Run the eval before trusting one for remediation
  proposals (Vulngraph never remediates autonomously, ADR 087).
- Provider-specific features beyond the shared surface (Anthropic thinking display,
  compaction, server tools) need an explicit field on `llm.Request` before a feature may
  use them — that friction is intentional.
- Per-call-site model pins were replaced by tiers. One visible change: nuclei template
  generation previously defaulted to `claude-sonnet-5`; it now uses the default tier
  (`LLM_MODEL`), overridable with `TEMPLATE_GEN_MODEL`.
- Tool-use loops replay only text and tool calls between turns, never provider thinking
  blocks. No current loop enables thinking; one that does must extend `llm.Message`.
