# LLM providers

Vulngraph uses an LLM for remediation reasoning, the severity adjudicator, natural-language →
graph query translation, the investigation chat, plan refinement, CT-log phishing triage
and AI nuclei template generation. **All of it is optional** — with no provider configured
those features are off (503 / heuristic triage) and inventory, graph, checks, scanning and
scoring all run normally.

Any provider works through one of two backends (design: [ADR 084](adr/084-provider-neutral-llm-seam.md)).

| Variable | Meaning |
|---|---|
| `LLM_PROVIDER` | `anthropic` or `openai` (any OpenAI-compatible server). Empty = inferred. |
| `LLM_API_KEY` | API key for that provider. Not needed for a keyless local server. |
| `LLM_BASE_URL` | Endpoint override. Required for every OpenAI-compatible server that isn't OpenAI itself. |
| `LLM_MODEL` | Capable model (reasoning, chat, translation). Required on `openai`; defaults to `claude-opus-5-5` on `anthropic`. |
| `LLM_FAST_MODEL` | Cheap model for high-volume triage. Defaults to `claude-haiku-4-5` / `LLM_MODEL`. |
| `LLM_REASONING_EFFORT` | `openai` only: `reasoning_effort` (`low`/`medium`/`high`) for reasoning models. |
| `REASON_MODEL`, `ADJUDICATOR_MODEL`, `TEMPLATE_GEN_MODEL` | Per-feature model overrides. |

Inference when `LLM_PROVIDER` is empty: `ANTHROPIC_API_KEY` set → anthropic;
`OPENAI_API_KEY` set → openai; only `LLM_BASE_URL` set → openai (local server).

## Examples

```sh
# Anthropic (the default the prompts were tuned on)
ANTHROPIC_API_KEY=sk-ant-...

# OpenAI
LLM_PROVIDER=openai LLM_API_KEY=sk-... LLM_MODEL=gpt-5 LLM_FAST_MODEL=gpt-5-mini

# OpenRouter / LiteLLM / any gateway
LLM_PROVIDER=openai LLM_BASE_URL=https://openrouter.ai/api/v1 LLM_API_KEY=sk-or-... \
  LLM_MODEL=anthropic/claude-opus-4.8

# Azure OpenAI (v1 API)
LLM_PROVIDER=openai LLM_BASE_URL=https://<resource>.openai.azure.com/openai/v1 \
  LLM_API_KEY=<key> LLM_MODEL=<deployment-name>

# Google Gemini (OpenAI-compatible endpoint)
LLM_PROVIDER=openai LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai \
  LLM_API_KEY=<key> LLM_MODEL=gemini-2.5-pro

# Fully local — Ollama, vLLM, LM Studio (no key, nothing leaves the host)
LLM_BASE_URL=http://localhost:11434/v1 LLM_MODEL=qwen3:32b
```

Helm: set `llm.provider` / `llm.baseURL` / `llm.model` / `llm.fastModel` and
`secret.llmApiKey`.

## Thinking on the anthropic backend

Reasoning and adjudication ask for adaptive thinking (`thinking: {type: "adaptive"}`).
Whether a model gets it is decided by family and version, not a fixed list, so new releases
and dated snapshots are covered: every Fable and Mythos model, and Opus/Sonnet 4.6 or later
(`claude-opus-5-5`, `claude-sonnet-5-5`, `claude-fable-5-1`, `claude-opus-4-8`, …). Haiku
4.5 and older tiers reject adaptive thinking, so a request on them goes out without it and
the reasoner logs `model does not support the provider's reasoning mode`.

## What a model needs

- **Tool calling** (OpenAI `tools` format) — the chat agent's investigation loop.
- **JSON-schema output** (`response_format: json_schema`) — reasoning and adjudication.
  Sent non-strict; replies are validated in code either way, and a malformed reply fails the
  job rather than acting on it.
- **Streaming** (SSE) — chat and plan refinement.

Small local models often handle chat and translation fine but are unreliable at the
structured remediation decisions. Run the golden-set gate against your model before
trusting its proposals. It is 20 coarse cases, each sampled once (see
[ADR 038](adr/038-reasoning-eval-harness.md)), so passing it is a minimum bar, not a measure
of decision quality:

```sh
LLM_BASE_URL=http://localhost:11434/v1 LLM_MODEL=qwen3:32b \
  go test -tags=eval ./internal/reason/ -v
```

## Usage and budgets

Every model call is recorded in the `llm_usage` ledger with its purpose (`chat`,
`nl_query`, `refine`, `template_gen`, `reason`, `adjudicate`, `ct_triage`, `drift_analysis`), model, token
counts and an estimated cost from `LLM_PRICES`. Admins see the month in Settings > LLM
Usage (`GET /api/llm/usage`).

- Anthropic reports usage on every reply. On the `openai` backend, streamed calls send
  `stream_options: {"include_usage": true}` to get the final usage chunk; a server that
  ignores it (or any reply without usage) is charged its **worst case**: every request byte
  as an input token and the whole output budget as output. The usage view counts these as
  `unreported_calls`. A failed call is charged the same way.
- Costs are estimates. No vendor price is built in as truth: unpriced models use a high
  fallback, so set `LLM_PRICES` (see [configuration](configuration.md#llm-provider)).
- `LLM_MONTHLY_BUDGET_USD` caps all spend and stops background work when reached (or when
  the ledger is unreadable). `LLM_INTERACTIVE_MONTHLY_BUDGET_USD` caps interactive spend
  separately, so background spend never cuts a user off. Both default to unlimited.
  Concurrent in-flight calls can overshoot a cap by at most their own cost.
- `drift_analysis` is background spend: when the total budget is reached or the ledger is unreadable, the
  batch is recorded as unknown, never as "no scan needed".

```sh
LLM_MONTHLY_BUDGET_USD=200
LLM_INTERACTIVE_MONTHLY_BUDGET_USD=50
LLM_PRICES='{"claude-opus":{"input":10,"output":50,"cache_read":1},"claude-haiku":{"input":2,"output":10}}'
```

(Illustrative numbers showing the format and prefix matching; take real ones from your provider.)

## Data egress

Prompts contain finding details, resource identifiers, graph context and (in chat) live
cloud API results. Attacker-influenceable text is fenced as untrusted data, but it is still
sent to the provider. If that matters for your environment, use a local server.
