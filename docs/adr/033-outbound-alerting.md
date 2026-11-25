# ADR 033 — Outbound alerting (notify)

**Status:** accepted · amended 2026-07-06 (generic webhook channel)

## Context

Everything the platform produced — enriched findings, agent decisions, drift, confirmed
phishing domains, changed detections — lived behind the UI. Teams live in Slack; a security
platform that requires someone to open it to learn about a critical finding is a platform
that misses critical findings. A single outbound notification hub was needed, distinct from
`connector` (which pulls assets *inbound*) — this pushes events *outbound* — with per-channel
routing so the SOC channel and the platform-team channel get different things.

## Decision

An `internal/app/notify/` domain that routes typed notifications to configured channels.

- **`Channel`** (Slack in v1; the dispatch switch is structured so webhook/Teams/PagerDuty
  drop in) with per-channel routing: `EventTypes`, `Severities`, and a `MinScore` gate. The
  Slack bot token is stored encrypted (reusing the connector cipher), in the `alert_channels` table.
- **`Notification{EventType, Severity, Score, Title, Message, Fields, …}`** with event types
  `finding | drift | decision | approval | connector | phishing | query_match` (the last
  added for ADR 027 detection-as-code). `Channel.accepts()` does the routing match.
- **`Service.Dispatch`** is best-effort and never returns an error to its caller: a delivery
  failure must never fail the event that produced it (a confirmed phishing domain, an enriched
  finding). Failures are logged and recorded on the channel's `last_status`.
- Call sites fan out via thin adapters so producers stay decoupled from `notify`: the enrich
  worker (new high/critical findings), the respond pipeline (non-observe decisions, ADR 030),
  the domain monitor (certificate-transparency look-alike/phishing domains), and the saved-query worker (changed
  detections, ADR 027).

## Consequences

- One alerting backbone every producer reuses — adding alerting to a new feature is building a
  `Notification` and calling `Dispatch`, not a new integration (this is exactly why ADR 027's
  alerting was nearly free).
- Best-effort dispatch means alerting can never take down the pipeline; the cost is that a
  misconfigured channel silently drops alerts until someone checks `last_status` (surfaced in
  the UI + the "send test" button).
- Per-channel `MinScore`/severity/event routing keeps high-volume low-severity noise out of
  paging channels without code — it's channel config.
- Secrets (bot token) follow the connector encryption model; a rotated `GRAPH_SECRET_KEY`
  disables delivery (decrypt fails) rather than leaking — fail-closed on secrets.

Cites ADR 030 (decision notifications), 027 (query_match event), 003 (encrypted-secret-at-rest
convention shared with connectors), 010 (layering — producers depend on a narrow dispatcher
interface, not the notify domain).

## Amendment (2026-07-06) — generic webhook channel

Slack-only delivery did not fit teams that route through Jira/PagerDuty/Teams/generic
receivers. Rather than build a bespoke integration per destination, added a **`webhook`
channel type** that POSTs a stable, self-describing JSON payload
(`event, severity, score, title, message, fields, link, source, timestamp`) to a
user-supplied URL — the operator points it at their own bridge/receiver (Jira, PagerDuty,
Teams, or a Lambda). This is the pragmatic first non-Slack backend (generic webhook chosen
over a bespoke Jira/PagerDuty client) and slots into the existing dispatch switch.

Two things it does deliberately:
- **SSRF-safe delivery.** The webhook URL is untrusted operator input, so the poster uses the
  SSRF-blocking `safenet.New` client (never `NewInternal`, which Slack uses for the trusted
  `slack.com` host) — a webhook target cannot be pointed at the metadata service or an internal
  address (per the project's engineering standards (`CLAUDE.md`), which require the SSRF-safe client for outbound HTTP).
- **Secret-at-rest.** The URL often embeds an auth token, so it is stored in the same encrypted
  `config_encrypted` blob as the Slack bot token (no new column/migration) and never returned
  over the API — same fail-closed-on-secret posture.

`internal/app/notify/{webhook.go,domain.go,service.go,repo.go,handler.go}` +
`frontend/.../AlertChannels.tsx` (type selector + URL field). Full per-destination clients
(native Jira/PagerDuty) remain a future enhancement layered on the generic webhook.
