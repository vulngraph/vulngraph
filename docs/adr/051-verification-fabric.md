# ADR 051 — Verification fabric: confidence by corroboration across independent sensors

**Status:** accepted — partially implemented. Shipped: the DNS-resolution sensor
(`enrich.DNSTakeover`) and an HTTP-fingerprint sensor over safenet
(`enrich.TakeoverProbe`). A fingerprint match elevates a takeover candidate; a candidate
is demoted only when both sensors agree it is live. Nuclei runs with a dial-time deny list
(`internal/scanner/nuclei` `sandboxOption` + `scan.AlwaysBlockedTargets`). Not built: a
general evidence/corroboration field on findings and a pluggable verifier interface.
Decision 1 is the target model, not an enforced invariant.

## Context

The platform senses the estate through several independent sensors, each of which
knows a *different kind* of truth:

| Sensor | Truth it senses | Posture |
|---|---|---|
| Collectors (cloud APIs) | Config — what the provider says about itself | passive, always-on |
| Correlation + Ladybug graph | Structure — reachability, blast radius, trust_entry | passive, every sweep |
| ClickHouse history / CloudTrail | Time — did it change, how long, is it *used* | passive |
| Intel (KEV / EPSS / OSV) | External threat — exploited in the wild | passive |
| Nuclei | Active web — does the endpoint really respond/exploit | active, `CapWeb` |
| Live AWS describe (`live_aws.go`) | Point-in-time re-check of one resource | active, read-only |
| DNS resolution | Does a name resolve / is the backing resource claimed | active (added by this ADR, `enrich.DNSTakeover`; absent when it was written) |
| Claude reasoning | Orchestrates the others | on-demand |

Recurring bug class (ADR 050, CSPM exposure checks, supply-chain detection):
a finding trusts **one** sensor and asserts a conclusion only a **different** sensor
could prove. The confirmed/possible tier (ADR 050) solved this for exposure by
hand. A related failure mode is two sensors (e.g. the Ladybug graph and ClickHouse)
silently disagreeing about the same question with no reconciliation, producing
false negatives.

## Decision

Make corroboration a first-class, general concept rather than a per-check hack.

1. **Every high-severity claim names its corroborating sensor.** A claim asserted
   by config alone is a *candidate* (possible tier); a claim a second, independent
   sensor confirms is *confirmed*. Severity is a function of the evidence tier, not
   of the raw rule. ADR 050's `public_access` becomes the first instance of a
   general `evidence`/confidence field on findings.

2. **A verifier is a pluggable sensor** behind a small interface: given a finding,
   it returns confirm / refute / inconclusive plus the evidence it saw. Passive
   sensors (graph reachability, CloudTrail usage) corroborate every sweep; active
   sensors (nuclei, live-AWS, DNS resolution) run on demand for candidates worth
   the cost. This generalizes the existing read-only `live_aws.go` verify path
   (ADR 045) from "AWS describe in chat" to "any sensor, any finding."

3. **New sensor — DNS resolution** for the dangling-CNAME/subdomain-takeover class.
   The CSPM takeover checks are pattern-only candidates today (ADR 050 demoted
   them). Confirmation is two sensors, cheapest first: resolve the CNAME target
   (NXDOMAIN / `NoSuchBucket` = dangling evidence), then optionally a nuclei
   `http/takeovers` fingerprint **against the record's own hostname** (not by
   blindly following the CNAME). Two sensors agreeing → escalate the candidate to
   confirmed high/critical. The second sensor shipped as a curated HTTP fingerprint over
   safenet (`enrich.TakeoverProbe`), not a nuclei `http/takeovers` template.

4. **Active sensors need an egress guard.** Nuclei bypasses `safenet` today (at time of writing; since closed by
   `sandboxOption`) (ADR
   009 rested on "we only ever scan ourselves"). Takeover verification inherently
   reaches toward third-party/unclaimed endpoints, breaking that assumption — so
   the active-verify path must route through an explicit egress control
   (safenet-style private-range/redirect/port guard) and never probe an arbitrary
   attacker-controllable target directly.

## Consequences

- One model replaces a growing pile of per-check severity hacks; the "does the
  data actually prove this?" question has a structural answer.
- Findings carry *why* they're at their severity (which sensors agreed) — directly
  feeds the narrative and the audit trail.
- Cost is controlled: active sensors run only to promote candidates, not on every
  asset every sweep.
- Opens a real SSRF surface (active probing) that must be gated before shipping —
  called out as a hard prerequisite, not an afterthought.

Cites ADR 009 (nuclei quarantine + the assumption this challenges), 045
(read-only live verification it generalizes), 049 (shared graph contract), 050
(the tier vocabulary it promotes to a general model). Related: ADR 052 applies
the same corroboration idea to privilege escalation.
