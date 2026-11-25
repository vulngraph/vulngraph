# ADR 059: The band-floor family — deterministic score floors and the hygiene ceiling

**Status:** accepted (2026-07-14)

## Context

Enrichment scores a finding by attaching graph signal to it — exposure, blast
radius, reachability, privesc, toxic combinations (ADR 014/044). That works when the
finding's resource has edges to reason over. It fails, structurally, for two classes
of finding, which are silently buried or wrongly promoted:

1. **Finding families on edge-less resource types.** A leaked credential
   (`ghas_secrets`) or a SAST hit belongs to a `github_repo`; a nuclei web vuln
   belongs to a scanned endpoint URL; a GuardDuty detection is a behavioral event on
   a host. Graph-signal scoring has nothing to attach to, so these earn nothing
   beyond `BaseSeverity` — which tops out at 40 (critical) while `ThresholdPipeline`
   is 50. Severity alone can therefore *never* leave the monitor band: a live leaked
   credential could sit at an effective score of 0, invisible on a score-sorted worklist.

2. **Advisory IAM checks wrongly pushed INTO the page band.** The resource-context
   sources (`attack_paths`, `toxic_combo`) legitimately score how dangerous a
   *resource* is from its privesc/exposure peer findings — but that peer-derived
   signal was landing additively on every *hygiene* finding about the same resource
   too. `aws-iam-overprivileged-role` (a right-sizing suggestion) could reach the page band
   purely from borrowed signal, as could dormant-key and stale-console advisories — the checks describe the opposite of urgency.

Scoring-by-category is the real gap. These findings need a band decision their
resource type gives graph reasoning no way to make.

## Decision

Four enrich `Source`s that deterministically floor findings into — or cap them out
of — score bands, by check family, complementing (never replacing) graph-signal
scoring. All express intent through the `Factor` shape in `enrich/domain.go`:
`Floor` raises the final score to at least a threshold; `Ceiling` caps it to
strictly below one. Floors only ever raise; a `Ceiling` never lowers a score already
below it, and a hard page floor (KEV, `CriticalFloor`) always wins over a ceiling.

- **`CriticalFloor`** (`sources_critical_floor.go`) — `contextIndependentCriticals`,
  a deliberately tiny map of checks that are critical regardless of any graph context
  (today: `aws-iam-root-active-key`, a standing full-account credential). Floors to
  `ThresholdPage`. A root user has no exposure/blast edges, so graph scoring leaves it
  in monitor; this guarantees it pages.

- **`ThreatFloor`** (`sources_threat_floor.go`) — GuardDuty/GCP-SCC behavioral
  detections floored by threat *family*, not blanket severity. `threatPageMarkers`
  (exfiltration, malware executed, active mining) → `ThresholdPage`;
  `threatHighMarkers` (C&C, backdoor, DGA, privesc/persistence) → `ThresholdHigh` (61, the `BandHigh` band);
  high/critical GCP-SCC → `ThresholdHigh` wholesale. Two noisy single-signal
  DNS-observation families (`PhishingDomainRequest`, `DriveBySourceTraffic`) are
  *excluded* from the blanket floor to avoid flooding the worklist, but escalate to
  actionable when the same host carries another distinct, independently-floored
  threat detection (corroboration gate — real converging evidence, not an isolated
  hit).

- **`SignalFloor`** (`sources_signal_floor.go`) — context-blind families on edge-less
  resource types. High/critical secrets → `ThresholdHigh` (a leaked credential that
  may still work is act-now; a test-mode key or one GitHub's validity check reports
  inactive → the reasoning pipeline, matching its `contained` class); nuclei web vulns → actionable (critical) or the reasoning pipeline
  (high), since they are probe-confirmed and often directly exploitable; IaC/SAST
  code findings → the reasoning pipeline (real but not yet live-exploitable).
  Medium/low/info stay at their graph-scored band to keep the pipeline from flooding
  with low-fidelity noise.

- **`HygieneCeiling`** (`sources_hygiene_ceiling.go`) — the inverse. A tiny map of
  unambiguously advisory IAM checks (`hygieneOptimizationChecks`: overprivileged
  right-size, key rotation, dormant/unused key, stale console login, missing user
  MFA) capped strictly below `ThresholdPage` via `Ceiling`. It does not touch the
  resource-context sources or suppress the checks' severity — the underlying privesc/
  exposure findings on the same resource still surface at page/high on their own. It
  only stops an advisory suggestion from *inheriting* enough borrowed signal to page.

## Consequences

- Context-blind live findings (leaked secrets, confirmed web vulns, act-now threats)
  leave the monitor band by their real urgency instead of scoring 0 forever.
- Advisory IAM hygiene stops dominating the page band on borrowed peer signal, while
  the genuinely dangerous findings on the same resource keep their band.
- Trade-off: the floors and the ceiling are hardcoded lookup tables
  patching a scoring-by-category gap. They are not graph reasoning — they are a
  deliberate, bounded, deterministic mechanism for exactly the families whose
  resource type gives graph scoring nothing to work with. Each list is kept tiny and
  unambiguous on purpose; a check earns a place only when there is genuinely no
  context in which the floor/ceiling would be wrong. The floors run at enrich time,
  before the LLM path, so a mis-scored family is a table edit, not a prompt change.

Cites ADR 014 (the additive scorer these sources plug into), 044 (must-fix
prioritization — the reachability signal these complement for edge-less resources),
043 (the enrich-time, per-finding factor pattern they mirror), 053 (the belief engine
that reasons over the bands these set).
