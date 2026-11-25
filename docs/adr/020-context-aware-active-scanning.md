# ADR 020 — Context-aware active scanning: scope, fingerprinting, and safety rails

**Status:** partially implemented · superseded in part by what shipped (see the 2026-10-24 amendment) · amended 2026-07-18 (implementation drift) · amended 2026-10-05 (unwired seams removed) · amended 2026-10-23 (rails unbuilt) · amended 2026-10-24 (the rails that exist)

> **Amendment (2026-10-24) — what is built, and the rails it has.** The context-aware verify
> loop this ADR decides on (fingerprint → feed CVEs → generated template → confirmed finding)
> does not exist, and neither do fingerprinting or vantage labelling. What shipped is
> operator-driven scanning: a full scan of internet-facing assets, scan profiles (manual or
> scheduled) and an LLM template generator for a person writing templates. Its rails:
>
> - **People only.** Every route that starts or shapes a scan is admin-only: `POST /api/scans`,
>   `POST /api/scan-profiles/{id}/trigger`, profile create/update/delete, and template
>   validate, test and generate. A profile's schedule runs without a person, on the profile an
>   admin saved.
> - **Audit.** A scan a person starts writes `scan.start` or `scan.profile_start` to
>   `audit_events` (docs/security-hardening.md#audit-trail). Scheduled runs, cancels, template
>   tests and template generation write no row.
> - **Targets.** `targetguard.go` refuses private and loopback space unless
>   `SCAN_ALLOW_INTERNAL_TARGETS=true`, and link-local space and the cloud metadata endpoints
>   always (`AlwaysBlockedTargets`); nuclei gets the same list as a dial-time exclude. A run is
>   capped at `MaxTargets` (500), and a profile's Cypher target query must end in `LIMIT` ≤ 500
>   (`ValidateTargetQuery`).
> - **Engine limits.** A global rate limit (150 requests a second), template and host
>   concurrency caps (25 each) and a 30-minute per-scan deadline (`internal/scanner/nuclei/nuclei.go`).
> - **Templates.** file, code, headless and workflow templates are rejected, and nuclei runs a
>   javascript template only when it is signed.
> - **The LLM template generator** (`internal/scanner/nuclei/template_generator.go`) returns
>   YAML to the admin who asked. It never saves or runs a template; it makes at most three
>   attempts, feeding the validator's errors back each time, and its output passes the same
>   validation as a hand-written template. Running it takes a separate admin template test
>   against one target, under the target rules above.
>
> Still missing: the CoVe/blast-radius pre-scan guard, the memory-ledger gate, a global scan
> kill switch (`SCAN_WORKER_DISABLED` only moves nuclei execution to the scanner pod), any
> review of what a generated template's requests do (validation is structural), and audit rows
> for the actions listed above as writing none.

> **Amendment (2026-10-23) — the verify-loop rails were never built.** There is no
> CoVe/blast-radius pre-scan guard, no memory-ledger gate, no `audit_events` writes from scans
> (since added for scans a person starts: see the 2026-10-24 amendment), and no global scan
> kill-switch (`SCAN_WORKER_DISABLED` only moves nuclei execution to the
> scanner pod). The only rails that exist are the nuclei engine's rate, concurrency and timeout
> limits and the deny list in `internal/app/scan/targetguard.go`. Decision and Consequences
> describe the intended v1, not what shipped.

> **Amendment (2026-10-05) — the unwired seams were removed.** The `detect` domain
> (`internal/app/detect`), the `scan.Product` / `scan.Candidate` / `scan.FindingSource` feed
> contract, `scan.NewMultiSource`, the NVD client (`internal/intel/nvd`) and the OSV
> `FindingSource` adapter were never wired into any binary and have been deleted. References to
> them below are historical; building this loop now starts from scratch.

> **Amendment (2026-07-18) — the v1 scope below has drifted; recording reality.**
> - **LLM template generation is no longer absent.** An operator-facing LLM nuclei template
>   generator shipped (`internal/scanner/nuclei/template_generator.go`, `template_adapter.go`,
>   wired in `cmd/graph/serve.go` and enabled when an LLM provider is configured (ADR 084); `detect.OriginGenerated` (removed)).
>   It is template *authoring*, not the autonomous verify-loop generation this ADR deferred — but
>   the blanket "no LLM generation in v1" no longer holds, and the deferred safety prerequisites
>   below (untrusted `Candidate.Summary`, behavioral checks, corpus-poisoning guards) apply to
>   exactly this capability.
> - **`internal/fingerprint/`** — the evidence-backed fingerprinting core this ADR scoped for
>   v1 — **was never built.**
> - **Scan `vantage` labeling**, which this ADR says "ships in v1," is **not implemented** (no
>   `vantage` field anywhere). The external vantage remains deferred as intended.

## Context

We want scanning that *confirms* exploitability: fingerprint an asset → find CVEs a feed reports for its software (NVD by CPE, OSV by package) → run a nuclei template that actually tests it → record only confirmed findings. At the time, the `detect` domain (`internal/app/detect`, since removed — see the 2026-10-05 amendment) modelled this generate-and-verify loop (Resolver/Generator/Validator/Verifier/Corpus + a severity gate), but it was **interfaces only — zero implementations, zero wiring** — and **nothing in the codebase produced a `scan.Product`/CPE**. So this is mostly a build-from-scratch, and a naive version is unsafe in specific, concrete ways. This ADR sets the v1 scope and the rails; it deliberately defers the two riskiest pieces.

Facts that shape the decision:
- The nuclei engine (`internal/scanner/nuclei/nuclei.go`) then ran `NewNucleiEngineCtx` with the **default template set and no rate limit, concurrency cap, or per-scan timeout** — ADR 009's intended guards were not in the code. *Since fixed:* the engine now sets a global rate limit, template/host/probe concurrency caps and a per-scan deadline (`globalRateLimit`, `templateConcurrency`, `hostConcurrency`, `probeConcurrency`, `maxScanDuration`).
- The `detect` gate (removed) trusted the generator's **self-reported `Confidence`** (`minConfidence = 0.7`) — an LLM grading its own output.
- `Candidate.Summary` is fed verbatim from NVD/OSV text — **attacker-influenceable** (anyone can publish a CVE description), so it's an untrusted input to any LLM step.
- CPE derivation from cloud metadata is unreliable; a wrong CPE pulls up to `maxResults=200` CVEs per asset, each becoming a candidate that could trigger an active scan.

## Decision

**v1 is a stock-template-only verify loop with evidence-backed fingerprinting and real rails. LLM template generation and the external vantage are not built.**

- **Scope (v1):** feeds → candidates → **resolve a bundled, pinned nuclei-templates corpus** (offline, reproducible, no runtime fetch; refreshed as a reviewed dependency bump) → verify → finding. No LLM generation in v1.
  - *As built:* the corpus is pinned but not bundled. Neither the repo nor the container image carries it; before its first scan a worker or scanner pod downloads one pinned release of [`projectdiscovery/nuclei-templates`](https://github.com/projectdiscovery/nuclei-templates) (MIT) and refuses it unless its sha256 matches (`internal/scanner/nuclei/templates.go`). A refresh is a reviewed bump of that pin. `NUCLEI_TEMPLATES_DIR` runs a mounted copy with no fetch at all.
- **Evidence-backed fingerprinting** — new `internal/fingerprint/` (pure, table-driven), three tiers, emit a `Product` only when confident:
  1. **SBOM/package → OSV** — reuse `collect/github/sbom.go` (`{ecosystem,package,version}`). Accurate, exists today; ships value alone.
  2. **Managed-service engine+version → CPE** — via a *curated* vendor/product table (e.g. `postgres → cpe:2.3:a:postgresql:postgresql`). Needs a small `collect/aws|gcp` enrichment to capture engine/version. **Never LLM-built CPEs.**
  3. **Banner/service → CPE** — a service-detection scanner such as naabu `-sV`/httpx (the naabu adapter was never wired and has been removed; needs `scan.Result.Service/Version`). Medium confidence (banners spoofable/masked).
  Add a **`Product` confidence**; **emit no Product when version confidence is low** (don't wildcard); **bar low-confidence fingerprints from the crit/high auto path**. Deriving an OS-level CPE for a bare compute instance from metadata alone is *not possible* today and won't be faked.
- **Safety rails — reuse what exists, don't invent weaker ones:**
  - **Enforce ADR 009's limits in the nuclei engine** (rate, concurrency, per-scan timeout, single-template runs) — a prerequisite. Rate, concurrency and per-scan timeout are now enforced; single-template runs are not.
  - **Owned-asset allowlist + re-resolve the target at Verify time** (cloud IPs churn — defend against scanning a host we no longer own).
  - A **`respond.CoVe`-style blast-radius guard before any active scan**, regardless of severity band (an "auto" template must still pass it).
  - Replace the gate's self-reported confidence with the **ADR 005 decaying-memory ledger** (`internal/app/memory`): no outcome history for a template class → human approval.
  - **Audit every scan, template, and gate decision to `audit_events` (ADR 008)** and provide a **global scan kill-switch**. This uses the existing audit trail — not a new monitoring stack.
- **Vantage constraint (ships in v1):** label every finding with its scan **vantage**. The scanner runs in-cluster (east-west) for v1, so an **in-cluster "no match" must NOT clear an internet-facing candidate** — it stays `pending: needs external vantage`. A wrong-vantage "verified not present" on an internet-facing critical is worse than no scan.
- **Autonomy (generated templates):** the gate stays as designed — validated, detection-only, low/med auto-run, critical/high human-approved.

## Not built

- **LLM template generation.** Highest-risk, lowest-maturity piece. Building it would first need: prompt-injection defenses (treat `Candidate.Summary` as untrusted data, not instructions); a **behavioral** safety check (`nuclei -validate` checks syntax, not behaviour — a "detection" template can still DoS or hit destructive endpoints); and corpus-poisoning guards (no n=1 promotion — the removed `verifyAndLearn` saved on a single match; provenance on every corpus row; corpus hits must **not** inherit stock-template trust / skip the confidence floor; expiry + periodic re-review).
- **External scan-agent vantage.** A deployment/topology decision (where the agent runs, how it gets an external IP, how it stays one-binary per ADR 001, how exposure assumptions are revisited). This ADR does not decide any of it.

## Consequences

- The intended v1 was confirmed, low-false-positive findings on the trustworthy fingerprint path (SBOM/OSV) and a stock-template active loop with the guards above. Package-to-advisory findings from SBOM/OSV data do exist (`internal/jobs/osv.go`), but this ADR's `internal/fingerprint/` → candidate → verify pipeline was not built, nor were the verify loop and its guards (see the amendments).
- The dangerous capabilities (AI-authored active scans; external scanning) are not built; either would need its own ADR on top of the safe core, favouring simplicity over cleverness.
- Prerequisite work is explicit: the nuclei engine had to gain its ADR 009 limits before the verify loop runs anything. Rate, concurrency and per-scan timeout limits have since landed.
- Fingerprinting reliability is the gating risk for the CVE-verification path's value; the confidence-tiering keeps unreliable signals out of the expensive/dangerous downstream paths.
