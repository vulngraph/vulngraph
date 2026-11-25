# ADR 029 — Multi-framework compliance mapping

**Status:** accepted (extends ADR 019)

## Context

Compliance (ADR 019) mapped checks to **CIS controls only** and reported pass/fail coverage.
But auditors and buyers work in framework terms — "show me SOC 2 / PCI-DSS / HIPAA posture,"
not "show me CIS-AWS-4.1." A single check almost always evidences a requirement in several
frameworks (blocking public network access satisfies CIS, SOC 2 CC6.6, *and* PCI-DSS Req 1),
so the existing check set should roll up under every framework it touches — no new checks,
just a mapping layer. A CIS-only view does not answer framework-oriented audit questions.

## Decision

Controls gain a `Frameworks []string`, populated at compute time from one auditable table.

- **`controlFrameworks`** maps each control ID to the frameworks it satisfies, grouped by
  the control's security *nature* via shared slices (`fwExposure`, `fwPublicData`,
  `fwEncryption`, `fwAccess`, `fwCISOnly`). Kept as one block rather than editing every
  control struct — the framework taxonomy is reviewable in a single place. Controls absent
  from the map default to CIS-only.
- **`frameworksFor(controlID)`** resolves the list; `Compute` stamps it on each control and
  accumulates a **per-framework rollup** (`FrameworkCoverage{Framework, Total, Passing}`) —
  one passing control counts toward every framework it satisfies. Stable framework order
  (CIS, SOC2, PCI-DSS, HIPAA) for the UI.
- **Contract:** the OpenAPI compliance schema gains `frameworks` on `Control` and
  `ComplianceCoverage` (ADR 017 — the integration test validates response shape, so the spec
  must move with the code); `api.gen.ts` regenerated. The Compliance page shows a
  per-framework coverage strip.

## Consequences

- One check set now presents as CIS / SOC2 / PCI-DSS / HIPAA posture — the auditor view,
  with zero new detection logic. Adding a framework is editing one map.
- **Trade-off:** the mapping is *control→framework attribution by security nature*, not a
  certified crosswalk to specific clause numbers. It answers "are the controls relevant to
  PCI passing" — it is **not** an audit attestation, evidence package, or gap-analysis export
  (that, plus control-exception workflow, remains ADR 019's deferred scope). The framework
  tags indicate which requirements a check *relates to*, not a compliance guarantee.
- Frameworks are derived, not stored per finding — recomputed each `Compute`, so re-tagging a
  control is a code change that takes effect on next load with no migration.

Cites ADR 019 (compliance reporting — this extends it), 017 (OpenAPI contract — spec moved
with the code), 007 (original cloud/CIS scope this widens).
