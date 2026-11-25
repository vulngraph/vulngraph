# ADR 093 — Compliance frameworks are rolled up per requirement

**Status:** accepted (2026-10-10)

## Context

The compliance view tagged roughly 30 graph-labelled controls with coarse framework names
(CIS / SOC2 / PCI-DSS / HIPAA). An auditor asks about specific requirements: "PCI DSS
1.3.1", "NIST AC-6", "ISO A.8.15". Prowler answers per requirement, and graph could
not. ADR 090 rejected deriving the compliance view from the benchmark matrices because
nobody had reviewed the framework tags such a derivation would need. This ADR supplies
tags that come from public, license-clean mappings instead.

## Decision

- **Frameworks:** NIST SP 800-53 Rev. 5, PCI DSS 4.0.1, SOC 2 (2017 TSC; Security, Availability,
  Confidentiality and Processing Integrity), ISO/IEC 27001:2022 Annex A, and the HIPAA
  Security Rule. Each framework has one file in `internal/checks/frameworks/`, embedded in
  the binary. Every file is under 800 lines.
- **Requirements map to benchmark controls, not checks** (`"aws-fsbp/IAM.6"`,
  `"cis-aws-foundations/2.3"`). The matrix decides which checks evidence a control. A check
  later added to a matrix row therefore reaches every requirement mapped to that row, with
  no regeneration. `TestFrameworksAreWellFormed` fails on a reference to a row that does not
  exist.
- **Mapping sources, license-clean only:**
  - Prowler's compliance JSONs (Apache-2.0) map requirement → Prowler check. Vulngraph joins each
    Prowler check to its own controls through Prowler's CIS file for the *pinned* version
    and Prowler's FSBP file. Other CIS versions are never joined, because CIS renumbers
    between versions. A Prowler check with no CIS or FSBP equivalent is not dropped
    silently. Each requirement records `unjoined: N`, the number of source mappings (a
    Prowler check, or an AWS related FSBP control with no matrix row) that reach no graph
    control. A requirement with `unjoined > 0` is never passing: it is shown as "partial
    mapping: N source checks without a graph control" in the API, UI and CSV.
  - The "Related requirements" AWS publishes for each Security Hub control map FSBP controls
    directly to NIST 800-53 r5 and PCI DSS v4.0.1 IDs.
  - Titles: NIST titles come from the OSCAL catalog and HIPAA titles from the regulation.
    Both are US government works. ISO, PCI and AICPA text is copyrighted, so those titles are
    paraphrased by hand. The generator keeps the hand-written titles, and it fails, naming
    the IDs, when a new requirement has no title. It never writes a placeholder or copies
    source text.
  - Attribution is in NOTICE.
- **CIS Controls v8 is not mapped.** It is CC BY-NC-ND. The only public machine-readable
  mapping (Azure Policy's `CIS_Controls_v8.1` initiative) maps to Azure Policy definitions,
  not to checks, and Prowler publishes none.
- **Generated, then reviewed.** `go run ./cmd/benchmark-watch -frameworks -update`
  regenerates the files from the same upstream bundle as ADR 092. The weekly watch reports a
  stale mapping as drift. `TestFrameworkFilesAreCanonical` keeps the files in generator
  format.
- **Rollup** (`compliance.Service`, live, no stored history). It reuses the existing inputs:
  the open-and-alive failing check set (`DistinctCheckIDs`) and one inventory sample read.
  Each mapped check is classified as evaluated, unevaluable (its applicable assets lack the
  evidence it reads), or absent (no applicable assets). Per requirement:
  - *failing* — any mapped check has an open finding. A finding is evidence whatever else is
    missing.
  - *passing* — every in-scope control is `covered`, no check is unevaluable, at least one
    check evaluated, and none fails.
  - *unknown* — everything else: a partial source mapping (`unjoined > 0`); a mapped control that is `partial`, `missing`, `manual`,
    `not_applicable` or since removed; an unevaluable check; or nothing evaluated, as with an
    empty inventory. **Unknown is never counted as passing.**
  - *manual* — no control maps to the requirement.

  A check is *evaluated* only when every applicable inventory sample (one per provider, type
  and metadata key set) carries its evidence. One observed key set never vouches for assets
  of the same type that were never observed.

  **Scope and freshness come from connectors, not only inventory.** A provider is in scope
  when it has an enabled collecting connector (`aws`, `gcp`, `azure`, `kubernetes`; not
  `aws_org`), any inventory, or an open finding. An in-scope control is an *evidence gap*,
  so its requirement is unknown, when its cloud is stale. A cloud is stale when any enabled
  connector has had no successful sync within `connector.DefaultStaleAfter` (24h), has never
  synced, or is `PartiallyStale` (`DefaultPartialStreakThreshold`). It is also stale when it
  has a connector but no inventory (a connector that never produced assets), or inventory
  that no enabled connector refreshes. Per cloud and per requirement, the response carries
  `evidence_as_of`: the oldest last successful sync, or null when one never synced. The same
  value is shown in the UI and the CSV. A control whose benchmark has no in-scope provider is
  out of scope, so an AWS-only estate is not held unknown by Azure gaps. A requirement whose
  controls are all out of scope is unknown, not passing.
- **API:** `GET /api/compliance/frameworks` returns summaries.
  `GET /api/compliance/frameworks/{id}` returns every requirement with its controls, checks,
  failing and unevaluable checks, gaps and out-of-scope controls.
  `GET /api/compliance/frameworks/{id}/export` returns the auditor CSV, for analysts and
  admins only. It holds one row per requirement: status, mapped controls and checks, and
  `failing_resources`, the distinct resources with an open finding for a failing check, or
  `n/a` when a failing check's findings name no resource (a zero there would read as "fails on
  nothing").
  The resource count is read with `finding.OpenResourcesByCheck`, which shares
  `distinctCheckIDs`' CTE and liveness gate, so the count cannot disagree with the state.
  An unread count is an error, never zero. CSV cells are protected against formula
  injection.
- **No score history.** Trends would need a ClickHouse table written every sweep. The live
  rollup costs the same two reads the existing coverage view makes, so no table was
  added.

## Consequences

- At the first generation, the requirements with at least one mapped check are: NIST 182/222,
  PCI 96/120, HIPAA 30/36, SOC 2 20/43, ISO 25/93. ISO's organizational, people and physical
  controls are not API-evaluable and stay manual. `docs/cspm-coverage.md` publishes these
  counts.
- Most requirements read *unknown* today. That is honest: the FSBP matrix still has 277
  `missing` controls. Each closed matrix gap moves requirements toward pass or fail with no
  change here.
- Prowler's requirement → check mappings are broad (one HIPAA requirement maps around 70
  controls). The mapping is only as precise as the source. Narrowing a requirement means
  editing the source or the generator, never hand-editing the file.
- The coarse control view and its CIS/SOC2/PCI/HIPAA tags stay as they are for existing
  readers (chat, MCP, home page).
