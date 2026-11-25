# ADR 092 — Benchmark matrices are checked against their upstream lists

**Status:** accepted (2026-10-10)

## Context

ADR 090 pins each CSPM matrix to the newest benchmark version that has a public,
machine-readable control list. Nothing re-read those lists afterwards. A new FSBP control,
a CIS release, or a control AWS retired would stay invisible until someone happened to
compare by hand. Coverage would then be wrong without anyone noticing: a control upstream
added has no row, so it never shows as `missing`, and a retired control keeps its row.

## Decision

- **`cmd/benchmark-watch` is the only place the upstreams are fetched.** It reads, over
  HTTPS:
  - Prowler's compliance directories (`prowler/compliance/{aws,azure,gcp,kubernetes}`,
    Apache-2.0);
  - kube-bench's `cfg/` tree (Apache-2.0);
  - the AWS Security Hub controls reference page;
  - the Azure Policy regulatory-compliance initiatives (MIT).

  When the AWS CLI has credentials and Security Hub is enabled, the FSBP list comes from
  `aws securityhub list-security-control-definitions --standards-arn <FSBP>` instead of the
  page. The diff itself lives in `internal/checks/upstream`. It reads a *bundle*: raw
  payloads under stable paths. `upstream.Wanted` names the files it still needs, so the
  command fetches listings first and then only the files the diff reads. `-record DIR` saves
  a bundle, and `-offline DIR` replays one with no network.
- **Upstream per matrix** (`upstream.Sources`; a matrix without an entry fails
  `TestEveryMatrixHasAnUpstream`):

  | Matrix | IDs read from | Also checked for a newer version |
  |---|---|---|
  | AWS FSBP | Security Hub API, else the reference page's FSBP rows | — (FSBP is versionless; controls are added in place) |
  | CIS AWS / GCP / Azure Foundations | Prowler `cis_<v>_<provider>.json` | Azure Policy CIS Azure initiatives (they lag; they only signal a version) |
  | CIS Kubernetes | Prowler `cis_2.0.1_kubernetes.json` | kube-bench `cis-*` |
  | CIS EKS / GKE | kube-bench `eks-*` / `gke-*` | — |

  The reference page, not the FSBP standard page, is the FSBP source. As of 2026-10 the
  reference marks 11 more controls as FSBP than the standard page lists.
- **Report.** For each matrix the report lists: a newer published version; upstream IDs
  with no matrix row (for FSBP, "new FSBP controls" with AWS's titles); matrix rows upstream
  no longer lists; and whether the upstream differs from the committed snapshot. The output
  is a text report or `-json`. `-fail-on-drift` exits 3 on drift (1 means the tool failed),
  so CI can tell "open an issue" from "fix the job". When the upstream does not publish the
  pinned version (CIS GKE 2.0.0; kube-bench stops at gke-1.9.0), the IDs are compared with
  the nearest older version and reported as informational only.
- **Degraded input is an error, never an empty list.** A GitHub API error object, an empty
  listing, a Prowler file with no requirements, or a reference page with no control rows
  all fail the run. None of them reads as "upstream lists nothing new". A matrix whose
  upstream could not be read is reported as drift.
- **Completeness test.** `benchmark-watch -update` records each upstream list in
  `internal/checks/benchmarks/testdata/sources/<benchmark>.json`.
  `TestMatricesMatchUpstreamSnapshot` requires each matrix's ID set to equal its snapshot,
  except for differences listed with a reason in `acknowledged.yaml`. An unexplained
  difference fails CI. The test compares ID sets only, so edits to statuses and check lists
  never trip it. An acknowledgement that has since been reconciled also fails. Left in place,
  it would silently re-mask the same difference if that difference came back, so the change
  that adds or drops the row deletes the entry too.
- **Weekly workflow** (`.github/workflows/benchmark-watch.yaml`). It runs the watch with
  `-frameworks` (ADR 093) on Monday mornings and opens or updates one issue on drift. It
  pins action SHAs, its permissions are `contents: read` + `issues: write`, and it never
  pushes. Reconciling drift is a normal pull request.
- **Last checked.** `docs/cspm-coverage.md` shows, per matrix, the snapshot date and the
  file it was read from.

## Consequences

- The first run found real drift, now acknowledged and left for the matrix owners. FSBP
  added 11 controls with no rows (Bedrock.1, BedrockAgentCore.7, Cognito.1, RDS.38, RDS.39,
  SageMaker.20–25). FSBP retired AppSync.1, AppSync.6 and EKS.3, which still have rows.
  GKE's nearest kube-bench version lists 3 IDs the pinned 2.0.0 does not. The four CIS
  matrices pinned to Prowler and CIS EKS match their upstreams exactly.
- A new matrix must declare its upstream before it can merge.
- The GitHub contents API is called about 10 times per run (unauthenticated limit 60 an
  hour; CI passes its token).
