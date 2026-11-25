# ADR 065: Terraform-state ownership (address-confirmed, high confidence)

**Status:** accepted (2026-07-18) · amended 2026-07-31 (one state per root module)

## Context

Terraform-authored infra had no ownership edge to its repo. The obvious cheap
join — a `.tf` resource name matched against a live asset's **name** — was
tried (`internal/collect/github/iac.go`) and found **zero matches**: Terraform resource names are HCL-local labels
(`resource "aws_iam_role" "deploy"`), not the physical name/ARN Terraform
assigns the resource in the cloud. Terraform state is the only artifact that
carries that authoritative resource→ARN/id mapping. State was previously
unavailable to Vulngraph. A common layout keeps state in **S3 backends inside
accounts the AWS connectors already read**, so the physical mapping is
reachable through existing connectors without a new trust relationship (the
read role still needs `s3:GetObject` on the state objects; see Consequences).

This ADR complements ADR 061 (the collector-supplies / correlate-joins split
and the `NeverSyncTypes` intermediate-asset pattern this feature reuses),
and ADR 063 (repo↔cloud-identity federation, including the `ladybugRelProps`
pattern for edge properties). Terraform state gives an authoritative join key,
so there is no low-confidence tier here.

## Decision

**Discover each repo's state location from its own `.tf`, confirm ownership
by address before trusting any state resource, parse state through a
secrets-discarding narrow struct, and join on the ARN/id state itself
recorded — always high confidence.**

- **Discovery, bounded:** `internal/collect/iac/tfstate.go` (`ParseTFBackend`)
  scans a repo's already-fetched `.tf` text for a static
  `backend "s3" { bucket, key, ... }` block. This names the exact S3 object
  holding the repo's state, so locating it costs one targeted `GetObject` —
  no bucket/prefix listing, no guessing. v1 scope is the **first** static
  backend block found per repo; a repo with only a partial backend
  (`-backend-config` supplied at `init` time, so no literal bucket/key in the
  tree) is skipped and counted, not guessed at.
- **Attribution, address-confirmed:** `ParseTFResourceAddresses` extracts the
  set of `resource "TYPE" "NAME"` → `TYPE.NAME` addresses the repo's `.tf`
  actually declares. A state resource is only attributed to the repo when its
  address is in that set. This guards the case a shared or templated backend
  block points at a state object the repo doesn't actually own (the state
  bucket/key is a weaker signal than the resource addresses inside it) — the
  robust, naming-convention-free confirmation the design chose over trusting
  the backend block alone.
- **Secrets-safe state parsing, enforced by construction:** `ParseTFState`
  parses the state JSON into `StateResource{Address, ARN, ID}` — a struct with
  no field for any other attribute. Terraform state can hold plaintext
  secrets (DB passwords, private keys) in resource attributes; the parser
  extracts ONLY the address and physical identifier (`arn`, falling back to
  `id` when the provider populated no arn) and never retains, logs, or passes
  on anything else. State bytes are parsed in-memory and discarded after
  extraction. A dedicated leak test asserts the emitted records carry no key
  beyond address/arn/id, so a future edit that widens the struct without also
  widening the test is caught, not shipped silently.
- **Ingest** (`internal/collect/github/tfstate_ingest.go`): per repo,
  backend located → `GetObject` (new bounded, size-capped S3 read capability,
  mirroring `live_aws.go`'s client construction; oversize or failed reads are
  skipped and counted, never sunk into the sync) → parse state → keep only
  resources whose address is in the repo's declared set → project each into a
  `declared_tf_resource` asset (`repo`, `address`, `target_arn` or
  `target_id`, `account_id`). `declared_tf_resource` is in
  `asset.NeverSyncTypes` — a correlation-only intermediate, never a Ladybug node,
  the same pattern `declared_k8s_workload` / `declared_ci_access` use.
- **Correlate** (`internal/app/correlate/tf_ownership.go`, rule
  `tf_ownership`): joins each `declared_tf_resource`'s `target_arn` (falling
  back to `target_id`) against the live asset ID. A match emits `defined_in`
  (live asset → repo) with `confidence:"high"` — state is authoritative, not
  a heuristic, so there is no lower tier to fall back to — and
  `provenance:"iac_terraform"`. Edges route through the **existing**
  `DefinedInIamRole` (`iam_role`, the typed IamRole→Repo table) and
  `DefinedInAsset` (everything else in `tfOwnershipSafeLiveTypes`, an explicit
  allow-list hand-verified against `assetTypeToNode` + `NeverSyncTypes`) rels —
  no new rel, no new node label, **no `SchemaVersion` bump**. A live match whose type is not on
  the allow-list (e.g. `security_group`, which routes to its own node label
  and would silently drop at Ladybug COPY) is skipped, not force-fit.
- **Account resolution: multi-account (per-bucket).** Each repo's backend
  bucket is resolved to the account that owns it by looking up the `s3_bucket`
  asset whose id is the bucket name and reading its `account_id`, then
  `ConnectorByAccountID` picks that account's connector for the `GetObject`.
  So state living in different accounts is each read with the right account's
  credentials — no single-account assumption. `cfg["tfstate_aws_account_id"]`
  remains an optional fallback for a bucket that is not present as an
  `s3_bucket` asset; a bucket resolvable to neither is skipped and counted.
- **v1 scope, explicit:** static `backend "s3"` blocks only, first
  backend block per repo. Terraform Cloud / non-S3 backends are out of scope.

## Consequences

- **Secrets never persisted, by construction, not by convention.** The parser
  cannot leak an attribute value it never has a struct field for; the
  leak test pins this so a future change that widens `StateResource` without
  widening the test fails CI rather than shipping a silent secrets exposure.
- **Read access to state buckets is the payoff gate.** A typical read-only
  inventory role can list/describe buckets but has no `s3:GetObject` on state
  objects, so every read returns `403 AccessDenied` and the feature is
  correct-but-empty until that permission is granted. The grant is documented
  in [`docs/iam/`](../iam/) (a read policy scoped to state-named buckets, a
  service-managed StackSet template, and a guide for extending an existing
  read-only role). Vulngraph does
  not grant it (no code path grants IAM permissions), so granting it is an
  operator step.
- **`unreadable_tf_state` finding — IMPLEMENTED (was deferred).** A state read
  failing specifically with `AccessDenied` now emits an info-severity
  `unreadable_tf_state` finding on the repo (source `iac_terraform`), naming the
  bucket/account/key and embedding the exact `s3:GetObject` grant, framed as
  optional because the grant lets Vulngraph's role read every secret in the
  state (the org templates leave it off by default). It is
  keyed on a deterministic id so it **auto-resolves** once the bucket becomes
  readable (ADR 054 lifecycle). Non-`AccessDenied` errors (region redirect,
  404, generic) do NOT emit it — they are not a grant gap. This turns a
  silent-zero blind spot into visible, self-documenting work.

  *Correction (same day):* the auto-resolve needed new code:
  `reconcileResolvedFindings` only diff-reconciled `Source:"cspm"` findings,
  so `iac_terraform`-sourced findings never resolved on their own. The
  diff-reconcile now covers `iac_terraform` too.
- **Region-aware reads — IMPLEMENTED.** `GetObject` resolves each bucket's
  region via `GetBucketLocation` (already-permitted) and reads from the correct
  regional endpoint, fixing the `301 PermanentRedirect` failures on cross-region
  state buckets — needs no new permissions.
- **v1 is narrower than "all Terraform ownership."** Only the first static
  `backend "s3"` block per repo is parsed (partial/`-backend-config` setups
  are skipped and counted), only resource types already safe-routed via
  `tfOwnershipSafeLiveTypes` are joined (an unrouted type is skipped, not
  guessed at). Multi-account bucket→account resolution IS implemented (each
  bucket resolved to its owning account via the s3_bucket asset). Not
  handled: broader backend discovery (multiple backend blocks per repo,
  `-backend-config` reconstruction).
- **No `SchemaVersion` bump.** This slice reuses `DefinedInAsset` /
  `DefinedInIamRole` exactly as they already existed (same properties, same
  routing) — it adds a new correlate rule and a new `provenance` value, not a
  new rel or loading-set change, so the standing Ladybug DDL rule (ADR 025/026)
  does not apply here.
- **Confidence is always "high," with no lower tier**: Terraform state is
  Terraform's own record of what it created and where, so a match carries the
  same authority as a live API read — there is no "best-effort match" framing
  needed here.

Cites ADR 061 (IaC → graph correlation — the collector-supplies /
correlate-joins split and `NeverSyncTypes` intermediate-asset pattern this
feature reuses) and ADR 063 (CI-workflow → cloud-identity federation — the
most recent repo↔cloud-identity feature, including the `ladybugRelProps`
property-carrying pattern).

## Amendment 2026-07-31 — one state per root module, not one per repo

The reader took `backends[0]`: the first `backend "s3"` block found anywhere in a
repo, then read that single state object. Terraform puts one backend in every ROOT
MODULE, so a monorepo has many, and the rest were invisible — with which one
survived decided by GitHub's file ordering. Monorepos with one backend per team
or per environment directory therefore had all but one root module missing
from the graph.

All discovered backends are now read, deduplicated by `bucket/key` and sorted so
truncation is deterministic, bounded by `maxTFBackendsPerRepo` (64) as a fan-out
guard with the skipped count logged — a silent cap reads as full coverage. This
also removes the nondeterministic choice of first backend. The attribution
filter stays repo-wide on purpose: an address is kept if ANY `.tf` in the repo
declares it, so a module's state still joins when the address was read from a
sibling directory.

**Still S3-only.** `backendBlockRe` matches `backend "s3"` alone. Only S3
backends are supported; GCS backends are reported as `no_backend`, so those
repos produce no `unreadable_tf_state` signal. GCS support (note: `prefix`,
not `key`) is not built.
