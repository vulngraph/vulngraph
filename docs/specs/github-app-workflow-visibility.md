# GitHub App and workflow visibility

**Status:** implementation
**Date:** 2026-11-27
**Issue:** https://github.com/vulngraph/vulngraph/issues/18

## Problem and goals

Repository inventory alone cannot distinguish an App from an installation or a
narrowed workflow token. Add observed grants and static workflow declarations,
with explicit unknown coverage, lifecycle handling, and potential-path findings.
A shared App or secret reference alone is never evidence of compromise.

## Design

Use the configured App JWT for its identity and installation metadata, and the
existing installation token for organization installation enumeration. Do not
exchange credentials for other installations. Inventory other Apps' identity
only where the authorized API exposes it. App distribution visibility remains
unknown: repository visibility does not establish App visibility.

Project identities, installations, workflows and requested token scopes as
separate assets. Store source snapshots and coverage in asset metadata, using
the existing versioned ClickHouse asset/edge storage. Preserve prior observed
source data on denied, malformed, failed or truncated reads and mark it unknown;
replace snapshots only with complete reads. This reuses the existing storage
contract rather than creating a second inventory store. Any storage migration
must address a demonstrated schema requirement, not duplicate these records.

Graph relationships are bounded by installations, memberships, workflows and
explicit token targets. Broad tokens connect to their installation, not every
pair of repositories sharing an App. Restricted scopes connect only to their
observed targets. Graph reach does not treat static declarations as confirmed
execution. Findings describe potential paths and their conditions, with no raw
secrets or credentials retained. Credential references are scoped to the source
workflow; their names do not identify a shared key.

Parse the official App-token action, literal identities, scope/permissions,
reusable workflow declarations, conditions, and public-input execution signals.
Unresolved expressions remain unknown. Preserve AWS/GCP declaration correlations
and assess Azure login client/tenant identities against collected inventory.
Execution evidence is out of scope: no Actions run logs or secret values are read.

## API capability evidence

Verified against official sources on 2026-11-27:

- [Apps API](https://docs.github.com/en/rest/apps/apps): JWT-only App identity and
  installation metadata; installation tokens cannot replace the JWT. Token
  creation can narrow repositories and permissions, never widen installation grants.
- [Organization installations](https://docs.github.com/en/rest/orgs/orgs#list-app-installations-for-an-organization):
  installation-token support requires organization Administration read permission.
- [Installation repositories](https://docs.github.com/en/rest/apps/installations#list-repositories-accessible-to-the-app-installation):
  describes the authenticated installation's accessible repositories. It is not
  a directory of another App's selected repositories.
- [App visibility](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/making-a-github-app-public-or-private):
  public/private controls who may install an App, not repository visibility.
- [Official token action](https://github.com/actions/create-github-app-token):
  defaults to the current repository; owner alone requests the owner's full
  installation; explicit repositories narrow access; permission inputs narrow
  grants. Both legacy app-id and current client-id inputs exist.
- [Workflow events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request_target):
  pull_request_target can expose privileged workflow context to untrusted inputs;
  the trigger alone does not demonstrate execution of attacker-controlled code.

## Validation and rollout

Test dangerous/safe workflows, unknown expressions, separate installations,
read-only/narrow permissions, membership gaps, API failure/truncation and lifecycle
changes. Correct the scale fixture to use New(), populated workflow trees and
relationship assertions. Measure 100/1,000/10,000 repositories under the shared
hardware lock, recording requests, elapsed time, memory and graph cardinality.
Regenerate the graph contract and bump the snapshot schema when changing DDL.

## Implemented boundaries

The connector reads default-branch workflow files (50 per repository, 1 MiB per
file), recognizes the official `actions/create-github-app-token` action, and
records other credential references and reusable-workflow call sites. It does
not evaluate arbitrary expressions, execute code, follow reusable workflow refs,
or infer credentials shared by equal secret names. Custom App-token scripts and
third-party token actions are outside static token-scope resolution. File-read
coverage is separate from these analysis limits. Literal App/client IDs identify
declarations; they do not prove the private key belongs to that App.

Repository pagination defaults to 50 pages (5,000 repositories). The 10,000-repo
fixture explicitly raises the limit to 101 pages. A capped enumeration is partial
and cannot establish removal. Production deployments must budget GitHub requests
and rate limits independently of the synthetic fixture timings below.

AWS/GCP cloud target declarations continue to join live inventory, now also from
the workflow node. Edges retain declaration/unknown/execution conditions through
Ladybug loading. Azure login client/tenant IDs are inventoried, but the existing
Azure connector supplies principal object IDs and role grants without the client
ID/tenant mapping or federated credentials. Azure workflow identity resolution is
explicitly unknown; no object-ID/client-ID guess or trust confirmation is made.

Installations and grants are separate: grant and token-scope generations change
when observed permissions, memberships or suspension changes. Complete source
scopes use the existing bounded retirement/confirmation pipeline. Failed reads
retain prior sanitized snapshots with unknown coverage. Large retirement sets
remain subject to the existing confirmation window and bounded drain; old
potential topology can remain during that window. A suspended or removed
connector installation that can no longer mint its observer token fails the sync
and retains previous inventory; it does not assert deletion from failed auth.

No Postgres or ClickHouse columns/tables are added: versioned assets, JSON metadata,
edge properties and the existing Goose retirement migrations provide the required
storage. The Ladybug DDL and snapshot schema are bumped and the generated graph
contract is regenerated. Storage integration tests exercise round trips, unknown
observations, grant retirement and replay on a fresh migrated database.

The reproducible collector benchmark is
`scripts/benchmark-github-visibility.sh NEW_OUTPUT_DIRECTORY`. It compiles outside
measurement and runs three repetitions for each 100/1,000/10,000 fixture, with
normal and denied-GraphQL variants. Fixtures contain a broad App token, a current
repository token with read permission, a public-input execution path and a cloud
identity declaration per repository, with one App installation in one organization.
Half the repositories are public. Many-installation scaling is not measured. Repeats
include prior snapshots. Exact assets/edges and relationship-family counts,
linear API requests and total allocation bounds are test assertions. OS maximum
RSS is recorded separately from Go total allocations. These are deterministic
local transport measurements, not GitHub quota/latency capacity claims.

Narrowing a minted token does not narrow its App private key. A separate potential
key-exposure finding therefore covers an untrusted execution path in the very job
that declares the private-key input, even if the token is restricted to the source
repository. Trusted minting in a separate job is distinguished from that pattern;
no shared credential is inferred across jobs or workflows by secret name.

## Measured fixture evidence

Final collector replay on macOS ARM64, Go 1.26.11, GOMAXPROCS=4, with exclusive hardware
access. Each collector row is the median of three complete repetitions; allocations
are the maximum total allocated bytes per repetition, not retained heap. OS RSS
includes both normal/denied scenarios, retained results, and JSON fixture writing.

| Repositories | Requests per repetition | Collector median | Max total allocation | Process peak RSS | Assets / edges |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 313 | 11.98 ms | 16.53 MB | 32.49 MB | 605 / 702 |
| 1,000 | 3,049 | 91.45 ms | 162.57 MB | 109.10 MB | 6,005 / 7,002 |
| 10,000 | 30,409 | 826.63 ms | 1,660.12 MB | 1,247.48 MB | 60,005 / 70,002 |

Before bounded within-repository reuse, requests were 813 / 8,049 / 80,409 for
the same fixture sizes and relationships. The 10k baseline median was 907.68 ms,
maximum total allocation 1,934.37 MB and process peak RSS 1,174.57 MB. The revised
collector reduces requests and total allocation in this fixture; its observed
peak RSS is higher. RSS comes from one process per size, including repetitions
and fixture writing; this is not an isolated cache footprint or proof of a
resident-memory improvement.

The denied-GraphQL variant preserves the same relationship counts and requests;
its median times were 10.04 / 70.02 / 684.50 ms. First and repeat collections have
the same request counts; repeat collections additionally read prior snapshots
through the fixture callback. These historical fixtures used the retired synchronous
SBOM response. The [asynchronous SBOM follow-up](github-async-sbom-reports.md)
records the supported protocol's additional requests and current ceilings.
The historical gates enforced fewer than `4*N+200` requests after reuse (the baseline gate was `12*N+200`) and
less than `384 KiB*N+16 MiB` total allocation, plus exact relationship counts.

Independent replay reads persisted collector fixtures, runs production AWS/GCP
correlation and graph filtering, then loads the native graph with COPY. It verifies
`4*N+4` supplied nodes, `8*N+2` edges, and `2*N` cloud-correlation edges.
The native graph additionally contains eight standard sentinel nodes and one
schema-metadata node; exact typed node assertions account for these nine nodes.
At 10,000 repositories this is 40,013 resident nodes / 80,002 edges; native load
took 362.24 ms and 56.33 MB total allocations. The replay also verifies
the typed relationship counts, preventing a fast empty or missing-workflow pass.
The existing native AMD64/ARM64 pipeline runs this replay against its generated
fixtures (up to 1,000 repositories on PRs and 10,000 on full runs).

Raw repetitions, persisted fixtures, source patch/hash, environment and process
resource records are retained outside the repository in
`github-app-evidence/cache-final` (the pre-reuse baseline is retained in
`github-app-evidence/final`). Corrected native reports are in
`github-app-evidence/cache-native-final`. All six baseline/candidate fixture pairs
match semantically across assets, edges, findings, closures and completeness after
normalizing observation timestamps; raw fixture hashes and the ignored timestamp
fields are recorded in `github-app-evidence/output-parity-final.json`. Reproduce collection with the script above and replay
with `GITHUB_VISIBILITY_FIXTURES=/absolute/output go test ./internal/app/graphstore
-run '^TestGitHubVisibilityFixtureReplay$' -count=1 -v`. These measurements cover
bounded local work and exact relationships; 30,409 calls to a real GitHub server
would have substantial rate-limit and network costs absent from this transport.

### Request costs and remote limits

Before reuse, the fixture spent eight REST reads per repository: four independent
tree reads (Terraform, Kubernetes YAML, workflows and identifier harvest), three
reads of the same workflow file, and one SBOM read. The shared readers now finish
within each repository, using one successful tree read and one successful file
read for these consumers; those historical fixtures modeled one SBOM read.
The supported asynchronous SBOM flow now needs generation, fetch and download,
plus any pending polls; see the follow-up above for current request measurements.
Pagination, batched
branch-protection/CODEOWNERS GraphQL requests and App/GHAS enumeration add requests.

Reuse is in memory for one repository in one sync. Exact URL (base, repository,
ref, path and options) plus authorization partition entries. Eight admitted
repositories each retain at most 4 MiB of accounted key/payload bytes and 64
entries; map/slice overhead is separately bounded by entry count. Large entries
bypass retention. Tree values are defensively copied and file strings are
immutable. Failed/malformed reads, truncated/missing trees and invalid or oversized
file contents are not cached; a later reader can recover. Cancellation applies
to cache hits too. Cached raw content is released after the repository finishes,
and never persisted or shared between syncs. Tests cover these boundaries and
assert that the real source readers share reads and release retained content.

There is no ETag/Last-Modified conditional fetch or webhook-driven workflow cache.
Retained sanitized source snapshots preserve unknown observations on failure;
they do not skip fresh reads on the next sync. Repeat request counts therefore
remain the same as the first collection after within-sync reuse.

GitHub documents installation-token REST budgets of at least 5,000 requests/hour,
scaling to 12,500 outside Enterprise Cloud; Enterprise Cloud organization
installations receive 15,000/hour. User/PAT budgets and Actions `GITHUB_TOKEN`
budgets are different. GraphQL has a separate primary budget. Secondary limits
also apply, including concurrency and per-minute point limits.
[Official rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api).

The existing client tracks remaining/reset headers per bearer token, waits below
100 remaining when the context permits, and returns an error when reset exceeds
the job deadline. It attempts at most three requests for 429 responses (using
numeric Retry-After or a 60-second fallback); 5xx responses get two short-backoff
retries. A 403 is returned as an error, with primary exhaustion distinguished by
remaining=0; secondary-limit 403 does not currently receive the 429 retry path.
Unknown workflow/App coverage survives these failures. The new workflow reader
limits concurrency to eight, which alone is not a rate-limit pacing guarantee.

GitHub recommends respecting Retry-After/reset, backing off secondary-limit
errors, and authenticated conditional requests; unchanged 304 responses can avoid
primary quota consumption.
[Official API practices](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api).
Remote throughput, quota recovery and inventory freshness at 10,000 repositories
remain unmeasured. The linear request ceiling is a regression guard, not a claim
that a complete live sync fits a single quota window or the current job deadline.

## Validation completed

Pinned Go 1.26.11 and golangci-lint 2.12.2 root/nested-module checks pass,
including 110 root unit packages, nested Ladybug tests, integration-tag vet on
changed packages and targeted race tests for repository read reuse. Fresh isolated
Postgres/ClickHouse migrations and the complete integration suite pass, including
snapshot/unknown-edge persistence and idempotent grant retirement. Bun 1.4.5 lint,
338 frontend tests and the production build pass. Generated graph contracts and
schema pins are checked by the suite. Native Linux AMD64/ARM64 PR checks provide
separate architecture validation; local timings above are macOS ARM64 only.
