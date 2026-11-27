# Asynchronous GitHub SBOM reports

Issue: https://github.com/vulngraph/vulngraph/issues/22

GitHub retired the synchronous dependency-graph SBOM endpoint on November 13,
2026. Its old mocked 200 response cannot validate current GitHub compatibility.
This follow-up changes SBOM acquisition; App/workflow visibility remains separate.

## Protocol and authorization

Use the current REST API version `2026-03-10`: GET `generate-report` returns 201
and an `sbom_url`; GET that report URL returns 202 while pending and 302 with a
temporary download location when ready. The current REST reference specifies
202; the older announcement's 201 pending response is not treated as completion.
The report URL must remain on the configured API origin, within the requested
repository and the fetch-report path with a UUID. No authenticated redirects are
followed. Downloads use fresh GET requests without Authorization, cookies or
Referer, require HTTPS, and retain safenet's transport checks for private/reserved
addresses at every connection. Temporary URLs and their queries are neither
stored nor included in errors.

Sources: [current REST reference](https://docs.github.com/en/rest/dependency-graph/sboms),
[retirement notice](https://github.blog/changelog/2026-05-12-synchronous-sbom-api-deprecated/),
[original asynchronous announcement](https://github.blog/changelog/2026-04-14-sbom-exports-are-now-computed-asynchronously/),
[retry and polling guidance](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api).

## Bounds and incomplete coverage

Keep three concurrent report jobs. Each repository has a two-minute deadline,
at most six poll cycles, three attempts per HTTP operation, and three download
redirects (at most 33 HTTP attempts per repository across all stages, subject to
the deadline). Pending/retry responses use bounded exponential fallback delays and
honor valid Retry-After and X-Poll-Interval values. Rate-limit responses without
Retry-After start at one minute. A delay beyond the remaining deadline returns an
incomplete result. Authenticated requests also use the existing remaining/reset
rate tracking. These bounds do not guarantee avoidance of rate limits.

Generation responses are limited to 64 KiB and reports to 32 MiB. Downloads must
contain an identifiable SPDX 2 document with an explicit packages array; both raw documents and the historical
API envelope are accepted. Unsupported/malformed documents, pending exhaustion,
denials, expired URLs, rate exhaustion and failed downloads yield unknown SBOM
coverage and a partial collection. They cannot establish an empty dependency
inventory or authorize absence-based cleanup. A valid empty SPDX document is a
complete observation. Archived repositories remain uncollected. No package
retirement scope or persistent report cache is added.

## Validation and cost accounting

Test ready and pending reports, retries/cancellation, malformed and oversized
responses, endpoint/origin/repository boundaries, redirects and credential
isolation, and complete-empty versus incomplete coverage. Migrate populated
100/1,000/10,000-repository fixtures to the current protocol and retain exact
package/relationship assertions.

An immediately ready report now needs generation, fetch and download instead of
one old synchronous request. Additional pending polls add API requests. Record
API-origin requests separately from temporary-download requests; these do not
necessarily consume the same rate bucket. Update the fixture request ceiling
with this explicit protocol cost, preserving the earlier evidence as a legacy
protocol baseline. Synthetic local timings omit remote generation time, network
latency and quota waits; live throughput and freshness remain unmeasured.

The populated ready and GraphQL-denied scenarios require fewer than `6N+200`
total requests; the one-pending-poll scenario requires fewer than `7N+200`.
All require exactly `N` downloads and respectively `2N` or `3N` SBOM API calls.
The former `4N+200` ceiling applied to the retired single-request protocol;
the increase is the explicit two-request per-repository protocol cost. Pending
fixture waits use a virtual clock and are counted separately. Exact output
bounds stay `6N+5` assets and `7N+2` relationships; allocation remains below
`384 KiB*N + 16 MiB` per collection.

## Measured local evidence

Go 1.26.11, Darwin arm64, GOMAXPROCS=4; three repetitions of each ready,
GraphQL-denied and one-pending scenario at each size. The fixture has one shared
package per repository and the populated workflows/App grants described in the
visibility specification. It does not measure maximum-size SBOM reports.

| Repositories | Ready requests (API + download) | Pending requests (API + download) | Ready median ms | Pending median ms | Maximum total allocation MB |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 413 + 100 | 513 + 100 | 11.00 | 11.17 | 17.62 |
| 1,000 | 4,049 + 1,000 | 5,049 + 1,000 | 81.03 | 81.40 | 174.00 |
| 10,000 | 40,409 + 10,000 | 50,409 + 10,000 | 810.99 | 790.43 | 1,773.99 |

Allocation is total Go allocation per collection, not live or peak memory.
Process peak RSS was 33.51 / 120.54 / 1,201.16 MB, including all nine collections
and fixture serialization at each size. This process includes an extra pending
scenario compared with the earlier visibility evidence; these RSS observations
are not a matched before/after comparison. Virtual pending waits and timing noise
explain why pending's local median can be lower despite more requests.

All 27 collections passed request, allocation and exact output bounds. Independent
native replay at 10,000 repositories verified 40,013 nodes and 80,002 relationships,
including 20,000 cloud joins. Nine comparisons against the previous ready/denied
fixtures preserve assets, relationships, findings and completeness after ignoring
observation timestamps and asserting the new `sbom_coverage=complete` metadata.

The 10,000-repository ready scenario makes 20,000 SBOM API requests, 10,000 tree
reads, 10,000 workflow-content reads, and 409 pagination, GraphQL and App/GHAS
requests, plus 10,000 downloads. API-origin totals mix authentication identities
and REST/GraphQL budgets; they must not be treated as one quota bucket.
[GitHub's rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
depend on token type and installation/account configuration. Generation time,
network delays, quota waits and live freshness remain unmeasured. There is no
persistent report or conditional-fetch cache.

Reproduce with `scripts/benchmark-github-visibility.sh /absolute/new-output`, then
`GITHUB_VISIBILITY_FIXTURES=/absolute/new-output PERF_CONNECTOR_MAX=10000 go test
./internal/app/graphstore -run '^TestGitHubVisibilityFixtureReplay$' -count=1 -v`.
Raw repetitions, fixture outputs, request breakdowns, native counts, environment,
source patch/hash and RSS records are retained in `github-sbom-evidence/async-final`;
semantic comparison evidence is `github-sbom-evidence/output-parity.json`.
