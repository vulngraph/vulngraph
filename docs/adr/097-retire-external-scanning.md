# ADR 097 — Retire active external scanning

**Status:** accepted

## Decision

Remove embedded Nuclei, external scan profiles and schedules, template testing
and generation, generic scan imports, and the MCP scan-start tool. External
probing does not fit this open-source project's scope. Removing the engine also
removes its template execution paths, downloads and dependency tree.

Keep inventory collection, posture checks, image and package analysis, scoped
package-inventory submission, and the opt-in VM disk workflow in ADR 096.
The isolated scanner process now only reads disk volumes. It has no graph RPC
secret and its ClickHouse user only reads the migration ledger. Its Postgres
permissions remain limited to River, disk results and the connector-mode view.
Drift analysis remains advisory and cannot start external scans.

## Upgrade

Goose migration 7 disables saved profiles and cancels unfinished external-scan
jobs, including installations with an older River state enum. It preserves
historical runs, findings and audit records and leaves disk jobs alone. Stop old
application workers before migrating; an old binary must not enqueue retired
jobs after the migration. Deploy the new worker and serve binaries together.
The removed HTTP endpoints return 404. A rollback does not reactivate profiles
or restart cancelled work automatically.

Migration 8 binds approvals to the user's authority version and starts a new
recorded administrator tenure for existing active administrators. Pending old
grants must be reissued, and the configured minimum tenure must elapse before
an existing administrator can issue a new high-risk approval. It preserves the
`admin_since` column introduced by migration 6 when rolled back.

ADR 009 and the active-scanning portions of ADR 020 are superseded. Their text
is retained as historical context.
