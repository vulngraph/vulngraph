# Migrations

Schema changes are goose migrations embedded in the binary (`migrations/postgres/`,
`migrations/clickhouse/`) and applied by `graph migrate` behind a Postgres advisory lock
(`internal/migrate`). Only one thing runs it: the serve pod's `migrate` init container in
the Helm chart, or the one-shot `migrate` service in `deploy/docker-compose`. The worker
and scanner never migrate; at boot they wait until the database reports every migration
the binary knows as applied (`cmd/graph/migrate_wait.go`), so on an upgrade they stay
unready until serve's init container has finished. River's own job tables are migrated
by River.

## Numbering

Each engine has its own sequence of five-digit versions. `00001_init.sql` creates the
whole schema; each later change is the next number: `00002_short_description.sql`.

- **Take the next number above the highest on `main` for that engine.** Before you merge,
  rebase and check again: a parallel branch may have taken the same number or a higher one
  in the meantime. If it did, renumber yours above it.
- **Never number a migration below one already on `main`.** goose runs in strict order (we
  do not pass `goose.WithAllowOutofOrder`). A database that has applied `00005` refuses to
  start when `00004` appears later: `graph migrate` fails and so does every pod's boot.
- **Number contiguously.** `TestEmbeddedMigrationsAreWellFormed` fails on a gap.
- **Never edit a migration that is on `main`.** goose records applied versions without a
  content hash, so an edit runs only on fresh databases and never reaches deployed ones.
  Change the schema with a new migration.

## Why strict order, not out-of-order

Out-of-order application is only safe when every migration is independent of every other.
Schema changes are not: a migration that creates a table, one that backfills it and one
that drops the columns it replaced must run in that order, and a late-landing migration
that assumed an earlier schema could run against a later one. Failing the boot loudly is
better than applying it.

## What enforces this

- `TestEmbeddedMigrationsAreWellFormed` (`internal/migrate`, every `go test`): versions are
  unique, contiguous from `00001`, and every SQL file has `-- +goose Up`.
  Numbered Go migrations must also be embedded and explicitly registered by
  `migrations.ProviderOptions`, shared by execution and readiness checks.
- `scripts/check-migration-order.sh <base-ref>` (CI `migration numbering` job, pull requests
  only): every migration the PR adds is numbered above the base branch's highest for its
  engine, and no migration already on the base branch is modified or deleted. Run it
  locally with `scripts/check-migration-order.sh origin/main`.

## Writing one

- Postgres: plain DDL, and update `internal/db/queries` plus `sqlc generate` when queries
  change. ClickHouse: every table is `ReplacingMergeTree` with a `TTL` (audit tables:
  `MergeTree`, 7-year TTL); see the ClickHouse section of `CLAUDE.md`.
- Prefer additive, idempotent statements (`IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`) so a
  re-run after a partial failure is harmless.
- A Go migration uses the same per-database Goose sequence and ledger as SQL.
  Register it on that database's provider, never Goose's process-global registry.
- A change to what the Ladybug graph loads also bumps `SchemaVersion`
  (`internal/app/graphstore/domain.go`); there is no in-place Ladybug migration.

## External-scanning retirement and authority upgrade

The public schema is upgraded by PostgreSQL migrations 7 and 8. Existing
migrations 1–6 and ClickHouse migration 1 remain unchanged. Migration 7 disables
external-scan schedules and cancels unfinished external-scan jobs. Stop old
workers before applying it so they cannot enqueue retired work afterward.
Migration 8 adds `authority_version`, invalidates old approval grants and
records a new tenure start for existing active administrators. The configured
minimum tenure must elapse before they can issue a new high-risk approval.
See [ADR 097](adr/097-retire-external-scanning.md) for rollback behavior.

`TestGooseParsesEmbeddedSQLInBothDirections` validates complete Goose Up/Down parsing.
The integration suite tests fresh installation, upgrade from version 6,
older River enums, reruns and down/reapply. It also tests the scanner's
restricted database grants. River still owns its own migration ledger;
`graph migrate` runs it in the same migration command after PostgreSQL Goose.

## ClickHouse version precision upgrade

ClickHouse migration 3 rebuilds the seven tables whose replacement versions
used whole-second timestamps, changing those columns to `DateTime64(9)`.
It preserves table defaults, indexes, settings and comments. Ordinary observation
timestamps keep their existing types. This prevents distinct subsecond versions
from collapsing to the same second; it does not impose ordering across machines
with skewed clocks or repair older writes whose precision was already lost.

Schedule a maintenance window, stop writers, back up the database and allow
temporary space for a second copy of the largest affected table. The migration
requires an Atomic database and the migration role's database-wide grants, plus
`SELECT` on `system.detached_tables` and `system.mutations`. Bundled deployments
include these grants. Before upgrading an external ClickHouse database, have its
administrator apply the two additional grants in [the setup SQL](../deploy/README.md#external-datastores). Custom dependent views must be removed and recreated around the upgrade.
Migration time depends on the table sizes and storage throughput.

During each table copy the public name is unavailable. A synchronous detach/attach
drains existing users after the rename. The migration compares canonical row
counts and checksums of stored values before publishing the replacement. The
source is kept under `_vg_m3_<table>_source` until verification succeeds; never
delete or modify these intermediate tables manually. If interrupted, rerun
`graph migrate` in the same direction. Goose records version 3 only after every
table finishes. Resume an interrupted upgrade before attempting rollback.

Rollback also needs a maintenance window: it rebuilds from current rows, retaining
the newest version before reducing precision. It does not restore an old backup,
and whole-second version ties become possible again after rollback.
