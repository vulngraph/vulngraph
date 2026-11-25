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
  unique, contiguous from `00001`, and every file has `-- +goose Up`.
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
- A change to what the Ladybug graph loads also bumps `SchemaVersion`
  (`internal/app/graphstore/domain.go`); there is no in-place Ladybug migration.
