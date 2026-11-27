# 098: Precise storage versions

Status: Accepted

Inventory and finding updates must remain distinguishable when two writes occur
within a second. ReplacingMergeTree version timestamps use `DateTime64(9)`;
ordinary observation and retention timestamps keep their existing types.
This orders writes by their timestamp, not by transaction completion across hosts.

ClickHouse cannot alter a DateTime version column to DateTime64 in place. A
Goose Go migration rebuilds the affected tables, preserving defaults, indexes,
settings and comments. It renames the source away from its application name and
uses synchronous detach/attach to drain in-flight access before copying. Reads
and writes to that application name fail until a verified replacement is ready;
the migration never exposes a partially copied table.

The source remains available under a migration-owned name until the replacement
has passed count and content checks. Table UUIDs and migration markers distinguish
owned intermediate tables from unrelated tables. A retry resumes interrupted
work, and rollback rebuilds from the current canonical rows rather than restoring
an obsolete backup. Goose records the version only after all tables complete.

An upgrade needs a maintenance window and temporary disk space for the largest
table being rebuilt. Stop application writers first to avoid retrying operations
against temporarily unavailable tables. The database fence also protects the copy
if an old writer is accidentally left running. Fresh installation, populated
upgrade, interruption recovery, rollback and rapid successive writes are tested
against real ClickHouse.
