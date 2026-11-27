#!/usr/bin/env bash
# Fails when a migration added on this branch is numbered at or below the
# highest migration already on the base branch, per engine.
#
# goose runs in strict order (internal/migrate, docs/migrations.md): a database
# that has applied 00005 refuses to start when 00004 appears later. Parallel
# branches that each take "the next number" collide exactly this way, and the
# unit test cannot see it — it only knows the merged tree, not which side was
# first. Run in CI on pull requests; rebase and renumber to fix.
#
# Usage: scripts/check-migration-order.sh <base-ref>   (e.g. origin/main)
set -euo pipefail

base="${1:?usage: $0 <base-ref>}"
status=0

for engine in postgres clickhouse; do
  dir="migrations/$engine"
  base_max=$(git ls-tree --name-only "$base" "$dir/" | sed -En 's#.*/([0-9]{5})_.*\.(sql|go)$#\1#p' | sort -n | tail -1)
  base_max=$((10#${base_max:-0}))
  while IFS= read -r path; do
    [ -z "$path" ] && continue
    file=$(basename "$path")
    case "$file" in [0-9][0-9][0-9][0-9][0-9]_*.sql|[0-9][0-9][0-9][0-9][0-9]_*.go) ;; *) continue ;; esac
    version=$((10#${file:0:5}))
    if [ "$version" -le "$base_max" ]; then
      echo "::error file=$path::$file is numbered at or below $base's highest $engine migration ($base_max); renumber it above $base_max"
      status=1
    fi
  done < <(git diff --name-only --no-renames --diff-filter=A "$base"...HEAD -- "$dir/")

  # A migration that already exists on the base has run on deployed databases:
  # editing, renaming or deleting it never reaches them. --no-renames reports a
  # rename as delete+add so the add is checked above and the delete here.
  while IFS= read -r path; do
    [ -z "$path" ] && continue
    case "$(basename "$path")" in [0-9][0-9][0-9][0-9][0-9]_*.sql|[0-9][0-9][0-9][0-9][0-9]_*.go) ;; *) continue ;; esac
    echo "::error file=$path::$path exists on $base and was modified or deleted; add a new migration instead"
    status=1
  done < <(git diff --name-only --no-renames --diff-filter=MD "$base"...HEAD -- "$dir/")
done

exit "$status"
