# ADR 018 — Keyset pagination for findings

**Status:** accepted · amended 2026-10-23 (score moved to `finding_enrichment`; per-page cost)

## Context

`GET /api/findings` (and the `finding` repo's `List`) caps results at `defaultLimit = 200`
with no way to read past it — no offset, no cursor, no total. That suits the product's
lead-on-top-risk view, but on a large estate there's no path to browse, export, or scroll
beyond the top 200; the list silently truncates.

Findings live in ClickHouse as a `ReplacingMergeTree`, read via `argMax(col, synced_at)` over
`GROUP BY id`. Two constraints follow:

- **Offset pagination is wrong here.** `LIMIT n OFFSET m` rescans and discards `m` rows every
  page — pathological at depth on a large table.
- **The sort columns are aggregates.** The default sort is `argMax(score, synced_at) DESC`
  (or `argMax(detected_at, synced_at) DESC` for `?sort=detected`). Aggregates can't sit in
  `WHERE`; they live in `HAVING`. And the current `ORDER BY` has no tiebreaker, so equal scores
  order nondeterministically — a latent bug a cursor would otherwise inherit.

## Decision

**Keyset (seek) pagination, cursor-based, with a stable tiebreaker.**

- **Stable order:** append `id` as the tiebreaker — `ORDER BY <sortExpr> DESC, id DESC`. This
  makes the order total (no ties) so a cursor can resume deterministically.
- **Cursor = the last row's `(sortValue, id)`**, compared as a tuple in `HAVING`:
  - score sort: `HAVING (argMax(score, synced_at), id) < (?, ?)`
  - detected sort: `HAVING (argMax(detected_at, synced_at), id) < (?, ?)`
  ClickHouse tuple comparison is lexicographic, so `(score, id) < (lastScore, lastId)` is exactly
  "the rows after the cursor" under `DESC, DESC`. No `OFFSET`, no deep rescans.
- **Opaque cursor token.** Base64url of `"<mode>|<sortval>|<id>"` (`mode` = `s`|`d`; `sortval` =
  the score int or `detected_at` unix-nanos). Opaque to clients; encodes which sort it belongs
  to so a cursor can't be misapplied across sort modes.
- **Response is an envelope, not a bare array:** `{ "items": [...], "next_cursor": "..." }`.
  `next_cursor` is set only when the page is full (`len == limit`), i.e. more may exist; absent
  on the last page. `Filter` gains a `Cursor string`; the handler parses `?cursor=` and `?limit=`.
- **`min_score` / `source` / `severity` filters compose** with the cursor unchanged — the cursor
  condition is just one more `HAVING`/`WHERE` term.

> **Amendment (2026-10-23).** `score` moved to `finding_enrichment` (ClickHouse),
> so the score-sort seek now runs over the joined `fe.score` aliased as `score`
> (`(score, id) < (?, ?)`) instead of `argMax(score, synced_at)`. The current SQL is in
> `internal/app/finding/repo.go` (`selectFindingKeysArgMax` and `List`).

## Consequences

- Keyset pagination avoids OFFSET's discarded rows, and a cursor resumes deterministically at
  any depth. But the seek condition is a `HAVING` over aggregates, so each page still aggregates
  every finding id: per-page cost grows with table size, not depth. Peak memory is kept down by
  a two-phase read (`selectFindingKeysArgMax` picks the page's ids from narrow key columns only,
  then `ByIDs` hydrates the wide columns).
- The response shape of `GET /api/findings` changes from `Finding[]` to `FindingPage`
  (breaking) — the generated frontend client and `useFindings` move to the envelope (a
  `useInfiniteQuery`); the openapi spec + contract test pin the new shape.
- Adding the `id` tiebreaker also fixes the pre-existing nondeterministic ordering of
  equal-scored findings.
- Cursor encode/decode is pure and unit-tested; the keyset SQL is covered by the finding repo
  integration test (CI runs it against real ClickHouse — the only place it's verifiable).
- Assets/scans/etc. keep their simple caps for now; this ADR is scoped to findings (the
  high-volume surface). The same pattern applies if/when they need it.
