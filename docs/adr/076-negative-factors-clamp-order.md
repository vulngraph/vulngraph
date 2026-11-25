# ADR 076: Negative score factors are spent against a clamped positive subtotal, not against the raw sum

**Status:** accepted (2026-08-21)

## Context

`Aggregate` in `internal/app/enrich/score.go` (ADR 014's additive scorer) summed *all* factor
points — positives and negatives together — and clamped the result at the very end:

```go
sum += f.Points          // for every factor, sign included
...
if sum > 100 { sum = 100 }
```

That is correct only while the positive subtotal stays under 100, and it need not.
A plausible `gcp-privesc` factor set — base severity 20 + blast radius 30 + internet
reach 20 + EPSS 12 + age 10 + toxic combo 20 — sums to 112 raw. Above 100 the clamp absorbs the entire negative contribution, so a demote
becomes a no-op that still shows up, plausibly, in the factor breakdown the UI renders.

Example: a non-production service account (`principal_class: -10` —
"non-production principal (test/staging)" — applied, factors sum 112) and a
production service account (no demote, factors sum 112) **both score exactly 100**. The
demote is computed, persisted in the breakdown, and arithmetically discarded. Every
negative-emitting source is affected, and `reachUnreachablePenalty = -25`
(`sources_reach.go`) faced the same fate on anything summing past 125 — meaning the
noise-suppression signal the reachability gate exists to provide silently stopped working on
exactly the loudest findings, the ones where it matters most.

The failure mode is invisible from the source side: each source is individually correct and
unit-tested, and `sources_principal_test.go` asserts only that the factor is `-10`. Only the
aggregator sees the interaction, and it had no test above the clamp with a negative present.

## Decision

**Clamp the positive subtotal to 100 *before* applying negatives.** The arithmetic order in
`Aggregate` is now, explicitly:

1. Sum the positive points; clamp that subtotal to 100.
2. Add the negative points (demotes, penalties) to the clamped subtotal.
3. Apply the highest declared `Floor`.
4. Apply suppression (page-floor exception preserved, ADR 059).
5. Apply the lowest declared `Ceiling` (same page-floor exception).
6. Bound to 0..100 and band it.

Steps 3–6 keep the precedence the previous code established — this ADR changes only where the
clamp sits relative to the negatives. The invariant it buys:

> Adding a negative factor to any factor set produces a **strictly lower** final score than the
> same set without it — unless the score is already 0, or an explicit `Floor` pins it.

**Floor still beats a demote, and that is why the floor is applied after the negatives.** A
`Floor` is a source asserting "this must always be at least band X" (KEV: known-exploited
always pages). That is a categorically stronger claim than "this principal matters somewhat
less", so a demote moves the score freely within the headroom above the floor and can never
push it below. Concretely: positives clamped to 100, `-25` penalty, page floor 81 → 81 (floor
wins); the same set with `-10` → 90 (headroom exists, demote honoured in full).

## Alternatives considered

Two alternatives were rejected:

- **Normalising/scaling the positive sum** (e.g. dividing 112 down to 100) — it silently
  redefines every threshold in `domain.go` and every band boundary tuned against them, for a
  problem that is purely about clamp ordering.
- **Raising the ceiling above 100** — the 0–100 contract is what the API, UI sorting and the
  band thresholds are built on; widening it moves the bug into every consumer.

## Consequences

- Scores drop for findings that were being over-scored by an absorbed demote. This is the
  point: a staging service account no longer pages with the same score as its production twin.
  Expect a visible re-band on re-enrichment for `gcp-privesc`-family findings with
  `principal_class: non-production` or an unreachable principal.
- The invariant is enforced by a table-driven regression test
  (`TestAggregate_NegativeFactorAlwaysLowersScore`) that sweeps positive sets straddling the
  clamp (5, 55, 90, 100, 105, 200, and the 112 example set) against negatives −1/−5/−10/−25,
  plus explicit tests for the 112 ± −10 case, staging-below-production, the −25 unreachable
  penalty above the clamp, and floor-beats-demote. A future negative-emitting source cannot
  reintroduce the absorption without failing these.
- Scores are not versioned by this change on their own; a full re-enrichment pass is what
  materialises the corrected values (see ADR 069 and the enrich fingerprint-version
  discipline — logic changes need the fingerprint prefix bumped or findings serve stale
  answers).
- No existing test encoded the old behaviour, so none had to be relaxed — the old order was
  simply untested above the clamp with a negative factor present.

Cites ADR 014 (the additive scorer and its clamp), 059 (the band-floor family and the
page-floor exception preserved here), 060 (the reachability gate whose −25 penalty this
restores), 067 (the scoring-integrity pipeline this extends: the same "each layer is
individually correct, the interaction is not" shape).
