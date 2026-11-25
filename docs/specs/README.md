# Specs

Larger changes start with an ADR or a spec. Most decisions so far are
recorded as ADRs in [`../adr/`](../adr/). Use a spec when a change needs its design agreed
*before* the implementation PR. The spec is the place to work out
the design, name the tradeoffs, and get agreement on the shape of a change
while it's still cheap to change — not a formality to backfill once the code
is already written.

A spec proposes; [`../adr/`](../adr/) records what was decided. Check the ADR
index before writing a spec — it's the fastest way to find out something was
already tried and rejected for a documented reason.

## When you need one

- A new feature, connector, check, or graph capability.
- A change to an existing data model, API contract, or schema.
- Anything that touches more than one domain (`internal/app/<name>/`) or
  changes a cross-cutting convention documented in [`CLAUDE.md`](../../CLAUDE.md).

You don't need one for a bug fix, a small refactor, a dependency bump, or
anything whose design is obvious from the issue itself — use judgment, and
when in doubt, open the issue first and ask.

## Process

1. **Copy [`TEMPLATE.md`](TEMPLATE.md)** to `docs/specs/<yyyy-mm-dd>-<short-name>.md`.
2. **Open it as a PR** with just the spec — no implementation code. This is
   where design discussion happens: alternatives considered, what breaks,
   what the tests need to prove.
3. **Get it accepted** (a maintainer approves the PR). The spec can change
   during review — that's the point of writing it first.
4. **Implement it** in a follow-up PR (or PRs) that reference the spec. Tests
   land in the same commit as the code they cover, per `CLAUDE.md`.
5. **If reality disagrees with the spec once you're implementing it**, amend
   the spec in the same PR rather than silently diverging — the spec should
   stay true to what actually shipped.

A spec that's accepted and implemented stays in `docs/specs/` as the full
design record. If it settled a durable architectural decision — something
future work should not silently re-litigate — add a short entry to
[`../adr/`](../adr/) pointing back to it; the ADR is the one-page summary,
the spec is the detail behind it.

## What makes a good spec

- States the **problem** before the solution — what's broken or missing, and
  for whom.
- Names the **alternatives** considered and why they were rejected, not just
  the chosen approach.
- Says what it **doesn't** cover as clearly as what it does.
- Is falsifiable: a reviewer (or future you) can look at the shipped code and
  tell whether it matches the spec.
