# <Title> — spec

**Status:** draft
**Author:** <you>
**Date:** <yyyy-mm-dd>

## Problem

What's broken, missing, or costly today? Who hits this, and how do you know
(a measurement, a user report, a limitation you ran into)? Don't describe the
solution here — just the problem, stated so someone who's never seen it would
recognize it as real.

## Goals

What this change must accomplish. Specific enough that a reviewer can check
the shipped code against this list.

## Non-goals

What this deliberately does NOT cover, and why — scoping a spec down is a
feature, not an admission of incompleteness. A future spec can extend it.

## Design

The actual proposal. Enough detail that someone else could implement it from
this section alone: data model / schema changes, new interfaces, which
existing code it touches, how it fails (what happens on a partial failure,
a missing dependency, bad input).

## Alternatives considered

What else you looked at, and why you didn't pick it. This is often the most
useful section for a reviewer — it's where disagreements get surfaced before
code is written instead of after.

## Testing

How you'll know this works, and how you'll know if it breaks later. What's
the guard test? What's genuinely hard to test and why (and what you're doing
about that instead).

## Rollout

Any migration, feature flag, or staged rollout this needs. What the
rollback path looks like if it doesn't work.

## Open questions

Anything you're not sure about yet. Fine to leave some for review — that's
what the PR discussion is for.
