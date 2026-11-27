# Performance assurance — spec

**Status:** PERF-01/02 implemented; PERF-03/04 measurements and guards under validation
**Author:** Vulngraph maintainers
**Date:** 2026-11-27
**Tracking:** [#19](https://github.com/vulngraph/vulngraph/issues/19)

## Problem

The existing native pipeline matrix measures representative fixtures. It has no
complete workload denominator. Service reads omit HTTP/browser overhead; external
processing, service-family fan-out, aged storage and full recovery remain gaps.
The [15-item worklist](../performance-assurance.md) records these limitations.

## Goals

1. Reconcile explicit workload memberships against shipped registrations and
   production service modules. Added, removed and unmapped entries fail a cheap
   check. Stable family IDs, owners and risk weights precede measurements.
2. Fix dataset, arrival, resource and correctness budgets for small, target and
   stress profiles. Report native architectures separately. Optional shipped
   features remain in scope. No family gets credit from documentation alone.
3. Measure inventory and dashboard queries on matched fixtures, preserving
   liveness, filters, ordering, cursors and counts. Retain query plans and costs
   before choosing a change; add correctness/cost regression checks with fixes.

## Design

The inventory is versioned JSON under `docs/performance/`. A repository-local
checker discovers entry points and compares them with explicit membership lists;
it never automatically assigns new functionality to an already covered family.
Service-module coverage complements registrations because many collector service
families are direct calls rather than registry entries. Helpers share a family's
cost model instead of increasing the denominator. Different material cost models
(e.g. inventory filtering and finding-rollup risk ordering) have distinct families even
when they share an HTTP route.

Profiles and reusable scenario/budget classes are referenced by each family.
Every family starts unmeasured; prior results are supporting evidence, pending
applicability review against the required scenarios. A covered result must name
the inventory/profile revision, native hardware, source, schema/dependencies,
complete repeated samples, independent correctness readback and retained raw
artifacts. Partial/failing/stale results contribute zero. Acceptance requires all
critical families and at least 90% weighted coverage in each declared profile.

Query experiments use isolated disposable datastores and deterministic fixtures,
initially covering wide metadata, filters/cursors, risk rollups, retained versions
and concurrent existing-resource updates. Full deletion/reappearance and stale
topology scenarios remain acceptance gaps.
Compare exact values and query-log rows/bytes/memory; shared-machine timing is
informational. Strict latency acceptance requires controlled hardware. External
provider fixtures and live-provider evidence are separate scenarios.

## Alternatives considered

Counting the 15 work items or passing test functions would hide missing service
families. A wildcard mapping would silently credit new work. Blanket FINAL/join
replacement could alter deduplication, liveness and snapshot semantics without a
measured benefit. None provides the evidence this plan requires.

## Testing

Mutation checks must reject new registrations/modules, missing owners/scenarios,
duplicate IDs and invalid weights. Query regressions compare independently
constructed expectations and retained baseline SQL on the same fixture. Existing
root/Ladybug lint/unit, integration and contract gates remain required. Native
repeat runs and independent replay remain explicit acceptance work.

## Rollout

Land inventory, profiles and reconciliation first. Follow with focused measured
query changes. No schema or API change is planned. Retain all 15 work items and
their gaps until each completion rule is met; a harness alone closes none.

## Open questions

Controlled native hardware and a coordinated 24-hour mixed soak are not yet
available. The parallel GitHub App task must supply its new registrations,
scenarios and request budgets before a release coverage claim.
