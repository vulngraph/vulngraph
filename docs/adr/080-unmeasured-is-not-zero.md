# ADR 080 — unmeasured is not zero: the auto-execute gate takes evidence with its known-ness

**Status:** accepted (implemented 2026-08-21) · **superseded in part by [ADR 087](087-no-autonomous-remediation.md)** (the gate no longer weighs blast radius; the known-ness convention and guard remain)

## Context

The generator behind most of this platform's recurring data-quality defects is:

> *a function received degraded input, logged a warning, and returned a value
> indistinguishable from a good one.*

Several instances have been fixed individually — CT-log query gaps, pruned-node
lookups, the blast-radius seed, the bulk edge fetch, the image-sweep status and the
`endpoint_absent` accounting. They are not separate bugs. They are one convention —
partiality communicated by a side channel (a log line, a bool on a shared struct, an
absent row) that callers can ignore for free — applied many times.

An audit of every non-test function under `internal/` and `pkg/` that can return partial
or degraded data with a nil error produced an inventory of such sites, ranked by
consequence rather than count. Most of them are dashboard aggregates, collector coverage gaps and
Cypher readers: a wrong number on a page. Exactly one class ends in a **cloud mutation**,
and that is what this ADR is about.

### The instance that reaches the autonomy gate

`respond.blastRadiusFor` walks a finding's blast radius. Three failure paths collapsed
into `asset.BlastRadius{}` with **no error and no completeness signal**:

- both walks erroring (a ClickHouse `Code: 241`, a pruned Ladybug seed),
- `ResolveID` erroring,
- `ResolveID` resolving to nothing new.

`Decide` then took `blastCount := len(br.Assets)` off that value — **zero** — and handed it
to the only gate in this system that grants autonomy:

```rego
allow_auto if {
	not destructive_actions[input.action_class]
	input.action_class != "observe"
	input.confidence_band == "high"
	input.blast_radius <= 10        # ← 0 satisfies this
}
```

So a ClickHouse memory error on the blast walk was **stronger evidence for autonomy than
a successful walk of eleven assets.** The failure to measure was the single most permissive
input the gate could receive, and it arrived wearing the same type, the same shape and the
same nil error as a real measurement. ADR 077's publish-boundary defect is the same shape one
domain over; the difference is that this one's consequence is `auto_executed` on a webhook
rather than a stale dashboard.

A second, quieter instance sat directly underneath it. `asset.BlastRadiusDir`'s batch node
hydration did this:

```go
fetched, err := s.repo.ByIDs(ctx, ids)
if err != nil {
	fetched = nil // degrade to stubs below
}
```

A `ByIDs` failure substituted `Asset{ID, Type}` placeholders for every node in the hop — no
`Provider`, no `RiskScore`, no `LastSeen` — and returned a nil error. The **count** stayed
correct, which is why nothing ever noticed; everything derived from the nodes did not.
`summarizeBlast`'s `ByType` and `topReachable` render those placeholders to the LLM reasoner
as measurements, and `Truncated` stayed false, so the reason-cache fingerprint did not even
change.

## Decision

**Every evidence field of `policy.Input` is paired with a `<Field>Known bool`, and
`allow_auto` requires all of them.** Evidence means something the gate measures about the
estate, as opposed to the action being proposed.

```go
type Input struct {
	ActionClass      string `json:"action_class"`
	ConfidenceBand   string `json:"confidence_band"`
	BlastRadius      int    `json:"blast_radius"`
	BlastRadiusKnown bool   `json:"blast_radius_known"`
}
```

`blastRadiusFor` returns `(asset.BlastRadius, bool)`; `Decide` threads the bool into the
gate. `BlastRadiusDir` stops degrading a hydration failure into stubs and returns the
wrapped error, which reaches `blastRadiusFor` as an errored walk and therefore as
unmeasured. Unknown evidence falls through to `needs_approval`: a human sizes what we could
not.

Three properties make this more than another flag.

- **The safe value is the ZERO value.** A caller that forgets `BlastRadiusKnown` gets no
  autonomy, not unearned autonomy. The next field added to this struct fails closed by
  default rather than failing open by omission — the opposite of `BulkPassFailed`, whose
  zero value meant "everything is fine" and whose consumer could ignore it for free.
- **It is at the chokepoint, not at the source.** Every silent partiality that can cause a
  wrong auto-executed mutation must arrive as a field of `policy.Input`, because that struct
  is the sole input to the sole gate. Fixing the producers is unbounded; fixing the gate's
  input contract is three fields.
- **It did not remove autonomy (superseded by ADR 087).** At the time, a measured, contained
  radius at high confidence still auto-executed, asserted by a test that ADR 087 removed along
  with auto-execution itself.

## Alternatives considered

The obvious structural fix is the general one: **make partiality a value in the type
everywhere**, via a generic `Result[T]` wrapper whose payload is unreachable without also
being handed the completeness. It is the only construct that gives real compile-time forcing
in Go, which has no `must_use`. It was rejected on two grounds.

**One: representation was never the gap.** In the defect ADR 077 addresses, `asset.EdgeSyncResult`
already carried `BulkPassFailed` *in the type*, and `graphstore` already called
`ReachComplete()` on it. The caller read a completeness member — the wrong one — and
published anyway. A wrapper would have failed identically. Converting the four existing
bespoke completeness types (`EdgeSyncResult`, `collect.Result`, `CTQueryStats`,
`BlastRadius`) into a generic one would also *lose* the domain detail the consumers need —
`Detail()`, `TruncatedTypes`, `ScopeEnumeration` — which is a downgrade dressed as rigour.

**Two: the general lint rule needs more exemptions than findings.** The natural mechanical
rule is "a function that observes an `error` must return one". It was prototyped as an AST
check and run over the highest-consequence packages in the tree (`respond`, `enrich`,
`policy`, `executor`, excluding transport, which maps errors to status codes):

| scope | functions | violations |
|---|---|---|
| respond + enrich + policy + executor, non-test, non-handler | **242** | **21** |

and most of the 21 are legitimate. `assessMustFix` returns `("", "")` and its blank IS its
unknown. `atoiOr` returns a documented default. `assessSafety` is advisory and fail-open by
design. **An AST cannot see that a zero value means "unknown"**, so the general rule needs
21 prose exemptions on one path — and a guard whose exemption list is longer than its
findings trains people to add the 22nd entry. That is decoration, so it was not shipped.
The probe was thrown away; this table is its only artefact, and it is the reason the
enforcement is narrow.

## Enforcement

> **Superseded by ADR 087 and by [ADR 006](006-embedded-opa.md)'s 2026-10-24 amendment.**
> `policy.Input` has no evidence fields today (only `ActionClass` and `ConfidenceBand`), so
> the pairing check has nothing to pair, and the gate is the Go function `policy.Decide`:
> `agent.rego` no longer exists. `TestAutoExecuteGateRequiresKnownEvidence` reads `policy.go`
> as Go source; it keeps the pairing check for any evidence field added later and refuses an
> `AllowAuto` grant anywhere but the observe case of `Decide`. The seam test is
> `TestDecide_UnmeasuredBlastRadiusReachesTheApprover`, which checks that known-ness reaches
> the approver. The current mutations are listed under the ADR 087 heading in
> `internal/guardmutation/mutations_test.go`. The rest of this section records the guards as
> first shipped, against the rego.

Two guards, three catalogued mutations (`internal/guardmutation`), one per place the defect
can be reintroduced.

`TestAutoExecuteGateRequiresKnownEvidence` (`internal/policy`) is structural, over
`policy.go` and `agent.rego` as source. Two halves:

1. **declaration** — every evidence field of `Input` has a `<Field>Known bool` companion
   carrying the json tag the rego reads. A field is exempt only by being listed in
   `actionFields` with a stated reason (`ActionClass` is the proposed action;
   `ConfidenceBand` is already four-valued *with* its own unknown, `insufficient`, which the
   rego escalates on).
2. **consumption** — every `allow_auto` rule that can grant autonomy to a state-changing
   action mentions every `_known` term. The observe rule is excluded by matching its own
   `action_class == "observe"` condition rather than by position, so reordering the rules
   cannot accidentally exempt a mutating one.

The second half is the one that matters, and it reads the rego as **text** rather than
evaluating it. An evaluation-based check can only sample points, and would pass on any input
space where the omission happens not to flip a verdict. Requiring the term to be *mentioned*
is what distinguishes this from `graph_ladybug_reach_complete` — a completeness signal that was
computed, exported, and structurally incapable of ever being false.

The respond seam test (`internal/app/respond`, then named
`TestDecide_UnmeasuredBlastRadiusNeverAutoExecutes`) was behavioural
and wired the **real** `policy.Gate`, because the thing under test is the seam and not
either side of it. Every fake in it was the most permissive available, so the only thing
between the finding and auto-execution was the radius being unmeasured.

The mutations catalogued at the time (historical; see the note above), each verified to fail its guard:

| mutation | reintroduces |
|---|---|
| `agent.rego`: drop `input.blast_radius_known` | the pairing survives and the rule stops reading it — the `reach_complete` shape |
| `respond/service.go`: `BlastRadiusKnown: blastKnown` → `true` | known-ness computed, logged, then asserted rather than threaded — the half-fix that is harder to spot than no fix |
| `asset/service.go`: restore `fetched = nil // degrade to stubs below` | verbatim the pre-fix line |

## Consequences

- **Before ADR 087, a finding whose blast radius could not be walked stopped auto-executing.**
  It was parked for a human and logged at Warn. This is a real operational cost paid in parked decisions,
  and it is the intended direction: the alternative is autonomy priced off a measurement
  that never happened.
- **Before ADR 087, a finding with no `ResourceID` also stopped auto-executing on size.**
  `blastKnown` stays false when there is nothing to walk, which is the same answer as a failed walk for the
  same reason. Stated explicitly because it is a behaviour change beyond the failure case.
- **A `ByIDs` failure now fails the blast walk** instead of degrading it. Every caller of
  `asset.BlastRadius` (enrich, respond, MCP, findingctx) sees an error where it used to see
  stub-populated success. Enrich's blast source already falls back and then errors out of
  `gather`; respond reports unmeasured. Both are fail-closed.
- **The other audited sites are unconverted, and deliberately.** A refactor touching dozens
  of call sites in one commit is unreviewable and likely to be reverted. The ranked inventory is
  the deliverable; the conversion stopped at the paths feeding auto-execution.
- **This ADR does not claim the generator is closed.** It claims the highest-consequence
  branch of it is, and that the next instance *at the gate* fails CI. `enrich.gather`
  (a source that errors, panics or times out is silently absent from the factors that
  produce `must_fix_class`), `graphstore.execCypher` (a row-decode failure served to the API
  and MCP as a complete result with `Truncated: false`), and
  `ciem.AnalyzeIAMAssets` (per-principal evaluation failures lower `scopeMax`, and with it
  severity caps, for a whole account) are the three next-worst, and they are named here so
  they are known gaps rather than invisible ones.

Cites ADR 006 (the gate this amends), 030 (the decision pipeline; with ADR 087 nothing
executes on its own, so the consequential edge is the decision webhook), 044 (the must-fix consumers), 054 (partial
collection must not license deletion — the same rule one domain over), 077 (the same
generator at the graph publish boundary, and the source of the `reach_complete` lesson).
