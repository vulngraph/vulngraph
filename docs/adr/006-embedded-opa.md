# ADR 006 — OPA embedded as a Go library

**Status:** superseded · amended 2026-07-18, 2026-10-23 and 2026-10-24. [ADR 087](087-no-autonomous-remediation.md) limits the gate's autonomy to observe only, and the 2026-10-24 amendment replaces the evaluator with a plain Go function (`policy.Decide`), so OPA is no longer a dependency. The decision this ADR made, an in-process gate with no policy service, still holds.

## Context

Action gating (which action classes may run autonomously, which need human approval, JIT
grant validity) needs a policy engine. OPA is commonly deployed as a separate service,
which adds a network hop and another process the gate's availability depends on.

## Decision

Embed OPA as a Go library (`open-policy-agent/opa/v1/rego`) with the policy compiled in via
`go:embed` from `internal/policy/agent.rego`. Every LLM proposal in `respond` is classified by
the gate in-process — `allow_auto` (the read-only `observe` class only), `needs_approval` or
`escalate` — with no network hop and no policy service to keep alive. The gate decides how a
proposal reaches a person. It does not gate execution: the executor never consults OPA, and an
execution is gated by the executor's own checks (admin role, a second admin's grant where
required, a `read_write` connector, the intent row; ADR 015 and ADR 087).

## Consequences

- Policy changes ship as commits (reviewed, tested) rather than runtime config.
- Policy evaluation cannot be a point of distributed failure: if the binary runs,
  the proposal gate runs.

## Amendment (2026-07-18) — registry/policy sync not yet enforced

The intended pre-commit sync check between the Go registry and the rego set has not been
added (`lefthook.yml` runs only `lint` + `test`). The destructive set is defined
independently in Go (`respond/cove.go`, `respond/impact.go`) and rego
(`internal/policy/agent.rego`), so the two can drift. Adding the check, or deriving one set
from the other, is open follow-up. The embed path was also corrected to the single
`internal/policy/agent.rego` file rather than a top-level `policy/*.rego` glob.

## Amendment (2026-10-23) — the sync check is no longer needed

ADR 087 removed `destructive_actions` from the rego, so the destructive set is defined only in
Go and there is no second set to keep in sync. The follow-up in the 2026-07-18 amendment is
closed without a sync check.

## Amendment (2026-10-23) — what OPA still buys

After ADR 087 the embedded policy is small: one `allow_auto` rule that is a single equality
(`action_class == "observe"`), two `escalate` rules on the confidence band, and a
`needs_approval` fallback, over two string inputs. A Go `switch` would express it in a few
lines. There is no operator-authored policy: the rego is compiled into the binary and nothing
loads a policy at runtime.

OPA is kept, for now, because the guards are written against the rego (`internal/policy`
tests, `TestAutoExecuteGateRequiresKnownEvidence`, the autonomy seam test in `respond` and the
guard-mutation row that mutates `agent.rego`), and swapping the evaluator would mean
re-pinning every one of them for no change in behaviour. The cost is real:
`open-policy-agent/opa` is a large dependency, and `internal/policy` is its only importer.
Replacing the gate with a Go switch, and the rego-specific guards with equivalent Go tests, is
open follow-up.

## Amendment (2026-10-24) — the gate is Go; OPA is removed

The follow-up above is done. `policy.Decide` (`internal/policy/policy.go`) is a `switch` over
the same two inputs with the same verdicts: `AllowAuto` for the exact `observe` class,
`Escalate` for any other class at `low` or `insufficient` confidence, `NeedsApproval` for
everything else, including unknown classes and bands. `policy.Gate` adapts it to
`respond.Gate`. `agent.rego` is deleted and `open-policy-agent/opa` is no longer in `go.mod`.

The guards moved with it. `TestAutoExecuteGateRequiresKnownEvidence` reads `policy.go` as Go
source: every evidence field of `Input` still needs a `<Field>Known bool` companion, and every
`AllowAuto: true` must be returned from a case of `Decide` whose whole condition is
`in.ActionClass == classObserve`. `TestGate_NoStateChangingInputIsAutonomous` and
`TestGate_ExactlyOneOutcome` sweep the input space through `Decide`, `TestDecide` is the
table of verdicts, the autonomy seam test in `respond` wires the real `policy.Gate`, and the
guard-mutation row that used to add a rego rule now adds a Go case.

What this ADR decided, an in-process gate with no policy service, still holds; the rego
evaluator is what is gone.
