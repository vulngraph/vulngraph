package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/respond"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// DecideArgs runs the reason→gate→decide pipeline for one finding. The finding
// is carried in the job so the worker needs no separate fetch.
//
// FindingID is the uniqueness key. Hashing the whole Finding made the key
// change with every score or timestamp refresh, so the same finding could be
// decided twice concurrently. MarshalJSON fills it from Finding.ID, so callers
// need not set it.
type DecideArgs struct {
	FindingID string          `json:"finding_id" river:"unique"`
	Finding   finding.Finding `json:"finding"`
}

func (DecideArgs) Kind() string { return "decide" }

// MarshalJSON defaults FindingID to Finding.ID. River builds the unique key
// from the encoded args, so an unset FindingID would otherwise collapse every
// decide onto one key.
func (a DecideArgs) MarshalJSON() ([]byte, error) {
	type plain DecideArgs
	if a.FindingID == "" {
		a.FindingID = a.Finding.ID
	}
	b, err := json.Marshal(plain(a))
	if err != nil {
		return nil, fmt.Errorf("DecideArgs.MarshalJSON: %w", err)
	}
	return b, nil
}

// InsertOpts keeps decides on the respond queue and unique per finding while
// queued/running, so a finding is never reasoned about twice concurrently.
func (DecideArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:      queueRespond,
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: uniqueStates},
	}
}

// decider is the slice of the respond service the worker needs (narrow consumer
// interface so Work is unit-testable; *respond.Service satisfies it).
type decider interface {
	Decide(ctx context.Context, f finding.Finding) (respond.Decision, error)
}

// RespondWorker decides on a finding via the respond service.
type RespondWorker struct {
	river.WorkerDefaults[DecideArgs]
	respond decider
}

// Timeout overrides River's 1-minute default. Decide chains the Ladybug BFS + a
// ClickHouse ContextPack + an LLM call, which on a cold graph or CH contention
// runs well past a minute; the default caused spurious mid-decision timeouts.
func (RespondWorker) Timeout(_ *river.Job[DecideArgs]) time.Duration {
	return 10 * time.Minute
}

func (w *RespondWorker) Work(ctx context.Context, job *river.Job[DecideArgs]) error {
	d, err := w.respond.Decide(ctx, job.Args.Finding)
	if err != nil {
		return fmt.Errorf("Work: %w", err)
	}
	log.FromContext(ctx).Info().
		Str("finding_id", d.FindingID).Str("outcome", string(d.Outcome)).
		Str("action_class", string(d.Plan.ActionClass)).Msg("decision made")
	return nil
}
