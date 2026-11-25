package jobs

import (
	"context"
	"errors"
	"testing"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/respond"
)

type fakeDecider struct {
	decision respond.Decision
	err      error
	got      finding.Finding
}

func (f *fakeDecider) Decide(_ context.Context, fnd finding.Finding) (respond.Decision, error) {
	f.got = fnd
	return f.decision, f.err
}

func TestRespondWorker_Decides(t *testing.T) {
	d := &fakeDecider{decision: respond.Decision{FindingID: "f1", Outcome: respond.OutcomeParked}}
	w := &RespondWorker{respond: d}

	err := w.Work(context.Background(), &river.Job[DecideArgs]{Args: DecideArgs{Finding: finding.Finding{ID: "f1"}}})
	require.NoError(t, err)
	require.Equal(t, "f1", d.got.ID, "the job's finding is passed to Decide")
}

func TestRespondWorker_DecideError(t *testing.T) {
	w := &RespondWorker{respond: &fakeDecider{err: errors.New("llm down")}}
	err := w.Work(context.Background(), &river.Job[DecideArgs]{Args: DecideArgs{Finding: finding.Finding{ID: "f1"}}})
	require.ErrorContains(t, err, "Work")
}
