package jobs

import (
	"context"
	"fmt"
	"testing"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type batchEnrichFake struct {
	calls      int
	sizes      []int
	ids        []string
	priorities []int
}

func (f *batchEnrichFake) InsertMany(_ context.Context, p []river.InsertManyParams) ([]*rivertype.JobInsertResult, error) {
	f.calls++
	f.sizes = append(f.sizes, len(p))
	if f.calls == 2 {
		return nil, context.DeadlineExceeded
	}
	for _, job := range p {
		f.ids = append(f.ids, job.Args.(EnrichArgs).FindingID)
		f.priorities = append(f.priorities, job.InsertOpts.Priority)
	}
	return nil, nil
}
func TestEnrichBulkEnqueueBoundsCallsAndContinuesAfterFailedBatch(t *testing.T) {
	var findings []finding.Finding
	for i := range 1201 {
		findings = append(findings, finding.Finding{ID: fmt.Sprint(i)})
	}
	fake := &batchEnrichFake{}
	insertEnrichBatches(context.Background(), fake, findings, enrichSweepPriority)
	require.Equal(t, []int{500, 500, 201}, fake.sizes)
	require.Len(t, fake.ids, 701)
	require.Equal(t, "1200", fake.ids[len(fake.ids)-1], "a failed middle batch must not lose later batches")
	for _, p := range fake.priorities {
		require.Equal(t, enrichSweepPriority, p)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	insertEnrichBatches(ctx, fake, findings, river.PriorityDefault)
	require.Equal(t, 3, fake.calls)
}
