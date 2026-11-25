package jobs

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/checks"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

type fakeRecorder struct {
	batches [][]finding.Finding
	err     error
}

func (f *fakeRecorder) RecordObserved(_ context.Context, fs []finding.Finding) error {
	f.batches = append(f.batches, append([]finding.Finding(nil), fs...))
	return f.err
}

func (f *fakeRecorder) all() []finding.Finding {
	var out []finding.Finding
	for _, b := range f.batches {
		out = append(out, b...)
	}
	return out
}

func ec2WithOS(id, eco string) asset.Asset {
	return asset.Asset{ID: id, Name: id, Type: "ec2_instance", Provider: asset.ProviderAWS,
		Metadata: map[string]string{"package_ecosystem": eco, "state": "running"}}
}

// A stable fleet on an end-of-life release gets its finding from the daily
// re-check even though no asset changed, assets the full registry already ran
// on are not evaluated twice, and the reconcile reads only the time-dependent
// checks' findings: a public-IP finding on the same instance is NOT closed as
// fixed just because the public-IP check did not run.
func TestRecheckTimeDependent(t *testing.T) {
	reg := checks.Default()
	td := reg.TimeDependent()
	assets := []asset.Asset{
		ec2WithOS("i-eol", "CentOS:7"),
		ec2WithOS("i-supported", "Amazon Linux:2023"),
		ec2WithOS("i-changed", "CentOS:7"),
		{ID: "bucket", Type: "s3_bucket", Provider: asset.ProviderAWS},
	}
	stale := finding.Finding{ID: dbutil.DeterministicID("aws-ec2-os-end-of-life", "i-supported"), Source: "cspm",
		CheckID: "aws-ec2-os-end-of-life", ResourceID: "i-supported"}
	other := finding.Finding{ID: "pub", Source: "cspm", CheckID: "aws-ec2-public-ip", ResourceID: "i-supported"}
	life := &fakeLifecycler{stored: []finding.Finding{stale, other}}
	rec := &fakeRecorder{}

	n, err := recheckTimeDependent(context.Background(), rec, life, td, assets, map[string]bool{"i-changed": true}, false, time.Now())
	require.NoError(t, err)
	require.Equal(t, 1, n)
	got := rec.all()
	require.Len(t, got, 1)
	require.Equal(t, "aws-ec2-os-end-of-life", got[0].CheckID)
	require.Equal(t, "i-eol", got[0].ResourceID)

	require.Len(t, life.calls, 1)
	require.ElementsMatch(t, []string{"i-eol", "i-supported"}, life.calls[0], "only assets a time-dependent check applies to, minus the already-checked")
	require.Equal(t, []finding.Finding{stale}, life.resolved, "only the time-dependent check's silence is read; the public-IP finding stays open")
	require.Equal(t, []finding.ResolutionReason{finding.ReasonFixed}, life.reasons)
}

// A failed write is an error, so the caller leaves the day un-advanced and the
// next sweep retries; nothing is reconciled on the back of an unrecorded run.
func TestRecheckTimeDependent_RecordErrorIsReturned(t *testing.T) {
	boom := errors.New("ch down")
	life := &fakeLifecycler{}
	_, err := recheckTimeDependent(context.Background(), &fakeRecorder{err: boom}, life, checks.Default().TimeDependent(),
		[]asset.Asset{ec2WithOS("i-eol", "CentOS:7")}, nil, false, time.Now())
	require.ErrorIs(t, err, boom)
	require.Empty(t, life.calls)
}

// Findings are written in bounded pages, not one insert per estate.
func TestRecheckTimeDependent_RecordsInPages(t *testing.T) {
	assets := make([]asset.Asset, recheckRecordBatch+5)
	for i := range assets {
		assets[i] = ec2WithOS(fmt.Sprintf("i-%d", i), "CentOS:7")
	}
	rec := &fakeRecorder{}
	n, err := recheckTimeDependent(context.Background(), rec, &fakeLifecycler{}, checks.Default().TimeDependent(), assets, nil, false, time.Now())
	require.NoError(t, err)
	require.Equal(t, len(assets), n)
	require.Len(t, rec.batches, 2)
	require.Len(t, rec.batches[0], recheckRecordBatch)
}
