package jobs

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/suppress"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

type recordingCarrier struct{ calls [][2]string }

func (r *recordingCarrier) CarryForward(_ context.Context, to, from string) (bool, error) {
	r.calls = append(r.calls, [2]string{to, from})
	return true, nil
}

func TestCarrySuppressionsFollowsSupersededChecks(t *testing.T) {
	c := &recordingCarrier{}
	found := []finding.Finding{
		{ID: dbutil.DeterministicID("aws-s3-public-read", "site"), CheckID: "aws-s3-public-read", ResourceID: "site"},
		{ID: dbutil.DeterministicID("aws-s3-public-write", "site"), CheckID: "aws-s3-public-write", ResourceID: "site"},
		{ID: "x", CheckID: "aws-s3-no-lifecycle", ResourceID: "site"},
	}
	carrySuppressions(context.Background(), c, found)
	old := dbutil.DeterministicID("aws-s3-public-bucket", "site")
	require.Equal(t, [][2]string{{found[0].ID, old}, {found[1].ID, old}}, c.calls,
		"each public read/write finding inherits the public-bucket finding's suppression on the same bucket")

	carrySuppressions(context.Background(), nil, found) // disabled: no panic
}

// The sync worker must call carrySuppressions once the findings are recorded
// and before enrichment, with the carrier the client wires in: without the
// call a check split silently drops every accepted exception, and no
// behavioural test of the worker would notice.
func TestSyncWorkerCarriesSuppressions(t *testing.T) {
	src, err := os.ReadFile("sync.go")
	require.NoError(t, err)
	s := string(src)
	recorded := strings.Index(s, "if runErr = w.findings.RecordObserved(ctx, found); runErr == nil {")
	carry := strings.Index(s, "carrySuppressions(ctx, w.suppressions, found)")
	enrich := strings.Index(s, "enqueueEnrichIfCapacity(ctx, found)")
	require.Positive(t, recorded)
	require.Greater(t, carry, recorded, "the carry follows a successful RecordObserved")
	require.Greater(t, enrich, carry, "and precedes enrichment")

	client, err := os.ReadFile("client.go")
	require.NoError(t, err)
	require.Contains(t, string(client), "suppressions: suppressionCarrier(deps.Suppress)", "the sync worker gets the suppress service")
}

func TestSuppressionCarrierKeepsNilNil(t *testing.T) {
	require.Nil(t, suppressionCarrier(nil))
	require.NotNil(t, suppressionCarrier(suppress.NewService(nil)))
}
