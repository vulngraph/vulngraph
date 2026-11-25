package govern

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/reasoncache"
)

// A fix the executor carried out resolves its decision as approved (at the
// decision's fingerprint, so a later change re-surfaces it), lands in the
// trail, and is the success sample the ledger learns from.
func TestRecordExecution_ResolvesTheDecisionAndRecordsTheRealOutcome(t *testing.T) {
	verdicts, outcomes, audit := &fakeVerdicts{}, &fakeOutcomes{}, &fakeAudit{}
	pending := fakePending{entries: []reasoncache.Entry{{FindingID: "f1", ActionClass: "remediate", Fingerprint: "fp1"}}}
	s := svc(verdicts, pending, s3Findings("f1"), outcomes, audit)

	require.NoError(t, s.RecordExecution(context.Background(), ExecutedFix{
		DecisionID: "d1", FindingID: "f1", ActionClass: "remediate", Actor: "bob@x.example",
	}))
	require.Equal(t, []string{"f1:approved:fp1"}, verdicts.upserts)
	require.Len(t, audit.events, 1)
	require.Equal(t, AuditActionExecution, audit.events[0].Action)
	require.Equal(t, "bob@x.example", audit.events[0].Actor)
	require.Len(t, outcomes.recorded, 1)
	o := outcomes.recorded[0]
	require.True(t, o.Success)
	require.Equal(t, "remediate", o.ActionClass)
	require.Equal(t, "s3_bucket", o.AssetType, "the asset type comes from the finding")
	require.Equal(t, "executor", o.DecidedBy)
	require.Equal(t, "executed:d1", o.DedupeKey, "one decision's run is one sample however often it is recorded")
}

func TestRecordExecution_UnknownAssetTypeRecordsNoOutcome(t *testing.T) {
	verdicts, outcomes := &fakeVerdicts{}, &fakeOutcomes{}
	s := svc(verdicts, fakePending{}, fakeFindings{}, outcomes, &fakeAudit{})

	require.NoError(t, s.RecordExecution(context.Background(), ExecutedFix{
		DecisionID: "d1", FindingID: "gone", ActionClass: "remediate", Actor: "bob@x.example",
	}))
	require.Equal(t, []string{"gone:approved:"}, verdicts.upserts)
	require.Empty(t, outcomes.recorded, "evidence under an empty asset type would describe nothing")
}
