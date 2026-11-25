package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type auditRow struct {
	action, targetType, targetID string
	details                      map[string]any
}

type fakeAuditRecorder struct{ rows []auditRow }

func (f *fakeAuditRecorder) Record(_ context.Context, action, targetType, targetID string, details map[string]any) {
	f.rows = append(f.rows, auditRow{action: action, targetType: targetType, targetID: targetID, details: details})
}

// namedProfileRepo returns a fully described profile, so the audit row's
// details can be checked field by field.
type namedProfileRepo struct {
	stubProfileRepo
	getErr error
}

func (n *namedProfileRepo) GetProfile(_ context.Context, id string) (ScanProfile, error) {
	if n.getErr != nil {
		return ScanProfile{}, n.getErr
	}
	return ScanProfile{
		ID: id, Name: "edge", ScannerType: "nuclei", TemplateStrategy: StrategyTags,
		TargetQuery: "MATCH (a:Asset) RETURN a LIMIT 500",
	}, nil
}

func TestStartScan_RecordsTheStart(t *testing.T) {
	audit := &fakeAuditRecorder{}
	svc := NewService(&fakeRepo{}, nil, nil, nil, nil).WithAudit(audit)
	trig := &fakeTriggerer{}

	require.NoError(t, svc.StartScan(context.Background(), trig))

	require.True(t, trig.called)
	require.Equal(t, []auditRow{{
		action: AuditActionStart, targetType: AuditTargetScan, targetID: "",
		details: map[string]any{"scope": "internet_facing"},
	}}, audit.rows)
}

func TestStartScan_FailedEnqueueWritesNoRow(t *testing.T) {
	audit := &fakeAuditRecorder{}
	svc := NewService(&fakeRepo{}, nil, nil, nil, nil).WithAudit(audit)
	boom := errors.New("river down")

	err := svc.StartScan(context.Background(), &fakeTriggerer{err: boom})

	require.ErrorIs(t, err, boom)
	require.Empty(t, audit.rows, "a scan that was never enqueued must not be recorded as started")
}

func TestStartProfileScan_RecordsTheStart(t *testing.T) {
	audit := &fakeAuditRecorder{}
	repo := &namedProfileRepo{}
	svc := NewProfileService(repo, nil, nil, nil, &stubEnqueuer{}).WithAudit(audit)

	runID, err := svc.StartProfileScan(context.Background(), "p-1")

	require.NoError(t, err)
	require.Equal(t, "run-1", runID)
	require.Equal(t, []auditRow{{
		action: AuditActionProfileStart, targetType: AuditTargetScanProfile, targetID: "p-1",
		details: map[string]any{
			"run_id": "run-1", "name": "edge", "scanner_type": "nuclei",
			"template_strategy": string(StrategyTags), "target_query": "MATCH (a:Asset) RETURN a LIMIT 500",
		},
	}}, audit.rows)
}

// The schedule runner calls TriggerProfileScan with no person behind it, so
// it writes no row even on a service wired with audit.
func TestTriggerProfileScan_ScheduledRunWritesNoRow(t *testing.T) {
	audit := &fakeAuditRecorder{}
	svc := NewProfileService(&namedProfileRepo{}, nil, nil, nil, &stubEnqueuer{}).WithAudit(audit)

	_, err := svc.TriggerProfileScan(context.Background(), "p-1")

	require.NoError(t, err)
	require.Empty(t, audit.rows)
}

func TestStartProfileScan_RefusedTriggerWritesNoRow(t *testing.T) {
	boom := errors.New("river down")
	cases := []struct {
		name    string
		repo    *namedProfileRepo
		enq     ProfileJobEnqueuer
		wantErr error
	}{
		{name: "no enqueuer", repo: &namedProfileRepo{}, enq: nil, wantErr: ErrNoEnqueuer},
		{name: "unknown profile", repo: &namedProfileRepo{getErr: ErrProfileNotFound}, enq: &stubEnqueuer{}, wantErr: ErrProfileNotFound},
		{name: "enqueue fails", repo: &namedProfileRepo{}, enq: &stubEnqueuer{err: boom}, wantErr: boom},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			audit := &fakeAuditRecorder{}
			svc := NewProfileService(tc.repo, nil, nil, nil, tc.enq).WithAudit(audit)

			_, err := svc.StartProfileScan(context.Background(), "p-1")

			require.ErrorIs(t, err, tc.wantErr)
			require.Empty(t, audit.rows)
		})
	}
}
