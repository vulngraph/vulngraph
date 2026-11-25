package connector

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

type fakeAudit struct{ rows []auditRow }

func (f *fakeAudit) Record(_ context.Context, action, targetType, targetID string, details map[string]any) {
	f.rows = append(f.rows, auditRow{action, targetType, targetID, details})
}

func newAuditedService(t *testing.T) (*Service, *fakeAudit) {
	t.Helper()
	svc, _ := newTestService(t)
	a := &fakeAudit{}
	return svc.WithAudit(a), a
}

// The create row names the config keys, never a credential value.
func TestCreate_IsAuditedWithoutConfigValues(t *testing.T) {
	svc, a := newAuditedService(t)
	cfg := map[string]string{"aws_access_key_id": "AKIAEXAMPLEKEYID", "aws_secret_access_key": "not-a-real-secret", "region": "eu-west-1"}
	c, err := svc.Create(context.Background(), TypeAWS, "prod", cfg, "cloudtrail")
	require.NoError(t, err)

	require.Equal(t, []auditRow{{AuditActionCreate, AuditTargetConnector, c.ID, map[string]any{
		"type": "aws", "name": "prod", "event_source": "cloudtrail", "mode": "read_only",
		"config_keys": []string{"aws_access_key_id", "aws_secret_access_key", "region"},
	}}}, a.rows)
}

func TestCreate_RefusedWritesNoRow(t *testing.T) {
	svc, a := newAuditedService(t)
	_, err := svc.Create(context.Background(), TypeAWS, "", awsConfig, "")
	require.ErrorIs(t, err, ErrMissingName)
	require.Empty(t, a.rows)
}

// Every mode change is a row with the mode it replaced, in both directions.
func TestSetMode_IsAuditedWithBeforeAndAfter(t *testing.T) {
	svc, a := newAuditedService(t)
	ctx := context.Background()
	c, err := svc.Create(ctx, TypeAWS, "prod", awsConfig, "")
	require.NoError(t, err)
	a.rows = nil

	require.NoError(t, svc.SetMode(ctx, c.ID, ModeReadWrite))
	require.NoError(t, svc.SetMode(ctx, c.ID, ModeReadOnly))
	require.Equal(t, []auditRow{
		{AuditActionModeChange, AuditTargetConnector, c.ID, map[string]any{"before": "read_only", "after": "read_write"}},
		{AuditActionModeChange, AuditTargetConnector, c.ID, map[string]any{"before": "read_write", "after": "read_only"}},
	}, a.rows)

	require.ErrorIs(t, svc.SetMode(ctx, "missing", ModeReadWrite), ErrNotFound)
	require.Len(t, a.rows, 2, "a change that did not happen writes no row")
}

func TestDelete_IsAudited(t *testing.T) {
	svc, a := newAuditedService(t)
	ctx := context.Background()
	c, err := svc.Create(ctx, TypeAWS, "prod", awsConfig, "")
	require.NoError(t, err)
	a.rows = nil

	require.NoError(t, svc.Delete(ctx, c.ID))
	require.Equal(t, []auditRow{{AuditActionDelete, AuditTargetConnector, c.ID, map[string]any{
		"type": "aws", "name": "prod", "mode": "read_only", "children_disabled": false,
	}}}, a.rows)

	require.ErrorIs(t, svc.Delete(ctx, c.ID), ErrNotFound)
	require.Len(t, a.rows, 1)
}

func TestPurgeAndDelete_IsAuditedWithWhatItRemoved(t *testing.T) {
	svc, a := newAuditedService(t)
	ctx := context.Background()
	c, err := svc.Create(ctx, TypeAWS, "aws-123456789012", map[string]string{
		"role_arn": "arn:aws:iam::123456789012:role/x", "region": "eu-west-1",
	}, "")
	require.NoError(t, err)
	a.rows = nil
	svc.WithPurge(&fakeAssetPurger{idsByAccount: map[string][]string{"aws/123456789012": {"a1", "a2"}}}, &fakeFindingResolver{})

	_, err = svc.PurgeAndDelete(ctx, c.ID)
	require.NoError(t, err)
	require.Equal(t, []auditRow{{AuditActionPurge, AuditTargetConnector, c.ID, map[string]any{
		"type": "aws", "name": "aws-123456789012", "accounts": []string{"aws:123456789012"},
		"assets_deleted": 2, "findings_resolved": 2, "edges_deleted": 2,
	}}}, a.rows)
}

// A purge that stops part way has already resolved findings: it is a row
// too, naming what it removed before it stopped.
func TestPurgeAndDelete_PartialFailureIsAudited(t *testing.T) {
	svc, a := newAuditedService(t)
	ctx := context.Background()
	c, err := svc.Create(ctx, TypeAWS, "aws-999", map[string]string{
		"role_arn": "arn:aws:iam::999:role/x", "region": "eu-west-1",
	}, "")
	require.NoError(t, err)
	a.rows = nil
	svc.WithPurge(&fakeAssetPurger{
		idsByAccount:  map[string][]string{"aws/999": {"a1"}},
		edgesPurgeErr: errors.New("boom"),
	}, &fakeFindingResolver{})

	_, err = svc.PurgeAndDelete(ctx, c.ID)
	require.ErrorContains(t, err, "PurgeAndDelete: purge edges: boom")
	require.Len(t, a.rows, 1)
	require.Equal(t, AuditActionPurgeFailed, a.rows[0].action)
	require.Equal(t, 1, a.rows[0].details["findings_resolved"])
	require.Equal(t, 0, a.rows[0].details["assets_deleted"])
	require.Equal(t, "purge edges: boom", a.rows[0].details["error"])
}
