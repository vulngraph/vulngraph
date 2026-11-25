package policy

import (
	"context"
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

func TestUpdate_IsAuditedWithBeforeAndAfter(t *testing.T) {
	store := &fakeStore{p: Policy{ID: "default", SuggestThreshold: 60}}
	a := &fakeAudit{}
	svc := NewService(store).WithAudit(a)

	require.NoError(t, svc.Update(context.Background(), Policy{SuggestThreshold: 40, ActionRules: map[string]ActionMode{"destroy": ModeDisabled}}))
	require.Equal(t, []auditRow{{AuditActionUpdate, AuditTargetPolicy, "default", map[string]any{
		"before": map[string]any{"suggest_threshold": 60, "action_rules": map[string]ActionMode{}},
		"after":  map[string]any{"suggest_threshold": 40, "action_rules": map[string]ActionMode{"destroy": ModeDisabled}},
	}}}, a.rows)
}

func TestUpdate_InvalidPolicyWritesNoRow(t *testing.T) {
	a := &fakeAudit{}
	svc := NewService(&fakeStore{}).WithAudit(a)
	require.ErrorIs(t, svc.Update(context.Background(), Policy{SuggestThreshold: 101}), ErrBadThreshold)
	require.Empty(t, a.rows)
}
