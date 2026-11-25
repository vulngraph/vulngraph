package apikey

import (
	"context"
	"testing"
	"time"

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

type keyRepo struct {
	recordingRepo
	deleteErr error
}

func (r *keyRepo) Create(ctx context.Context, userID, name string, scope Scope, expiresAt *time.Time) (APIKey, string, error) {
	k, plain, err := r.recordingRepo.Create(ctx, userID, name, scope, expiresAt)
	k.ID = "key-1"
	return k, plain, err
}

func (r *keyRepo) Delete(context.Context, string, string) error { return r.deleteErr }

// The rows name the key and its owner, never the plaintext key.
func TestCreateAndRevoke_AreAudited(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	repo := &keyRepo{}
	a := &fakeAudit{}
	s := NewService(repo).WithAudit(a)
	s.now = func() time.Time { return now }

	_, plain, err := s.Create(context.Background(), "u-1", "ci", ScopeAdmin, nil)
	require.NoError(t, err)
	require.NoError(t, s.Delete(context.Background(), "key-1", "u-1"))

	require.Equal(t, []auditRow{
		{AuditActionCreate, AuditTargetAPIKey, "key-1", map[string]any{
			"owner_user_id": "u-1", "name": "ci", "scope": "admin", "expires_at": "2026-12-30T00:00:00Z",
		}},
		{AuditActionRevoke, AuditTargetAPIKey, "key-1", map[string]any{"owner_user_id": "u-1"}},
	}, a.rows)
	for _, r := range a.rows {
		for _, v := range r.details {
			require.NotEqual(t, plain, v)
		}
	}
}

func TestCreateAndRevoke_RefusedWritesNoRow(t *testing.T) {
	a := &fakeAudit{}
	s := NewService(&keyRepo{deleteErr: ErrNotFound}).WithAudit(a)
	_, _, err := s.Create(context.Background(), "u-1", "", ScopeRead, nil)
	require.ErrorIs(t, err, ErrNameRequired)
	require.ErrorIs(t, s.Delete(context.Background(), "nope", "u-1"), ErrNotFound)
	require.Empty(t, a.rows)
}
