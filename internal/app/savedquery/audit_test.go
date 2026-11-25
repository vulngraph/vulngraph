package savedquery

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

// getRepo is fakeRepo whose Get returns a fixed stored query.
type getRepo struct {
	fakeRepo
	stored SavedQuery
}

func (g *getRepo) Get(context.Context, string) (SavedQuery, error) { return g.stored, nil }

func TestSavedQueryChanges_AreAudited(t *testing.T) {
	repo := &getRepo{stored: SavedQuery{ID: "q1", Name: "old", Cypher: "MATCH (n) RETURN n", AlertOnChange: true}}
	a := &fakeAudit{}
	svc := NewService(repo).WithAudit(a)
	ctx := context.Background()

	// The fake repo returns its input, so the id stands in for the one the database assigns.
	_, err := svc.Create(ctx, SavedQuery{ID: "q1", Name: "new", Cypher: "MATCH (a:Asset) RETURN a"})
	require.NoError(t, err)
	_, err = svc.Update(ctx, SavedQuery{ID: "q1", Name: "renamed", Cypher: "MATCH (a:Asset) RETURN a", AlertOnChange: false})
	require.NoError(t, err)
	require.NoError(t, svc.Delete(ctx, "q1"))

	require.Len(t, a.rows, 3)
	require.Equal(t, AuditActionCreate, a.rows[0].action)
	require.Equal(t, AuditTargetSavedQuery, a.rows[0].targetType)
	require.Equal(t, "q1", a.rows[0].targetID)

	require.Equal(t, AuditActionUpdate, a.rows[1].action)
	before := a.rows[1].details["before"].(map[string]any)
	after := a.rows[1].details["after"].(map[string]any)
	require.Equal(t, true, before["alert_on_change"], "turning a detection's alert off is visible")
	require.Equal(t, false, after["alert_on_change"])
	require.Equal(t, "renamed", after["name"])

	require.Equal(t, AuditActionDelete, a.rows[2].action)
	require.Equal(t, "MATCH (n) RETURN n", a.rows[2].details["cypher"], "the deleted definition is kept in the row")
}

func TestSavedQueryRejectedChange_IsNotAudited(t *testing.T) {
	a := &fakeAudit{}
	svc := NewService(&fakeRepo{}).WithAudit(a)
	_, err := svc.Create(context.Background(), SavedQuery{Name: "x", Cypher: "MATCH (n) DELETE n"})
	require.ErrorIs(t, err, ErrWriteQuery)
	require.Empty(t, a.rows)
}
