package finding

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
)

type recordedAudit struct {
	action, targetType, targetID string
	details                      map[string]any
}

type fakeAudit struct{ rows []recordedAudit }

func (f *fakeAudit) Record(_ context.Context, action, targetType, targetID string, details map[string]any) {
	f.rows = append(f.rows, recordedAudit{action, targetType, targetID, details})
}

// urgentIfCritical stands in for enrich.AgentRefusal, which this package cannot import.
func urgentIfCritical(f Finding) string {
	if f.Severity == SeverityCritical {
		return "critical severity"
	}
	return ""
}

func apiKeyCtx() context.Context {
	ctx := auth.ContextWithUser(context.Background(), auth.User{ID: "u1", Email: "admin@b.example", Role: auth.RoleAdmin})
	return auth.ContextWithAPIKey(ctx, auth.APIKeyRecord{ID: "k1", UserID: "u1", Scope: "admin"})
}

func TestResolveManually_IsAudited(t *testing.T) {
	repo := &fakeRepo{stored: []Finding{{ID: "f1", Severity: SeverityHigh, ScoreBand: "pipeline", DetectedAt: time.Now()}}}
	audit := &fakeAudit{}
	svc := NewService(repo).WithAudit(audit)

	f, err := svc.ResolveManually(context.Background(), "f1", "instance terminated", "admin@b.example")
	require.NoError(t, err)
	require.True(t, f.Resolved())

	require.Len(t, audit.rows, 1)
	row := audit.rows[0]
	require.Equal(t, AuditActionResolve, row.action)
	require.Equal(t, AuditTargetFinding, row.targetType)
	require.Equal(t, "f1", row.targetID)
	require.Equal(t, "instance terminated", row.details["reason"])
	require.Equal(t, "high", row.details["severity"])
}

func TestResolveManually_APIKey(t *testing.T) {
	cases := []struct {
		name     string
		guard    func(Finding) string
		severity Severity
		wantErr  bool
	}{
		{"low-urgency finding passes the guard", urgentIfCritical, SeverityMedium, false},
		{"critical finding is refused", urgentIfCritical, SeverityCritical, true},
		{"no guard wired refuses", nil, SeverityLow, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeRepo{stored: []Finding{{ID: "f1", Severity: tc.severity, DetectedAt: time.Now()}}}
			audit := &fakeAudit{}
			svc := NewService(repo).WithAudit(audit)
			if tc.guard != nil {
				svc = svc.WithAgentGuard(tc.guard)
			}
			_, err := svc.ResolveManually(apiKeyCtx(), "f1", "noise", "admin@b.example")
			if !tc.wantErr {
				require.NoError(t, err)
				require.Len(t, repo.stored, 2)
				return
			}
			require.ErrorIs(t, err, ErrNeedsPerson)
			require.Len(t, repo.stored, 1, "a refused resolve writes nothing")
			require.Len(t, audit.rows, 1)
			require.Equal(t, AuditActionResolveRefused, audit.rows[0].action)
		})
	}
}

func TestResolveHandler_APIKey_403(t *testing.T) {
	repo := &fakeRepo{stored: []Finding{{ID: "f1", Severity: SeverityCritical, DetectedAt: time.Now()}}}
	h := NewHandler(NewService(repo).WithAgentGuard(urgentIfCritical), nil)

	req := httptest.NewRequest(http.MethodPost, "/api/findings/f1/resolve", strings.NewReader(`{"reason":"noise"}`)).
		WithContext(apiKeyCtx())
	req.SetPathValue("id", "f1")
	rec := httptest.NewRecorder()
	h.Resolve(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "critical severity")
	require.Len(t, repo.stored, 1)
}
