package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
)

// bypassCtx is the context a request carries after BYPASS_AUTH's RequireAuth:
// the synthetic admin, as every request under that flag sees it.
func bypassCtx(t *testing.T) context.Context {
	t.Helper()
	var ctx context.Context
	auth.NewHandlerBypass().RequireAuth(func(_ http.ResponseWriter, r *http.Request) {
		ctx = r.Context()
	})(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/execute", nil))
	require.NotNil(t, ctx)
	u, ok := auth.UserFromContext(ctx)
	require.True(t, ok)
	require.NotEmpty(t, u.ID, "the synthetic admin has an id, so the no-principal check alone would pass it")
	return ctx
}

// Under BYPASS_AUTH every request is the same synthetic admin, so a change
// could be attributed to nobody. A non-destructive action needs no grant, so
// without this refusal anyone who reached serve could run it.
func TestExecute_RefusesUnderBypassAuth(t *testing.T) {
	audit := &fakeAuditor{}
	svc := NewService(awsRW()).WithAudit(audit)
	ctx := bypassCtx(t)

	_, err := svc.Execute(ctx, ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionS3BlockPublic, Params: map[string]string{ParamBucketName: "logs-bucket"},
	})
	require.ErrorIs(t, err, ErrBypassAuth)
	require.NotErrorIs(t, err, ErrNoExecutionRole, "the cloud call was never reached")
	for _, e := range audit.events {
		require.NotEqual(t, AuditActionExecuteIntent, e.Action, "no intent row: nothing was about to run")
	}

	res, err := svc.Execute(ctx, ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionS3BlockPublic, Params: map[string]string{ParamBucketName: "logs-bucket"}, DryRun: true,
	})
	require.NoError(t, err, "a dry run changes nothing and stays available")
	require.True(t, res.DryRun)
}

func TestRunDecisionAndStalledRelease_RefuseUnderBypassAuth(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	ctx := bypassCtx(t)

	_, _, err := f.svc.RunDecision(ctx, "d-s3", nil, "", decisionRequest)
	require.ErrorIs(t, err, ErrBypassAuth)
	require.Empty(t, f.runs.rows, "no claim without an identified person")

	f.runs.rows["d-s3"] = DecisionRun{DecisionID: "d-s3", Status: RunRunning, UpdatedAt: time.Now().Add(-time.Hour)}
	_, err = f.svc.MarkStalledRunFailed(ctx, "d-s3", true, "")
	require.ErrorIs(t, err, ErrBypassAuth)
	require.Equal(t, RunRunning, f.runs.rows["d-s3"].Status, "the run is not released")
}

func TestRequirePerson(t *testing.T) {
	_, err := requirePerson(context.Background())
	require.ErrorIs(t, err, ErrNoPrincipal)

	_, err = requirePerson(bypassCtx(t))
	require.ErrorIs(t, err, ErrBypassAuth)

	p, err := requirePerson(auth.ContextWithUser(context.Background(), auth.User{ID: "u-1", Email: "a@example.com"}))
	require.NoError(t, err)
	require.Equal(t, "u-1", p.ID)
}
