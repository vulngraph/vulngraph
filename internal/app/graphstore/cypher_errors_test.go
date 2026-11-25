package graphstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/pkg/errs"
)

func TestClassifyEngineError(t *testing.T) {
	cases := []struct {
		msg     string
		invalid bool
		timeout bool
	}{
		{msg: "Parser exception: Invalid input <MATCH (n:Asset RETURN>: expected rule oC_SingleQuery", invalid: true},
		{msg: "Binder exception: Table Nope does not exist.", invalid: true},
		{msg: "Binder exception: Variable m is not in scope.", invalid: true},
		{msg: "Catalog exception: function FOO does not exist.", invalid: true},
		{msg: "Interrupted.", timeout: true},
		{msg: "Runtime exception: Divide by zero."},
		{msg: "Buffer manager exception: Unable to allocate memory!"},
	}
	for _, c := range cases {
		err := classifyEngineError(errors.New(c.msg))
		require.Equal(t, c.invalid, errors.Is(err, explore.ErrInvalidQuery), c.msg)
		require.Equal(t, c.timeout, errors.Is(err, explore.ErrQueryTimeout), c.msg)
		var rej *explore.QueryRejection
		if errors.As(err, &rej) {
			require.Equal(t, c.msg, rej.Reason)
		}
	}
}

// Pins the prefixes against the linked liblbug: if an engine upgrade rewords
// its errors, bad Cypher would silently go back to being a 500.
func TestExecCypher_ClassifiesEngineErrors(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()
	assets, edges, sigs := digestFixture()
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, stubSignals{sigs}))

	for _, q := range []string{
		`MATCH (n:Asset RETURN n`,
		`MATCH (n:NoSuchLabel) RETURN n`,
		`MATCH (n:Asset) RETURN m`,
		`MATCH (n:Asset) RETURN no_such_function(n)`,
	} {
		_, err := svc.RunCypher(ctx, q, 10, 10)
		var rej *explore.QueryRejection
		require.ErrorAs(t, err, &rej, q)
		require.NotEmpty(t, rej.Reason)
	}

	_, err = svc.RunCypher(ctx, `MATCH (n) DETACH DELETE n`, 10, 10)
	require.ErrorIs(t, err, ErrReadOnly)
	require.ErrorIs(t, err, explore.ErrInvalidQuery, "the read-only guard is a rejection too")

	_, err = svc.RunCypher(ctx, `MATCH (n:Asset) RETURN n`, 10, 10)
	require.NoError(t, err)
}

// An already-expired deadline is a timeout, not an engine failure.
func TestRunCypher_DeadlineIsATimeout(t *testing.T) {
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()
	assets, edges, sigs := digestFixture()
	require.NoError(t, svc.SyncFromSources(context.Background(), 0, stubAssets{assets}, stubEdges{edges}, stubSignals{sigs}))

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	_, err = svc.RunCypher(ctx, `MATCH (n:Asset) RETURN n`, 10, 10)
	require.ErrorIs(t, err, explore.ErrQueryTimeout)
}

func TestWriteQueryError_StatusAndCode(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
		detail string
	}{
		{fmt.Errorf("execCypher: %w", &explore.QueryRejection{Reason: "Binder exception: x"}), http.StatusBadRequest, "INVALID_INPUT", "Binder exception: x"},
		{fmt.Errorf("execCypher: %w: Interrupted.", explore.ErrQueryTimeout), http.StatusGatewayTimeout, "TIMEOUT", "graph query timed out"},
		{errors.New("Runtime exception: boom"), http.StatusInternalServerError, "INTERNAL", "Runtime exception: boom"},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		writeQueryError(rec, httptest.NewRequest(http.MethodPost, "/internal/graph/cypher", nil), c.err, "test")
		require.Equal(t, c.status, rec.Code)
		var p errs.ErrorResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &p))
		require.Equal(t, c.code, p.ErrCode)
		require.Equal(t, c.detail, p.Detail)
	}
}

// End to end across the pod boundary: the worker's handler and the serve pod's
// RPC client agree, so a bad query reaches the API layer as a rejection.
func TestCypherRPC_RejectionSurvivesThePodBoundary(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()
	assets, edges, sigs := digestFixture()
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, stubSignals{sigs}))

	mux := http.NewServeMux()
	NewHandler(svc).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	rpc := explore.NewLadybugRPCRepo(srv.URL, "")

	_, err = rpc.RunCypher(ctx, `MATCH (n:NoSuchLabel) RETURN n`, 10, 10)
	var rej *explore.QueryRejection
	require.ErrorAs(t, err, &rej)
	require.Contains(t, rej.Reason, "Binder exception")

	_, err = rpc.RunCypher(ctx, `MATCH (n:Asset) RETURN n`, 10, 10)
	require.NoError(t, err)
}
