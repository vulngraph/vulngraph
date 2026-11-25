package explore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/pkg/errs"
)

func newTestHandler() *Handler {
	repo := graph()
	repo.seeds = []Node{{ID: "a"}}
	return NewHandler(NewService(repo), nil)
}

func TestQueryHandler_RunsSpec(t *testing.T) {
	h := newTestHandler()
	body := `{"seed":{"ids":["a"]},"traverse":[{"direction":"out","max_hops":1}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/graph/query", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.Query(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var res Result
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	require.NotEmpty(t, res.Nodes)
	require.NotEmpty(t, res.Edges)
}

func TestQueryHandler_BadJSON_400(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest(http.MethodPost, "/api/graph/query", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	h.Query(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestQueryHandler_NoSeed_400(t *testing.T) {
	h := NewHandler(NewService(&fakeRepo{}), nil) // empty seeds
	body := `{"seed":{"ids":["x"]}}`
	req := httptest.NewRequest(http.MethodPost, "/api/graph/query", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.Query(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestTranslateHandler_ReturnsSpec(t *testing.T) {
	tr := &fakeTranslator{spec: GraphQuerySpec{Seed: NodeMatch{Types: []string{"ec2_instance"}}}}
	h := NewHandler(NewService(graph(), WithTranslator(tr)), nil)
	body := `{"natural_language":"show ec2 instances"}`
	req := httptest.NewRequest(http.MethodPost, "/api/graph/translate", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.Translate(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var spec GraphQuerySpec
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &spec))
	require.Equal(t, []string{"ec2_instance"}, spec.Seed.Types)
}

func TestTranslateHandler_Unavailable_400(t *testing.T) {
	h := newTestHandler() // no translator wired
	req := httptest.NewRequest(http.MethodPost, "/api/graph/translate", strings.NewReader(`{"natural_language":"x"}`))
	rec := httptest.NewRecorder()
	h.Translate(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestExpandHandler_RequiresID_400(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/graph/expand", nil)
	rec := httptest.NewRecorder()
	h.Expand(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestExpandHandler_OK(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/graph/expand?id=a&dir=out", nil)
	rec := httptest.NewRecorder()
	h.Expand(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

// Cypher is a read-only endpoint gated by RequireAuth (any authenticated user),
// not RequireRole(Admin) — there is no NonAdmin_403 to enforce here. Auth is
// verified at the mux layer in httpsrv/server.go. These tests cover the handler
// logic: 503 when Ladybug is unavailable and 400 for malformed input.

func TestCypherHandler_Unavailable_503(t *testing.T) {
	// nil CypherRunner → Ladybug not configured → 503 (errs.Unavailable).
	h := NewHandler(NewService(&fakeRepo{}), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/graph/cypher", strings.NewReader(`{"query":"MATCH (n) RETURN n"}`))
	rec := httptest.NewRecorder()
	h.Cypher(rec, req)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)

	rec = httptest.NewRecorder()
	h.NL(rec, httptest.NewRequest(http.MethodPost, "/api/graph/nl", strings.NewReader(`{"question":"q"}`)))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// capturingCypher records the caps it was handed.
type capturingCypher struct{ maxNodes, maxEdges int }

func (c *capturingCypher) RunCypher(_ context.Context, _ string, maxNodes, maxEdges int) (Result, error) {
	c.maxNodes, c.maxEdges = maxNodes, maxEdges
	return Result{}, nil
}

type constCypherTranslator struct{}

func (constCypherTranslator) TranslateToCypher(context.Context, string) (string, error) {
	return "MATCH (n) RETURN n", nil
}

// Both Cypher endpoints apply the documented caps: omitted → 500/2000, larger
// than the hard cap → 2000/5000, and NL passes the client's caps through.
func TestCypherEndpoints_ApplyDocumentedCaps(t *testing.T) {
	cases := []struct {
		name               string
		caps               string
		wantNodes, wantEdg int
	}{
		{"omitted uses the defaults", ``, 500, 2000},
		{"within range passes through", `,"max_nodes":10,"max_edges":20`, 10, 20},
		{"above the hard cap is clamped", `,"max_nodes":99999,"max_edges":99999`, 2000, 5000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &capturingCypher{}
			h := NewHandler(NewService(&fakeRepo{}, WithCypherTranslator(constCypherTranslator{})), c)
			rec := httptest.NewRecorder()
			h.Cypher(rec, httptest.NewRequest(http.MethodPost, "/api/graph/cypher", strings.NewReader(`{"query":"MATCH (n) RETURN n"`+tc.caps+`}`)))
			require.Equal(t, http.StatusOK, rec.Code)
			require.Equal(t, []int{tc.wantNodes, tc.wantEdg}, []int{c.maxNodes, c.maxEdges}, "cypher")

			c = &capturingCypher{}
			h = NewHandler(NewService(&fakeRepo{}, WithCypherTranslator(constCypherTranslator{})), c)
			rec = httptest.NewRecorder()
			h.NL(rec, httptest.NewRequest(http.MethodPost, "/api/graph/nl", strings.NewReader(`{"question":"q"`+tc.caps+`}`)))
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.Equal(t, []int{tc.wantNodes, tc.wantEdg}, []int{c.maxNodes, c.maxEdges}, "nl")
		})
	}
}

// The NL endpoint documents 503 when the graph engine is not wired.
func TestNLHandler_Unavailable_503(t *testing.T) {
	h := NewHandler(NewService(&fakeRepo{}), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/graph/nl", strings.NewReader(`{"question":"q"}`))
	rec := httptest.NewRecorder()
	h.NL(rec, req)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestCypherHandler_EmptyQuery_400(t *testing.T) {
	h := NewHandler(NewService(&fakeRepo{}), &fakeCypher{})
	req := httptest.NewRequest(http.MethodPost, "/api/graph/cypher", strings.NewReader(`{"query":""}`))
	rec := httptest.NewRecorder()
	h.Cypher(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// A query the read-only guard rejects is a client error, never a 500.
func TestCypherHandler_RejectedQuery_400(t *testing.T) {
	h := NewHandler(NewService(&fakeRepo{}), &fakeCypher{})
	for _, q := range []string{
		"MATCH (n) SET n.x = 1 RETURN n",
		"CREATE (n:Asset)",
		"MATCH (n) RETURN n; MATCH (m) DETACH DELETE m",
		"not cypher at all",
	} {
		body, err := json.Marshal(map[string]string{"query": q})
		require.NoError(t, err)
		rec := httptest.NewRecorder()
		h.Cypher(rec, httptest.NewRequest(http.MethodPost, "/api/graph/cypher", strings.NewReader(string(body))))
		require.Equal(t, http.StatusBadRequest, rec.Code, q)
	}

	rec := httptest.NewRecorder()
	h.Cypher(rec, httptest.NewRequest(http.MethodPost, "/api/graph/cypher", strings.NewReader(`{"query":"MATCH (n) RETURN n LIMIT 1"}`)))
	require.Equal(t, http.StatusOK, rec.Code)
}

// Engine outcomes map to distinct statuses: a rejection is the caller's 400
// with the engine's reason, a timeout 504, anything else an opaque 500.
func TestCypherHandler_EngineErrorStatuses(t *testing.T) {
	const q = "MATCH (n:Asset) RETURN n"
	cases := []struct {
		err    error
		status int
		detail string
	}{
		{fmt.Errorf("RunCypher: %w", &QueryRejection{Reason: "Binder exception: Table Nope does not exist."}),
			http.StatusBadRequest, "Binder exception: Table Nope does not exist."},
		{fmt.Errorf("RPC /internal/graph/cypher: %w", ErrQueryTimeout), http.StatusGatewayTimeout, "graph query timed out"},
		{errors.New("RPC /internal/graph/cypher: HTTP 500"), http.StatusInternalServerError, "graph cypher failed"},
	}
	for _, c := range cases {
		h := NewHandler(NewService(&fakeRepo{}), &perQueryCypher{errFor: map[string]error{q: c.err}})
		rec := httptest.NewRecorder()
		h.Cypher(rec, httptest.NewRequest(http.MethodPost, "/api/graph/cypher", strings.NewReader(`{"query":"`+q+`"}`)))
		require.Equal(t, c.status, rec.Code, c.err.Error())
		require.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
		var p struct {
			Detail string `json:"detail"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &p))
		require.Contains(t, p.Detail, c.detail)
		require.NotContains(t, p.Detail, "RPC /internal", "transport internals stay in the log")
	}
}

// A rejected query is rejected by every tier: the secondary is not retried.
func TestTieredCypherRunner_RejectionDoesNotFallThrough(t *testing.T) {
	const q = "MATCH (n:Nope) RETURN n"
	primary := &perQueryCypher{errFor: map[string]error{q: &QueryRejection{Reason: "Binder exception"}}}
	secondary := &countingCypher{}
	_, err := NewTieredCypherRunner(primary, secondary).RunCypher(context.Background(), q, 1, 1)
	require.ErrorIs(t, err, ErrInvalidQuery)
	require.Zero(t, secondary.calls)

	primary.errFor[q] = errors.New("ladybug down")
	_, err = NewTieredCypherRunner(primary, secondary).RunCypher(context.Background(), q, 1, 1)
	require.NoError(t, err)
	require.Equal(t, 1, secondary.calls, "an engine failure still falls through")
}

type countingCypher struct{ calls int }

func (c *countingCypher) RunCypher(context.Context, string, int, int) (Result, error) {
	c.calls++
	return Result{}, nil
}

// The worker's typed err_code, not its message, decides the sentinel.
func TestLadybugRPCRepo_DecodesTypedErrors(t *testing.T) {
	status := http.StatusBadRequest
	write := func(w http.ResponseWriter, _ *http.Request) {
		switch status {
		case http.StatusBadRequest:
			errs.WriteHTTPError(w, errs.InvalidInput("Parser exception: bad"))
		case http.StatusGatewayTimeout:
			errs.WriteHTTPError(w, errs.Timeout("graph query timed out"))
		default:
			errs.WriteHTTPError(w, errs.Internal("Runtime exception: boom"))
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(write))
	defer srv.Close()
	rpc := NewLadybugRPCRepo(srv.URL, "")

	_, err := rpc.RunCypher(context.Background(), "q", 1, 1)
	var rej *QueryRejection
	require.ErrorAs(t, err, &rej)
	require.Equal(t, "Parser exception: bad", rej.Reason)

	status = http.StatusGatewayTimeout
	_, err = rpc.RunCypher(context.Background(), "q", 1, 1)
	require.ErrorIs(t, err, ErrQueryTimeout)
	require.NotErrorIs(t, err, ErrInvalidQuery)

	status = http.StatusInternalServerError
	_, err = rpc.RunCypher(context.Background(), "q", 1, 1)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrInvalidQuery)
	require.NotErrorIs(t, err, ErrQueryTimeout)
}

// fakeCypher satisfies CypherRunner for handler tests.
type fakeCypher struct{}

func (f *fakeCypher) RunCypher(_ context.Context, _ string, _, _ int) (Result, error) {
	return Result{}, nil
}

// perQueryCypher returns a different Result per query text, so one QueryHealth
// call can exercise every outcome at once.
type perQueryCypher struct {
	byQuery map[string]Result
	errFor  map[string]error
}

func (c *perQueryCypher) RunCypher(_ context.Context, q string, _, _ int) (Result, error) {
	if err := c.errFor[q]; err != nil {
		return Result{}, err
	}
	return c.byQuery[q], nil
}

// A probe failure is reported as a fixed category; the engine's raw error
// (which can carry query text and graph internals) is logged, never echoed.
func TestQueryHealth_DoesNotEchoRawErrors(t *testing.T) {
	cypher := &perQueryCypher{
		byQuery: map[string]Result{},
		errFor: map[string]error{
			"BROKEN": errors.New("ladybug: binder error near MATCH (a:SecretTable)"),
			"SLOW":   fmt.Errorf("run: %w", context.DeadlineExceeded),
		},
	}
	h := NewHandler(NewService(graph()), cypher).WithNamedQueries([]NamedQueryEntry{
		{Name: "broken", Query: "BROKEN"},
		{Name: "slow", Query: "SLOW"},
	})
	rec := httptest.NewRecorder()
	h.QueryHealth(rec, httptest.NewRequest(http.MethodGet, "/api/graph/queries/health", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, rec.Body.String(), "SecretTable")
	require.NotContains(t, rec.Body.String(), "binder")

	var got []struct {
		Name  string `json:"name"`
		Error string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Len(t, got, 2)
	require.Equal(t, "probe failed (see server logs)", got[0].Error)
	require.Equal(t, "probe timed out", got[1].Error)
}

// TestQueryHealth_ReportsEmptyNotHealthy is the guard for a failure that hid
// two defects: QueryHealth reported healthy for any query
// that merely parsed, so the three CIEM queries built on CanEscalateTo (zero such
// edges ever written) and every query traversing HasRole/ProtectedBy (dropped at
// Ladybug load) all looked fine. A query that runs and can never return anything
// must be visible as empty, and an unprobeable entry must not claim health.
func TestQueryHealth_ReportsEmptyNotHealthy(t *testing.T) {
	cypher := &perQueryCypher{
		byQuery: map[string]Result{
			"GRAPH":  {Nodes: []Node{{ID: "a"}}},
			"SCALAR": {Columns: []string{"c"}, Rows: []map[string]any{{"c": 1}}},
			"EMPTY":  {},
		},
		errFor: map[string]error{"BROKEN": context.DeadlineExceeded},
	}
	h := NewHandler(NewService(graph()), cypher).WithNamedQueries([]NamedQueryEntry{
		{Name: "graph_shape", Query: "GRAPH"},
		{Name: "scalar_shape", Query: "SCALAR"},
		{Name: "dead", Query: "EMPTY"},
		{Name: "broken", Query: "BROKEN"},
		{Name: "parameterised", Query: "EMPTY", Params: []string{"id"}},
	})

	rec := httptest.NewRecorder()
	h.QueryHealth(rec, httptest.NewRequest(http.MethodGet, "/api/graph/queries/health", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var got []struct {
		Name    string `json:"name"`
		Healthy bool   `json:"healthy"`
		Probed  bool   `json:"probed"`
		Empty   bool   `json:"empty"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	byName := map[string]struct {
		healthy, probed, empty bool
	}{}
	for _, r := range got {
		byName[r.Name] = struct{ healthy, probed, empty bool }{r.Healthy, r.Probed, r.Empty}
	}

	require.Equal(t, struct{ healthy, probed, empty bool }{true, true, false}, byName["graph_shape"])
	// A scalar result is a real result: aggregates populate Rows, not Nodes.
	require.Equal(t, struct{ healthy, probed, empty bool }{true, true, false}, byName["scalar_shape"])
	// The whole point: runs clean, returns nothing, must not read as a pass.
	require.Equal(t, struct{ healthy, probed, empty bool }{true, true, true}, byName["dead"])
	require.Equal(t, struct{ healthy, probed, empty bool }{false, true, false}, byName["broken"])
	// Cannot be probed → nothing was measured, so it does not claim health.
	require.Equal(t, struct{ healthy, probed, empty bool }{false, false, false}, byName["parameterised"])
}

func TestQueryHealth_NoEngineIsProblem503(t *testing.T) {
	rec := httptest.NewRecorder()
	NewHandler(NewService(graph()), nil).QueryHealth(rec, httptest.NewRequest(http.MethodGet, "/api/graph/queries/health", nil))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
}
