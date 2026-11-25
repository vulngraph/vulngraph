package explore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeStats struct {
	health    GraphHealth
	healthErr error
	assets    int64
}

func (f *fakeStats) NodeCounts(context.Context) (assets, roles, repos int64, err error) {
	return f.assets, 0, 0, nil
}

func (f *fakeStats) GraphHealth(context.Context) (GraphHealth, error) {
	return f.health, f.healthErr
}

func getStatus(t *testing.T, h *Handler) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	h.Status(rec, httptest.NewRequest(http.MethodGet, "/api/graph/status", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var out map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	return out
}

// ready used to be `cypher != nil` — a startup wiring fact — so a wired engine
// with no loaded graph read as ready and the Explore banner never showed.
func TestStatus_ReadyOnlyWithALoadedGraph(t *testing.T) {
	built := time.Now().Add(-time.Hour).UTC()
	for name, tc := range map[string]struct {
		cypher    CypherRunner
		stats     NodeStatsProvider
		wantReady bool
		wantState string
		wantBuilt bool
	}{
		"no engine":           {nil, nil, false, graphStateNotConfigured, false},
		"runner but no stats": {&fakeCypher{}, nil, false, graphStateUnknown, false},
		"health unreadable":   {&fakeCypher{}, &fakeStats{healthErr: errors.New("worker down")}, false, graphStateUnknown, false},
		"wired, never built":  {&fakeCypher{}, &fakeStats{}, false, graphStateNotReady, false},
		"built but empty":     {&fakeCypher{}, &fakeStats{health: GraphHealth{LastBuiltAt: built}}, false, graphStateNotReady, true},
		"built and serving":   {&fakeCypher{}, &fakeStats{health: GraphHealth{Ready: true, NodeCount: 9, LastBuiltAt: built}}, true, graphStateReady, true},
	} {
		t.Run(name, func(t *testing.T) {
			out := getStatus(t, NewHandler(NewService(graph()), tc.cypher).WithNodeStats(tc.stats))
			require.Equal(t, tc.wantReady, out["ready"])
			require.Equal(t, tc.wantState, out["state"])
			_, hasBuilt := out["last_built_at"]
			require.Equal(t, tc.wantBuilt, hasBuilt, "a build time is reported only when one exists")
			_, hasCount := out["node_count"]
			require.Equal(t, tc.wantState == graphStateNotReady || tc.wantState == graphStateReady, hasCount,
				"node_count only when the engine answered")
		})
	}
}

func TestStats_NoEngineIs503NotZeroCounts(t *testing.T) {
	rec := httptest.NewRecorder()
	NewHandler(NewService(graph()), nil).Stats(rec, httptest.NewRequest(http.MethodGet, "/api/graph/stats", nil))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
}

// fakeWorker serves the graphstore internal RPC routes the serve pod reads.
func fakeWorker(t *testing.T, health string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/graph/stats", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"assets":5,"roles":2,"repos":1}`))
	})
	mux.HandleFunc("GET /internal/graph/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(health))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// The default deployment reads stats over the worker RPC. That provider used to
// expose no readiness, so /api/graph/stats said ready: true and last_rebuilt:
// now on every poll — a never-built graph looked freshly rebuilt.
func TestStats_RPCProvider_ReportsWorkerBuildState(t *testing.T) {
	get := func(t *testing.T, health string) map[string]any {
		t.Helper()
		rpc := NewLadybugRPCRepo(fakeWorker(t, health).URL, "")
		h := NewHandler(NewService(graph()), rpc).WithNodeStats(rpc)
		rec := httptest.NewRecorder()
		h.Stats(rec, httptest.NewRequest(http.MethodGet, "/api/graph/stats", nil))
		require.Equal(t, http.StatusOK, rec.Code)
		var out map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
		return out
	}

	out := get(t, `{"ready":false,"node_count":0}`)
	require.Equal(t, false, out["ready"])
	require.Contains(t, out, "last_rebuilt")
	require.Nil(t, out["last_rebuilt"], "never built is null, not now")

	out = get(t, `{"ready":true,"node_count":5,"last_built":"2026-10-01T12:00:00Z"}`)
	require.Equal(t, true, out["ready"])
	require.Equal(t, "2026-10-01T12:00:00Z", out["last_rebuilt"])
	require.Equal(t, map[string]any{"assets": 5.0, "roles": 2.0, "repos": 1.0}, out["nodes"])
}

func TestStatus_RPCProvider_UnreachableWorkerIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler()) // e.g. an older worker without /internal/graph/health
	t.Cleanup(srv.Close)
	rpc := NewLadybugRPCRepo(srv.URL, "")
	out := getStatus(t, NewHandler(NewService(graph()), rpc).WithNodeStats(rpc))
	require.Equal(t, false, out["ready"])
	require.Equal(t, graphStateUnknown, out["state"])
}

// A worker that cannot report its build state (unreachable, or one that
// predates /internal/graph/health mid rolling upgrade) is a temporary 503,
// never counts with a guessed readiness.
func TestStats_UnreadableBuildStateIs503(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	rpc := NewLadybugRPCRepo(srv.URL, "")
	rec := httptest.NewRecorder()
	NewHandler(NewService(graph()), rpc).WithNodeStats(rpc).
		Stats(rec, httptest.NewRequest(http.MethodGet, "/api/graph/stats", nil))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
}

func TestTieredStats_ReportsTheServingTier(t *testing.T) {
	ctx := context.Background()
	primary := &fakeStats{assets: 1}
	secondary := &fakeStats{assets: 2, health: GraphHealth{Ready: true, NodeCount: 2}}
	ts := NewTieredStats(primary, secondary)

	hl, err := ts.GraphHealth(ctx)
	require.NoError(t, err)
	require.True(t, hl.Ready, "replica still syncing: the worker answers Cypher, so its state is reported")
	assets, _, _, err := ts.NodeCounts(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 2, assets)

	primary.health = GraphHealth{Ready: true, NodeCount: 1}
	assets, _, _, err = ts.NodeCounts(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, assets, "a ready replica is primary")

	primary.health = GraphHealth{}
	secondary.healthErr = errors.New("worker down")
	_, err = ts.GraphHealth(ctx)
	require.Error(t, err, "no ready tier and an unreadable worker is unknown, not ready")
}
