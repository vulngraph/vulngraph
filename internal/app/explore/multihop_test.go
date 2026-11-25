package explore

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func getStats(t *testing.T, h *Handler) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	h.Stats(rec, httptest.NewRequest(http.MethodGet, "/api/graph/stats", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var out map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	return out
}

// The multi-hop guard reaches /api/graph/status and /api/graph/stats: unknown
// until a build recorded its table sizes, false when every table fits, true
// with the oversized tables named when one does not.
func TestStatusAndStats_ReportTheMultiHopGuard(t *testing.T) {
	built := time.Now().Add(-time.Hour)
	cases := map[string]struct {
		health     GraphHealth
		wantFlag   any // nil = unknown
		wantTables []any
	}{
		"never measured": {GraphHealth{}, nil, []any{}},
		"every table fits": {
			GraphHealth{Ready: true, NodeCount: 3, LastBuiltAt: built, NodeTablesMeasured: true, OversizedNodeTables: map[string]int64{}},
			false, []any{},
		},
		"a table above one node group": {
			GraphHealth{
				Ready: true, NodeCount: 3, LastBuiltAt: built, NodeTablesMeasured: true,
				OversizedNodeTables: map[string]int64{"Package": 200000, "Asset": 150000},
			},
			true,
			[]any{
				map[string]any{"label": "Asset", "rows": 150000.0},
				map[string]any{"label": "Package", "rows": 200000.0},
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := NewHandler(NewService(graph()), &fakeCypher{}).WithNodeStats(&fakeStats{health: tc.health})

			status := getStatus(t, h)
			flag, present := status["multi_hop_may_be_incomplete"]
			require.Equal(t, tc.wantFlag != nil, present, "status omits the flag only when nothing was measured")
			require.Equal(t, tc.wantFlag, flag)
			if len(tc.wantTables) > 0 {
				require.Equal(t, tc.wantTables, status["oversized_node_tables"])
			}

			stats := getStats(t, h)
			require.Contains(t, stats, "multi_hop_may_be_incomplete")
			require.Equal(t, tc.wantFlag, stats["multi_hop_may_be_incomplete"], "stats reports unknown as null")
			require.Equal(t, tc.wantTables, stats["oversized_node_tables"])
		})
	}
}

// The worker's flag on a Cypher answer crosses the RPC and reaches the API
// response.
func TestCypher_RPCCarriesTheMultiHopFlag(t *testing.T) {
	for _, flagged := range []bool{true, false} {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /internal/graph/cypher", func(w http.ResponseWriter, _ *http.Request) {
			body := `{"nodes":[],"edges":[],"truncated":false,"multi_hop_may_be_incomplete":false}`
			if flagged {
				body = strings.Replace(body, `"multi_hop_may_be_incomplete":false`, `"multi_hop_may_be_incomplete":true`, 1)
			}
			_, _ = w.Write([]byte(body))
		})
		srv := httptest.NewServer(mux)
		rpc := NewLadybugRPCRepo(srv.URL, "")
		h := NewHandler(NewService(graph()), rpc)
		rec := httptest.NewRecorder()
		h.Cypher(rec, httptest.NewRequest(http.MethodPost, "/api/graph/cypher",
			strings.NewReader(`{"query":"MATCH (a:Asset)-[:HasRole]->(r:IamRole)-[:CanAssume]->(b) RETURN b"}`)))
		srv.Close()
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var out map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
		if flagged {
			require.Equal(t, true, out["multi_hop_may_be_incomplete"])
		} else {
			require.NotContains(t, out, "multi_hop_may_be_incomplete")
		}
	}
}
