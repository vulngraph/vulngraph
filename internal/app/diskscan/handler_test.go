package diskscan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeRuns struct {
	runs      []DiskScanRun
	vols      []VolumeResult
	gotConn   string
	gotLimit  int
	volsCalls int
}

func (f *fakeRuns) ListRuns(_ context.Context, connectorID string, limit int) ([]DiskScanRun, error) {
	f.gotConn, f.gotLimit = connectorID, limit
	return f.runs, nil
}

func (f *fakeRuns) AssetVolumes(context.Context, string) ([]VolumeResult, error) {
	f.volsCalls++
	return f.vols, nil
}

type fakeStamps struct {
	state, gap string
	err        error
}

func (f fakeStamps) DiskScanStamp(context.Context, string) (string, string, error) {
	return f.state, f.gap, f.err
}

// fakeControl mirrors the connector service's actor rule: only an admin
// session, never an API key, may change the mode.
type fakeControl struct {
	info    ConnectorInfo
	err     error
	setErr  error
	gotMode DiskScanMode
	gotConf string
	calls   int
}

func (f *fakeControl) Info(context.Context, string) (ConnectorInfo, error) { return f.info, f.err }

func (f *fakeControl) SetMode(_ context.Context, _ string, m DiskScanMode, conf string, a Actor) error {
	f.calls++
	f.gotMode, f.gotConf = m, conf
	if !a.Admin || a.ViaAPIKey {
		return ErrForbidden
	}
	return f.setErr
}

func awsInfo() ConnectorInfo {
	return ConnectorInfo{ConnectorID: "c1", Type: "aws", Role: "arn:aws:iam::1:role/GraphDiskScan", Confirmation: "type this"}
}

func serve(t *testing.T, h http.HandlerFunc, method, path, pattern string, body string, ctx context.Context) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(pattern, h)
	req := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

type actorKey struct{}

// testActor reads the Actor a test stored in the context, standing in for the
// auth-backed function cmd/graph injects.
func testActor(ctx context.Context) Actor {
	a, _ := ctx.Value(actorKey{}).(Actor)
	return a
}

func withActor(a Actor) context.Context {
	return context.WithValue(context.Background(), actorKey{}, a)
}

func adminCtx() context.Context { return withActor(Actor{ID: "u1", Admin: true}) }

func newHandler(runs Runs, stamps AssetStamps, conns ConnectorControl) *Handler {
	return NewHandler(runs, stamps, conns, testActor)
}

func TestList_ParsesFilterAndLimit(t *testing.T) {
	f := &fakeRuns{runs: []DiskScanRun{{ID: "r1", ConnectorID: "c1", Status: StatusPartial, StartedAt: time.Unix(1, 0).UTC(),
		Counts: RunCounts{Volumes: 3, Scanned: 1, Gaps: 2}}}}
	h := newHandler(f, fakeStamps{}, &fakeControl{})
	rec := serve(t, h.List, "GET", "/api/disk-scans?connector_id=c1&limit=5", "GET /api/disk-scans", "", adminCtx())
	require.Equal(t, 200, rec.Code)
	require.Equal(t, "c1", f.gotConn)
	require.Equal(t, 5, f.gotLimit)
	var out struct {
		Runs []map[string]any `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.Equal(t, "partial", out.Runs[0]["status"])
	require.NotContains(t, out.Runs[0], "finished_at")
}

func TestList_RejectsBadLimit(t *testing.T) {
	h := newHandler(&fakeRuns{}, fakeStamps{}, &fakeControl{})
	for _, q := range []string{"limit=0", "limit=x", "limit=201"} {
		rec := serve(t, h.List, "GET", "/api/disk-scans?"+q, "GET /api/disk-scans", "", adminCtx())
		require.Equal(t, 400, rec.Code, q)
	}
}

func TestGetAsset_NotEnabledHidesStoredVolumes(t *testing.T) {
	f := &fakeRuns{vols: []VolumeResult{{VolumeRef: "vol-1", InventoryKnown: true, PackageCount: 9}}}
	h := newHandler(f, fakeStamps{state: AssetNotEnabled, gap: GapNotEnabled}, &fakeControl{})
	rec := serve(t, h.GetAsset, "GET", "/api/assets/i-1/disk-scan", "GET /api/assets/{id}/disk-scan", "", adminCtx())
	require.Equal(t, 200, rec.Code)
	var out AssetResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.Equal(t, AssetNotEnabled, out.State)
	require.Equal(t, GapNotEnabled, out.Gap)
	require.Empty(t, out.Volumes)
}

func TestGetAsset_MissingStampReadsAsNoneNeverScanned(t *testing.T) {
	f := &fakeRuns{vols: []VolumeResult{{VolumeRef: "vol-1", Gap: GapReadError}}}
	h := newHandler(f, fakeStamps{}, &fakeControl{})
	rec := serve(t, h.GetAsset, "GET", "/api/assets/i-1/disk-scan", "GET /api/assets/{id}/disk-scan", "", adminCtx())
	var out AssetResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.Equal(t, AssetNone, out.State)
	require.Len(t, out.Volumes, 1)
	require.False(t, out.Volumes[0].InventoryKnown)
	require.Equal(t, GapReadError, out.Volumes[0].Gap)
}

func TestGetAsset_UnknownAsset404(t *testing.T) {
	h := newHandler(&fakeRuns{}, fakeStamps{err: ErrNotFound}, &fakeControl{})
	rec := serve(t, h.GetAsset, "GET", "/api/assets/x/disk-scan", "GET /api/assets/{id}/disk-scan", "", adminCtx())
	require.Equal(t, 404, rec.Code)
}

func TestGetConnector_ShowsRoleIdentifierSentenceAndLastRun(t *testing.T) {
	info := awsInfo()
	info.Mode = DiskScanModeExistingSnapshots
	info.EnabledBy = "u1"
	info.EnabledAt = time.Unix(100, 0).UTC()
	f := &fakeRuns{runs: []DiskScanRun{{ID: "r1", ConnectorID: "c1", Status: StatusSucceeded}}}
	h := newHandler(f, fakeStamps{}, &fakeControl{info: info})
	rec := serve(t, h.GetConnector, "GET", "/api/connectors/c1/disk-scan", "GET /api/connectors/{id}/disk-scan", "", adminCtx())
	require.Equal(t, 200, rec.Code)
	var out map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.Equal(t, "existing_snapshots", out["mode"])
	require.Equal(t, info.Role, out["role"])
	require.Equal(t, "type this", out["confirmation"])
	require.NotEmpty(t, out["warning"])
	require.Equal(t, []any{"off", "existing_snapshots", "create_snapshots"}, out["modes"])
	require.Equal(t, "succeeded", out["last_run"].(map[string]any)["status"])
}

func TestGetConnector_OffReportsOffAndGCPCannotCreate(t *testing.T) {
	h := newHandler(&fakeRuns{}, fakeStamps{}, &fakeControl{info: ConnectorInfo{ConnectorID: "g1", Type: "gcp", Confirmation: "x"}})
	rec := serve(t, h.GetConnector, "GET", "/api/connectors/g1/disk-scan", "GET /api/connectors/{id}/disk-scan", "", adminCtx())
	var out map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.Equal(t, "off", out["mode"])
	require.Equal(t, []any{"off", "existing_snapshots"}, out["modes"])
	require.NotContains(t, out, "last_run")
}

func put(h *Handler, ctx context.Context, body string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/connectors/{id}/disk-scan", h.SetConnector)
	req := httptest.NewRequest("PUT", "/api/connectors/c1/disk-scan", strings.NewReader(body)).WithContext(ctx)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestSetConnector_AdminSessionPassesTheTypedConfirmationThrough(t *testing.T) {
	c := &fakeControl{info: awsInfo()}
	rec := put(newHandler(&fakeRuns{}, fakeStamps{}, c), adminCtx(), `{"mode":"existing_snapshots","confirmation":"type this"}`)
	require.Equal(t, 204, rec.Code)
	require.Equal(t, DiskScanModeExistingSnapshots, c.gotMode)
	require.Equal(t, "type this", c.gotConf)
}

func TestSetConnector_OffMapsToTheZeroMode(t *testing.T) {
	c := &fakeControl{info: awsInfo()}
	rec := put(newHandler(&fakeRuns{}, fakeStamps{}, c), adminCtx(), `{"mode":"off"}`)
	require.Equal(t, 204, rec.Code)
	require.Equal(t, DiskScanModeOff, c.gotMode)
}

func TestDiskScan_NonAdmin_403(t *testing.T) {
	viewer := withActor(Actor{ID: "u2"})
	c := &fakeControl{info: awsInfo()}
	rec := put(newHandler(&fakeRuns{}, fakeStamps{}, c), viewer, `{"mode":"existing_snapshots","confirmation":"type this"}`)
	require.Equal(t, 403, rec.Code)
}

func TestDiskScan_APIKeyAdmin_403(t *testing.T) {
	ctx := withActor(Actor{ID: "u1", Admin: true, ViaAPIKey: true})
	rec := put(newHandler(&fakeRuns{}, fakeStamps{}, &fakeControl{info: awsInfo()}), ctx, `{"mode":"existing_snapshots","confirmation":"type this"}`)
	require.Equal(t, 403, rec.Code)
}

func TestSetConnector_ErrorMapping(t *testing.T) {
	cases := map[string]struct {
		err  error
		want int
	}{
		"confirmation": {ErrConfirmation, 400},
		"invalid":      {ErrInvalid, 400},
		"not found":    {ErrNotFound, 404},
		"unsupported":  {ErrUnsupported, 409},
		"role missing": {ErrRoleMissing, 409},
		"role shared":  {ErrRoleShared, 409},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := &fakeControl{info: awsInfo(), setErr: tc.err}
			rec := put(newHandler(&fakeRuns{}, fakeStamps{}, c), adminCtx(), `{"mode":"create_snapshots","confirmation":"x"}`)
			require.Equal(t, tc.want, rec.Code)
		})
	}
}

func TestSetConnector_BadBodyAndModes(t *testing.T) {
	c := &fakeControl{info: awsInfo()}
	h := newHandler(&fakeRuns{}, fakeStamps{}, c)
	require.Equal(t, 400, put(h, adminCtx(), `not json`).Code)
	require.Equal(t, 400, put(h, adminCtx(), `{"mode":"yolo"}`).Code)
	require.Equal(t, 400, put(h, adminCtx(), `{}`).Code)
	require.Zero(t, c.calls)
}

func TestSetConnector_GCPCreateSnapshotsRefusedBeforeTheService(t *testing.T) {
	c := &fakeControl{info: ConnectorInfo{ConnectorID: "g1", Type: "gcp"}}
	rec := put(newHandler(&fakeRuns{}, fakeStamps{}, c), adminCtx(), `{"mode":"create_snapshots","confirmation":"x"}`)
	require.Equal(t, 409, rec.Code)
	require.Zero(t, c.calls)
}
