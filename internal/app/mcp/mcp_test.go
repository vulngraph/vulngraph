package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/compliance"
	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/findingctx"
	"github.com/vulngraph/vulngraph/internal/app/respond"
	"github.com/vulngraph/vulngraph/internal/app/suppress"
)

type fakeAssets struct {
	err       error
	blastErr  error
	truncated bool
}

func (f fakeAssets) Get(_ context.Context, id string) (asset.Asset, error) {
	if f.err != nil {
		return asset.Asset{}, f.err
	}
	return asset.Asset{ID: id, Name: "web", Type: "ec2_instance"}, nil
}

// BlastRadius returns the seed first, as asset.Service's walk does.
func (f fakeAssets) BlastRadius(_ context.Context, id string, _ int) (asset.BlastRadius, error) {
	if f.blastErr != nil {
		return asset.BlastRadius{}, f.blastErr
	}
	return asset.BlastRadius{SeedID: id, Assets: []asset.Asset{{ID: id}, {ID: "a"}, {ID: "b"}}, Truncated: f.truncated}, nil
}
func (f fakeAssets) List(_ context.Context, _ asset.Filter) ([]asset.Asset, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []asset.Asset{{ID: "a1", Name: "web", Type: "ec2_instance"}}, nil
}

type fakeFindings struct{}

func (fakeFindings) List(context.Context, finding.Filter) ([]finding.Finding, error) {
	return []finding.Finding{{ID: "f1", CheckID: "aws-ec2-public-ip"}}, nil
}

// fakeFindingCtx returns f for every id, or an unscored finding when f is unset.
type fakeFindingCtx struct{ f finding.Finding }

func (c fakeFindingCtx) Context(_ context.Context, id string) (findingctx.FindingContext, error) {
	f := c.f
	if f.ID == "" {
		f = finding.Finding{ID: id, Title: "ctx"}
	}
	return findingctx.FindingContext{ContextPack: respond.ContextPack{Finding: f}}, nil
}

// routineFinding is scored, low-urgency and not critical: the only shape MCP may
// suppress.
var routineFinding = finding.Finding{
	ID: "f1", Severity: finding.SeverityMedium, Score: 40, ScoreBand: "monitor",
	MustFixClass: "routine", EnrichedAt: time.Now(),
}

type fakeCompliance struct{}

func (fakeCompliance) Compute(context.Context) (compliance.Coverage, error) {
	return compliance.Coverage{Total: 3, Passing: 2}, nil
}

type fakeGraph struct{}

func (fakeGraph) Translate(_ context.Context, nl string) (explore.GraphQuerySpec, error) {
	return explore.GraphQuerySpec{Seed: explore.NodeMatch{Types: []string{"ec2_instance"}}}, nil
}
func (fakeGraph) Run(_ context.Context, _ explore.GraphQuerySpec) (explore.Result, error) {
	return explore.Result{Nodes: []explore.Node{{ID: "i-1", Type: "ec2_instance"}}}, nil
}
func (fakeGraph) TranslateAndRunCypher(_ context.Context, _ explore.CypherRunner, _ string, _, _ int) (explore.Result, string, error) {
	return explore.Result{}, "", nil
}

type fakeSuppress struct {
	gotID, gotReason, gotBy string
	gotExpiry               time.Time
}

func (f *fakeSuppress) SuppressUntil(_ context.Context, id, reason, by string, expiresAt time.Time) (suppress.Suppression, error) {
	f.gotID, f.gotReason, f.gotBy, f.gotExpiry = id, reason, by, expiresAt
	return suppress.Suppression{FindingID: id, Reason: reason, SuppressedBy: by}, nil
}

func newHandler() *Handler {
	return NewHandler(fakeAssets{}, fakeFindings{}, fakeFindingCtx{}, fakeCompliance{}, fakeGraph{}, nil, nil, &fakeSuppress{}, nil, nil, nil).
		WithLimits(unlimited{}, unlimited{})
}

// unlimited admits every call.
type unlimited struct{}

func (unlimited) Allow(string) (bool, time.Duration) { return true, 0 }

// admin returns a request carrying an admin session, mirroring what RequireAuth
// attaches in production.
func adminCtx() context.Context {
	return auth.ContextWithUser(context.Background(), auth.User{ID: "u1", Email: "a@b.example", Role: auth.RoleAdmin})
}

func viewerCtx() context.Context {
	return auth.ContextWithUser(context.Background(), auth.User{ID: "u2", Email: "v@b.example", Role: auth.RoleViewer})
}

// rpcCtx is rpc with an explicit context (for the auth-gated write tool).
func rpcCtx(t *testing.T, ctx context.Context, h *Handler, body string) rpcResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/mcp", strings.NewReader(body)).WithContext(ctx)
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var resp rpcResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp
}

// rpc sends a JSON-RPC request as a viewer and decodes the response.
func rpc(t *testing.T, h *Handler, body string) rpcResponse {
	t.Helper()
	return rpcCtx(t, viewerCtx(), h, body)
}

func TestInitialize(t *testing.T) {
	resp := rpc(t, newHandler(), `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	require.Nil(t, resp.Error)
	result := resp.Result.(map[string]any)
	require.Equal(t, "graph", result["serverInfo"].(map[string]any)["name"])
}

func TestToolsList(t *testing.T) {
	resp := rpc(t, newHandler(), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	require.Nil(t, resp.Error)
	tools := resp.Result.(map[string]any)["tools"].([]any)
	names := map[string]bool{}
	for _, tl := range tools {
		names[tl.(map[string]any)["name"].(string)] = true
	}
	require.True(t, names["get_asset_context"])
	require.True(t, names["list_findings"])
	require.True(t, names["get_compliance"])
	require.True(t, names["suppress_finding"])
}

func TestToolsCall_GetAssetContext(t *testing.T) {
	resp := rpc(t, newHandler(), `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_asset_context","arguments":{"asset_id":"i-1"}}}`)
	require.Nil(t, resp.Error)
	content := resp.Result.(map[string]any)["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	require.Contains(t, text, `"blast_radius":2`, "the seed is not part of its own blast radius")
	require.Contains(t, text, `"blast_radius_known":true`)
	require.Contains(t, text, `"blast_radius_truncated":false`)
	require.Contains(t, text, "i-1")
}

func TestToolsCall_GetAssetContext_BlastKnownness(t *testing.T) {
	call := func(assets fakeAssets) string {
		t.Helper()
		h := NewHandler(assets, fakeFindings{}, fakeFindingCtx{}, fakeCompliance{}, fakeGraph{}, nil, nil, &fakeSuppress{}, nil, nil, nil)
		resp := rpc(t, h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_asset_context","arguments":{"asset_id":"i-1"}}}`)
		require.Nil(t, resp.Error)
		return resp.Result.(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	}

	text := call(fakeAssets{truncated: true})
	require.Contains(t, text, `"blast_radius_truncated":true`, "a budget-cut walk is a lower bound")
	require.Contains(t, text, `"blast_radius":2`)
	require.Contains(t, text, `"reachable":[{"ID":"a"`, "the seed is not listed as reachable")

	text = call(fakeAssets{blastErr: errors.New("walk failed")})
	require.Contains(t, text, `"blast_radius_known":false`)
	require.NotContains(t, text, `"blast_radius":`, "an unmeasured radius carries no count")
	require.Contains(t, text, `"asset":`, "the asset details still come back")
}

func TestToolsCall_ListFindings(t *testing.T) {
	resp := rpc(t, newHandler(), `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_findings","arguments":{"source":"cspm"}}}`)
	require.Nil(t, resp.Error)
	text := resp.Result.(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	require.Contains(t, text, "aws-ec2-public-ip")
}

func TestToolsCall_GraphQuery(t *testing.T) {
	resp := rpc(t, newHandler(), `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"graph_query","arguments":{"question":"what ec2 instances exist"}}}`)
	require.Nil(t, resp.Error)
	text := resp.Result.(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	require.Contains(t, text, "i-1")
}

func TestToolsCall_UnknownTool(t *testing.T) {
	resp := rpc(t, newHandler(), `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope","arguments":{}}}`)
	require.NotNil(t, resp.Error)
	require.Equal(t, codeMethodNotFound, resp.Error.Code)
}

func TestToolsCall_ToolError(t *testing.T) {
	h := NewHandler(fakeAssets{err: errors.New("not found")}, fakeFindings{}, fakeFindingCtx{}, fakeCompliance{}, fakeGraph{}, nil, nil, &fakeSuppress{}, nil, nil, nil)
	resp := rpc(t, h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_asset_context","arguments":{"asset_id":"x"}}}`)
	require.NotNil(t, resp.Error)
	require.Equal(t, codeInternal, resp.Error.Code)
}

func TestToolsCall_SuppressFinding_Admin(t *testing.T) {
	sup := &fakeSuppress{}
	h := NewHandler(fakeAssets{}, fakeFindings{}, fakeFindingCtx{f: routineFinding}, fakeCompliance{}, fakeGraph{}, nil, nil, sup, nil, nil, nil)
	resp := rpcCtx(t, adminCtx(), h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"suppress_finding","arguments":{"finding_id":"f1","reason":"false positive","expires_in_days":30}}}`)
	require.Nil(t, resp.Error)
	text := resp.Result.(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	require.Contains(t, text, "f1")
	require.Equal(t, "f1", sup.gotID)
	require.Equal(t, "false positive", sup.gotReason)
	require.Equal(t, "mcp:a@b.example", sup.gotBy) // actor from session, marked as the MCP seam
	require.WithinDuration(t, time.Now().Add(30*24*time.Hour), sup.gotExpiry, time.Minute)
}

func TestToolsCall_SuppressFinding_RequiresExpiryAndReason(t *testing.T) {
	for _, args := range []string{
		`{"finding_id":"f1","reason":"r"}`,
		`{"finding_id":"f1","reason":"r","expires_in_days":0}`,
		`{"finding_id":"f1","reason":"r","expires_in_days":31}`,
		`{"finding_id":"f1","reason":"r","expires_in_days":365}`,
		`{"finding_id":"f1","reason":"  ","expires_in_days":7}`,
		`{"finding_id":"","reason":"r","expires_in_days":7}`,
	} {
		sup := &fakeSuppress{}
		h := NewHandler(fakeAssets{}, fakeFindings{}, fakeFindingCtx{f: routineFinding}, fakeCompliance{}, fakeGraph{}, nil, nil, sup, nil, nil, nil)
		resp := rpcCtx(t, adminCtx(), h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"suppress_finding","arguments":`+args+`}}`)
		require.NotNil(t, resp.Error, args)
		require.Equal(t, codeInvalidParams, resp.Error.Code, args)
		require.Empty(t, sup.gotID, args)
	}
}

// An agent holding an admin token must not be able to hide anything urgent, or
// anything whose urgency is not known yet.
func TestToolsCall_SuppressFinding_RefusesUrgentOrUnscored(t *testing.T) {
	with := func(mut func(*finding.Finding)) finding.Finding {
		f := routineFinding
		mut(&f)
		return f
	}
	for name, f := range map[string]finding.Finding{
		"critical":   with(func(f *finding.Finding) { f.Severity = finding.SeverityCritical }),
		"must_fix":   with(func(f *finding.Finding) { f.MustFixClass = "must_fix" }),
		"page band":  with(func(f *finding.Finding) { f.ScoreBand = "page" }),
		"high band":  with(func(f *finding.Finding) { f.ScoreBand = "high" }),
		"unenriched": with(func(f *finding.Finding) { f.EnrichedAt = time.Time{} }),
		"no band":    with(func(f *finding.Finding) { f.ScoreBand = "" }),
		"no class":   with(func(f *finding.Finding) { f.MustFixClass = "" }),
	} {
		t.Run(name, func(t *testing.T) {
			sup := &fakeSuppress{}
			h := NewHandler(fakeAssets{}, fakeFindings{}, fakeFindingCtx{f: f}, fakeCompliance{}, fakeGraph{}, nil, nil, sup, nil, nil, nil)
			resp := rpcCtx(t, adminCtx(), h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"suppress_finding","arguments":{"finding_id":"f1","reason":"noise","expires_in_days":7}}}`)
			require.NotNil(t, resp.Error)
			require.Equal(t, codeForbidden, resp.Error.Code)
			require.Contains(t, resp.Error.Message, "person")
			require.Empty(t, sup.gotID, "the suppression must never be written")
		})
	}
}

func TestToolsCall_SuppressFinding_NonAdmin(t *testing.T) {
	sup := &fakeSuppress{}
	h := NewHandler(fakeAssets{}, fakeFindings{}, fakeFindingCtx{}, fakeCompliance{}, fakeGraph{}, nil, nil, sup, nil, nil, nil)
	resp := rpcCtx(t, viewerCtx(), h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"suppress_finding","arguments":{"finding_id":"f1","reason":"nope"}}}`)
	require.NotNil(t, resp.Error)
	require.Equal(t, codeForbidden, resp.Error.Code)
	require.Empty(t, sup.gotID) // service never called
}

func TestToolsCall_SuppressFinding_Unauthenticated(t *testing.T) {
	sup := &fakeSuppress{}
	h := NewHandler(fakeAssets{}, fakeFindings{}, fakeFindingCtx{}, fakeCompliance{}, fakeGraph{}, nil, nil, sup, nil, nil, nil)
	resp := rpcCtx(t, context.Background(), h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"suppress_finding","arguments":{"finding_id":"f1","reason":"nope"}}}`)
	require.NotNil(t, resp.Error)
	require.Equal(t, codeForbidden, resp.Error.Code)
	require.Empty(t, sup.gotID)
}

func TestUnknownMethod(t *testing.T) {
	resp := rpc(t, newHandler(), `{"jsonrpc":"2.0","id":1,"method":"frobnicate"}`)
	require.NotNil(t, resp.Error)
	require.Equal(t, codeMethodNotFound, resp.Error.Code)
}

func TestParseError(t *testing.T) {
	resp := rpc(t, newHandler(), `not json`)
	require.NotNil(t, resp.Error)
	require.Equal(t, codeParse, resp.Error.Code)
}

func TestToolsCall_SearchAssets(t *testing.T) {
	resp := rpc(t, newHandler(), `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_assets","arguments":{"query":"web"}}}`)
	require.Nil(t, resp.Error)
	text := resp.Result.(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	require.Contains(t, text, "a1")
}

func TestToolsCall_SearchAssets_MissingQ(t *testing.T) {
	resp := rpc(t, newHandler(), `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_assets","arguments":{}}}`)
	require.NotNil(t, resp.Error)
}

func TestToolsList_IncludesNewTools(t *testing.T) {
	resp := rpc(t, newHandler(), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	require.Nil(t, resp.Error)
	tools := resp.Result.(map[string]any)["tools"].([]any)
	names := map[string]bool{}
	for _, tl := range tools {
		names[tl.(map[string]any)["name"].(string)] = true
	}
	require.True(t, names["search_assets"], "search_assets must be registered")
}
