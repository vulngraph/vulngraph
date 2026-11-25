package mcp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/pkginv"
)

type fakeSubmitter struct {
	calls []pkginv.Request
	got   pkginv.Principal
	rec   pkginv.InventoryRecord
	err   error
}

func (f *fakeSubmitter) Submit(_ context.Context, p pkginv.Principal, _ string, req pkginv.Request) (pkginv.InventoryRecord, error) {
	f.got = p
	f.calls = append(f.calls, req)
	if !p.MaySubmit() {
		return pkginv.InventoryRecord{}, pkginv.ErrForbidden
	}
	return f.rec, f.err
}

func inventoryKeyCtx(scope string, owner auth.Role) context.Context {
	ctx := auth.ContextWithUser(context.Background(), auth.User{ID: "u1", Role: auth.RoleViewer})
	return auth.ContextWithAPIKey(ctx, auth.APIKeyRecord{ID: "key-a", UserID: "u1", Scope: scope, OwnerRole: owner})
}

func inventoryArgs() map[string]any {
	return map[string]any{
		"cloud_resource_id": "i-0abc",
		"os":                map[string]any{"id": "ubuntu", "version_id": "22.04"},
		"observed_at":       "2026-11-25T11:00:00Z",
		"scanner":           map[string]any{"name": "acme-agent", "version": "1.4.2"},
		"complete":          true,
		"packages":          []any{map[string]any{"name": "bash", "version": "5.1", "source_name": "bash"}},
	}
}

func inventoryHandler(sub *fakeSubmitter) *Handler {
	return newHandler().WithPackageInventory(sub)
}

func TestSubmitPackageInventory_InventoryKeyAccepted(t *testing.T) {
	sub := &fakeSubmitter{rec: pkginv.InventoryRecord{AssetID: "i-0abc", Source: "byoa:key-a:acme-agent", InventoryKnown: true, CVEMatchableKnown: true}}
	h := inventoryHandler(sub)
	resp := rpcCtx(t, inventoryKeyCtx("inventory", auth.RoleAdmin), h, toolCall(t, toolSubmitPackageInventory, inventoryArgs()))
	out := fencedBody(t, resp)
	require.Equal(t, true, out["accepted"])
	require.Equal(t, "i-0abc", out["asset_id"])
	require.Equal(t, true, out["inventory_known"])
	require.Len(t, sub.calls, 1)
	require.Equal(t, "i-0abc", sub.calls[0].CloudResourceID)
	require.Equal(t, "key-a", sub.got.KeyID)
}

func TestSubmitPackageInventory_WrongScope_Refused(t *testing.T) {
	for name, ctx := range map[string]context.Context{
		"session admin":     auth.ContextWithUser(context.Background(), auth.User{ID: "u1", Role: auth.RoleAdmin}),
		"unauthenticated":   context.Background(),
		"read key":          inventoryKeyCtx("read", auth.RoleAdmin),
		"write key":         inventoryKeyCtx("write", auth.RoleAdmin),
		"admin key":         inventoryKeyCtx("admin", auth.RoleAdmin),
		"owner demoted":     inventoryKeyCtx("inventory", auth.RoleViewer),
		"owner now analyst": inventoryKeyCtx("inventory", auth.RoleAnalyst),
	} {
		t.Run(name, func(t *testing.T) {
			h := inventoryHandler(&fakeSubmitter{})
			resp := rpcCtx(t, ctx, h, toolCall(t, toolSubmitPackageInventory, inventoryArgs()))
			require.NotNil(t, resp.Error)
			require.Equal(t, codeForbidden, resp.Error.Code)
		})
	}
}

func TestSubmitPackageInventory_StrictSchema(t *testing.T) {
	h := inventoryHandler(&fakeSubmitter{})
	ctx := inventoryKeyCtx("inventory", auth.RoleAdmin)
	for name, mutate := range map[string]func(map[string]any){
		"unknown top-level field": func(a map[string]any) { a["inventory_known"] = true },
		"unknown package field":   func(a map[string]any) { a["packages"] = []any{map[string]any{"name": "a", "version": "1", "cve": "x"}} },
	} {
		t.Run(name, func(t *testing.T) {
			args := inventoryArgs()
			mutate(args)
			resp := rpcCtx(t, ctx, h, toolCall(t, toolSubmitPackageInventory, args))
			require.NotNil(t, resp.Error)
			require.Equal(t, codeInvalidParams, resp.Error.Code)
		})
	}
}

func TestSubmitPackageInventory_ErrorMapping(t *testing.T) {
	ctx := inventoryKeyCtx("inventory", auth.RoleAdmin)
	for name, tc := range map[string]struct {
		err  error
		code int
	}{
		"not found":    {pkginv.ErrAssetNotFound, codeInvalidParams},
		"stale":        {pkginv.ErrStale, codeInvalidParams},
		"rate limited": {pkginv.ErrRateLimited, codeRateLimited},
	} {
		t.Run(name, func(t *testing.T) {
			h := inventoryHandler(&fakeSubmitter{err: tc.err})
			resp := rpcCtx(t, ctx, h, toolCall(t, toolSubmitPackageInventory, inventoryArgs()))
			require.NotNil(t, resp.Error)
			require.Equal(t, tc.code, resp.Error.Code)
		})
	}
}

// An inventory key maps to viewer, which would reach every read tool. It may
// call only submit_package_inventory, and sees only it in tools/list.
func TestInventoryKey_ConfinedToTheSubmitTool(t *testing.T) {
	h := inventoryHandler(&fakeSubmitter{})
	ctx := inventoryKeyCtx("inventory", auth.RoleAdmin)

	list := rpcCtx(t, ctx, h, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	require.Equal(t, []string{toolSubmitPackageInventory}, toolNames(list))

	resp := rpcCtx(t, ctx, h, toolCall(t, "list_findings", map[string]any{}))
	require.NotNil(t, resp.Error)
	require.Equal(t, codeForbidden, resp.Error.Code)

	other := rpcCtx(t, viewerCtx(), h, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	require.Greater(t, len(toolNames(other)), 1, "other callers still see every tool")
}
