package mcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/diskscan"
)

type fakeDiskRuns struct {
	runs []diskscan.DiskScanRun
	vols []diskscan.VolumeResult
}

func (f fakeDiskRuns) ListRuns(context.Context, string, int) ([]diskscan.DiskScanRun, error) {
	return f.runs, nil
}

func (f fakeDiskRuns) AssetVolumes(context.Context, string) ([]diskscan.VolumeResult, error) {
	return f.vols, nil
}

type fakeDiskStamps struct {
	state, gap string
	err        error
}

func (f fakeDiskStamps) DiskScanStamp(context.Context, string) (string, string, error) {
	return f.state, f.gap, f.err
}

func diskHandler(r fakeDiskRuns, s fakeDiskStamps) *Handler {
	return newHandler().WithDiskScan(r, s)
}

func TestGetDiskScanStatus_ViewerSeesUnreadDiskAsUnknown(t *testing.T) {
	h := diskHandler(fakeDiskRuns{}, fakeDiskStamps{state: "not_enabled", gap: diskscan.GapNotEnabled})
	out := fencedBody(t, rpcCtx(t, viewerCtx(), h, toolCall(t, "get_disk_scan_status", map[string]any{"asset_id": "i-1"})))
	require.Equal(t, "not_enabled", out["state"])
	require.Equal(t, "not_enabled", out["gap"])
	require.Empty(t, out["volumes"])
}

func TestGetDiskScanStatus_ScannedVolume(t *testing.T) {
	vols := []diskscan.VolumeResult{{VolumeRef: "vol-1", SnapshotSource: diskscan.SourceReused, InventoryKnown: true,
		PackageCount: 312, ObservedAt: time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)}}
	h := diskHandler(fakeDiskRuns{vols: vols}, fakeDiskStamps{state: "scanned"})
	out := fencedBody(t, rpcCtx(t, viewerCtx(), h, toolCall(t, "get_disk_scan_status", map[string]any{"asset_id": "i-1"})))
	v := out["volumes"].([]any)[0].(map[string]any)
	require.Equal(t, "reused", v["snapshot_source"])
	require.EqualValues(t, 312, v["package_count"])
}

func TestGetDiskScanStatus_UnknownAssetIsInvalidParams(t *testing.T) {
	h := diskHandler(fakeDiskRuns{}, fakeDiskStamps{err: diskscan.ErrNotFound})
	resp := rpcCtx(t, viewerCtx(), h, toolCall(t, "get_disk_scan_status", map[string]any{"asset_id": "nope"}))
	require.NotNil(t, resp.Error)
}

func TestGetDiskScanStatus_WithoutAssetListsRuns(t *testing.T) {
	runs := []diskscan.DiskScanRun{{ID: "r1", ConnectorID: "c1", Status: diskscan.StatusPartial}}
	h := diskHandler(fakeDiskRuns{runs: runs}, fakeDiskStamps{err: errors.New("unused")})
	out := fencedBody(t, rpcCtx(t, viewerCtx(), h, toolCall(t, "get_disk_scan_status", nil)))
	require.Equal(t, "partial", out["runs"].([]any)[0].(map[string]any)["status"])
}

func TestGetDiskScanStatus_IsListedAndOffersNoWriteTool(t *testing.T) {
	h := diskHandler(fakeDiskRuns{}, fakeDiskStamps{})
	names := toolNames(rpcCtx(t, viewerCtx(), h, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	require.Contains(t, names, "get_disk_scan_status")
	for _, n := range names {
		require.NotContains(t, n, "disk_scan_mode")
		require.NotContains(t, n, "enable_disk")
	}
}

func TestGetDiskScanStatus_InventoryKeyRefused(t *testing.T) {
	h := diskHandler(fakeDiskRuns{}, fakeDiskStamps{state: "none"})
	resp := rpcCtx(t, inventoryKeyCtx(auth.ScopeInventory, auth.RoleViewer), h, toolCall(t, "get_disk_scan_status", map[string]any{"asset_id": "i-1"}))
	require.NotNil(t, resp.Error)
}
