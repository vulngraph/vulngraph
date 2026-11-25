package mcp

// Disk scan status: one read tool. Turning disk scanning on is an admin's
// standing approval and is made only through the session-only REST route, so
// nothing in this file can change a connector or start a scan.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/diskscan"
)

// WithDiskScan registers get_disk_scan_status. Called only when the disk-scan
// store is wired.
func (h *Handler) WithDiskScan(runs diskscan.Runs, stamps diskscan.AssetStamps) *Handler {
	h.register(tool{
		Name: "get_disk_scan_status",
		Description: "Whether and how a VM's disk was read by agentless disk scanning. With asset_id: state scanned, not_enabled or none, a gap reason, " +
			"and the latest result per volume (snapshot source, observed time, package count). Without asset_id: the most recent disk scan runs. " +
			"not_enabled and none mean the disk was NOT read: they are unknown, never 'no vulnerabilities'. Read-only; enabling disk scanning is done by an admin in the UI.",
		InputSchema: objSchema(map[string]any{
			"asset_id": strProp("the VM's asset id; omit to list recent runs"),
		}),
		handler: func(ctx context.Context, args map[string]any) (any, error) {
			id, _ := args["asset_id"].(string)
			if strings.TrimSpace(id) == "" {
				list, err := runs.ListRuns(ctx, "", 20)
				if err != nil {
					return nil, fmt.Errorf("get_disk_scan_status: %w", err)
				}
				out := make([]diskscan.RunResponse, len(list))
				for i, r := range list {
					out[i] = diskscan.ToRunResponse(r)
				}
				return map[string]any{"runs": out}, nil
			}
			state, gap, err := stamps.DiskScanStamp(ctx, id)
			if errors.Is(err, diskscan.ErrNotFound) {
				return nil, fmt.Errorf("%w: no asset with that asset_id", errInvalidParams)
			}
			if err != nil {
				return nil, fmt.Errorf("get_disk_scan_status: %w", err)
			}
			vols, err := runs.AssetVolumes(ctx, id)
			if err != nil {
				return nil, fmt.Errorf("get_disk_scan_status: %w", err)
			}
			return diskscan.BuildAsset(id, state, gap, vols), nil
		},
	})
	return h
}
