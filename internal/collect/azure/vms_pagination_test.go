package azure

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/testutil/collectbench"
)

func TestVMEnumerationExhaustsPagesOrFailsClosed(t *testing.T) {
	for _, mode := range []string{"complete", "empty", "late_forbidden", "missing_identity", "missing_list", "duplicate", "repeated_link", "unread_nic", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			pages := 0
			const prefix = "/subscriptions/sub/resourceGroups/rg/providers/"
			opts := readOnlyARM()
			opts.Retry.MaxRetries = -1
			opts.Transport = collectbench.Transport(func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, "/networkInterfaces/") {
					res := collectbench.Response(req, `{"error":{"code":"AuthorizationFailed","message":"fixture denial"}}`)
					res.StatusCode = http.StatusForbidden
					return res, nil
				}
				pages++
				if pages == 1 && mode == "empty" {
					return collectbench.Response(req, `{"value":[]}`), nil
				}
				if pages == 1 && mode == "missing_list" {
					return collectbench.Response(req, `{}`), nil
				}
				if pages == 2 && mode == "late_forbidden" {
					res := collectbench.Response(req, `{"error":{"code":"AuthorizationFailed","message":"fixture denial"}}`)
					res.StatusCode = http.StatusForbidden
					return res, nil
				}
				id := fmt.Sprintf("%sMicrosoft.Compute/virtualMachines/vm-%d", prefix, pages)
				if pages == 2 && mode == "duplicate" {
					id = prefix + "Microsoft.Compute/virtualMachines/vm-1"
				}
				if mode == "missing_identity" {
					id = ""
				}
				next := ""
				if pages == 1 || mode == "repeated_link" {
					next = `,"nextLink":"https://management.azure.com/subscriptions/sub/providers/Microsoft.Compute/virtualMachines?page=2"`
				}
				nic := ""
				if mode == "unread_nic" {
					nic = fmt.Sprintf(`,"properties":{"networkProfile":{"networkInterfaces":[{"id":%q}]}}`, prefix+"Microsoft.Network/networkInterfaces/nic")
				}
				return collectbench.Response(req, fmt.Sprintf(`{"value":[{"id":%q%s}]%s}`, id, nic, next)), nil
			})
			if mode == "cancelled" {
				cancel()
			}
			got, _, err := collectVMs(ctx, fakeCred{}, "sub", time.Now(), opts)
			if mode != "complete" && mode != "empty" && mode != "unread_nic" {
				require.Error(t, err)
				require.Empty(t, got)
				return
			}
			require.NoError(t, err)
			if mode == "empty" {
				require.Empty(t, got)
				return
			}
			require.Len(t, got, 2)
			require.Equal(t, 2, pages)
			if mode == "unread_nic" {
				for _, vm := range got {
					require.True(t, asset.PublicIPUnread(vm))
					require.NotContains(t, vm.Metadata, "direct_public_ip")
				}
			}
		})
	}
}
