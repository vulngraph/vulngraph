package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/testutil/collectbench"
)

func TestConnectorScale(t *testing.T) {
	for _, n := range collectbench.Sizes(t) {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			var calls atomic.Int64
			const prefix = "/subscriptions/sub/resourceGroups/rg/providers/"
			transport := collectbench.Transport(func(req *http.Request) (*http.Response, error) {
				calls.Add(1)
				if req.Method != http.MethodGet || req.URL.Host != "management.azure.com" {
					return nil, fmt.Errorf("unexpected ARM fixture request %s %s", req.Method, req.URL)
				}
				path := req.URL.Path
				body := ""
				switch {
				case strings.HasSuffix(path, "/virtualMachines"):
					start, _ := strconv.Atoi(req.URL.Query().Get("skip"))
					var vms []map[string]any
					for i := start; i < min(start+100, n); i++ {
						vms = append(vms, map[string]any{"id": fmt.Sprintf("%sMicrosoft.Compute/virtualMachines/vm-%d", prefix, i), "name": fmt.Sprintf("vm-%d", i), "location": "westeurope", "properties": map[string]any{"networkProfile": map[string]any{"networkInterfaces": []map[string]string{{"id": fmt.Sprintf("%sMicrosoft.Network/networkInterfaces/nic-%d", prefix, i)}}}}})
					}
					page := map[string]any{"value": vms}
					if start+100 < n {
						next := *req.URL
						q := next.Query()
						q.Set("skip", fmt.Sprint(start+100))
						next.RawQuery = q.Encode()
						page["nextLink"] = next.String()
					}
					b, err := json.Marshal(page)
					if err != nil {
						return nil, err
					}
					body = string(b)
				case strings.Contains(path, "/networkInterfaces/"):
					body = fmt.Sprintf(`{"id":%q,"properties":{"ipConfigurations":[{"properties":{"privateIPAddress":"10.0.0.2","subnet":{"id":%q}}}]}}`, path, prefix+"Microsoft.Network/virtualNetworks/vnet/subnets/shared")
				case strings.HasSuffix(path, "/subnets/shared"):
					body = `{"properties":{"networkSecurityGroup":{"id":"nsg-shared"}}}`
				default:
					return nil, fmt.Errorf("unexpected ARM fixture path %s", path)
				}
				return collectbench.Response(req, body), nil
			})
			opts := readOnlyARM()
			opts.Transport = transport
			collectbench.Run(t, "azure", "real ARM SDK VM pagination, NIC and shared-subnet enrichment", "azure_vm", n, func() { calls.Store(0) }, func() (collect.Result, int, error) {
				a, e, err := collectVMs(context.Background(), fakeCred{}, "sub", time.Now(), opts)
				require.Equal(t, n+(n+99)/100+1, int(calls.Load()), "shared subnet must be fetched once")
				return collect.Result{Assets: a, Edges: e}, int(calls.Load()), err
			})
		})
	}
}
