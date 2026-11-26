package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/testutil/collectbench"
)

func TestVMNICConcurrencyIsBoundedOrderedAndCancelable(t *testing.T) {
	const prefix = "/subscriptions/sub/resourceGroups/rg/providers/"
	for _, cancelEarly := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelEarly), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var active, peak atomic.Int64
			opts := readOnlyARM()
			opts.Transport = collectbench.Transport(func(req *http.Request) (*http.Response, error) {
				if strings.HasSuffix(req.URL.Path, "/virtualMachines") {
					var vms []map[string]any
					for i := range 40 {
						vms = append(vms, map[string]any{"id": fmt.Sprintf("%sMicrosoft.Compute/virtualMachines/vm-%d", prefix, i), "properties": map[string]any{"networkProfile": map[string]any{"networkInterfaces": []map[string]string{{"id": fmt.Sprintf("%sMicrosoft.Network/networkInterfaces/nic-%d", prefix, i)}}}}})
					}
					b, err := json.Marshal(map[string]any{"value": vms})
					return collectbench.Response(req, string(b)), err
				}
				if !strings.Contains(req.URL.Path, "/networkInterfaces/") {
					return nil, fmt.Errorf("unexpected path %s", req.URL.Path)
				}
				n := active.Add(1)
				defer active.Add(-1)
				for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
				}
				if cancelEarly {
					cancel()
				}
				select {
				case <-req.Context().Done():
					return nil, req.Context().Err()
				case <-time.After(5 * time.Millisecond):
				}
				return collectbench.Response(req, `{"properties":{"ipConfigurations":[]}}`), nil
			})
			got, _, err := collectVMs(ctx, fakeCred{}, "sub", time.Now(), opts)
			if cancelEarly {
				require.ErrorIs(t, err, context.Canceled)
				require.Empty(t, got)
			} else {
				require.NoError(t, err)
				require.Len(t, got, 40)
				require.Greater(t, peak.Load(), int64(1))
				require.LessOrEqual(t, peak.Load(), int64(8))
				for i, a := range got {
					require.Equal(t, fmt.Sprintf("%sMicrosoft.Compute/virtualMachines/vm-%d", prefix, i), a.ID)
				}
			}
			require.Zero(t, active.Load())
		})
	}
}

func TestSubnetResolverSharesConcurrentUnknownResult(t *testing.T) {
	var calls atomic.Int64
	lookup := subnetNSGResolver(func(string, string, string) (*armnetwork.Subnet, error) {
		calls.Add(1)
		return nil, context.DeadlineExceeded
	})
	var wg sync.WaitGroup
	var falselyKnown atomic.Int64
	for i := range 64 {
		wg.Go(func() {
			id := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/net/subnets/shared"
			if i%2 == 1 {
				id = strings.ToUpper(id)
			}
			nsg, known := lookup(id)
			if known || nsg != "" {
				falselyKnown.Add(1)
			}
		})
	}
	wg.Wait()
	require.Equal(t, int64(1), calls.Load())
	require.Zero(t, falselyKnown.Load())
}
