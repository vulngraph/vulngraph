package gcp

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/testutil/collectbench"
)

func TestConnectorScale(t *testing.T) {
	sizes := collectbench.Sizes(t)
	// No ambient ADC: unrelated service factories must fail locally rather
	// than contact a developer's cloud account. The scope label records this.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "absent.json"))
	for _, n := range sizes {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			f := &fakeCompute{}
			for i := range n {
				f.instances = append(f.instances, gceInstance{Name: fmt.Sprintf("vm-%d", i), Zone: "europe-west4-a", Machine: "e2-small", Status: "RUNNING", Network: "default", PrivateIP: fmt.Sprintf("10.%d.%d.%d", i/65536, i/256%256, i%256), Labels: map[string]string{"env": "benchmark"}})
			}
			c := withFake(f)
			collectbench.Run(t, "gcp", "Compute mapping and partial-sweep handling; other APIs unavailable", "gce_instance", n, func() { f.projCalls = 0 }, func() (collect.Result, int, error) {
				r, err := c.Collect(context.Background(), nil)
				return r, 1 + f.projCalls, err
			})
		})
	}
}
