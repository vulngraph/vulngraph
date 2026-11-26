package demo

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/testutil/collectbench"
)

func TestConnectorScale(t *testing.T) {
	_ = collectbench.Sizes(t)
	c := New()
	r, err := c.Collect(context.Background(), nil)
	require.NoError(t, err)
	n := 0
	for _, a := range r.Assets {
		if a.Type == "ec2_instance" {
			n++
		}
	}
	collectbench.Run(t, "demo", "complete fixed built-in estate", "ec2_instance", n, func() {}, func() (collect.Result, int, error) { r, err := c.Collect(context.Background(), nil); return r, 0, err })
}
