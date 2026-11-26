package enrich

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPackageExposureUsesRuntimeReach(t *testing.T) {
	const pkg = "pkg:npm/example@1.0.0"
	lineage := containerWorkloadLineage(pkg, "image/sha256:example", "cluster/pod/app/web", false)
	tests := []struct {
		name             string
		reach            ReachProvider
		exposed, unknown bool
	}{
		{"ingress reaches pod", fakeReach{hops: 3, ok: true}, true, false},
		{"complete graph finds no path", fakeReach{hops: reachNone, ok: true}, false, false},
		{"graph unavailable", nil, false, true},
		{"node absent from graph", fakeReach{ok: false}, false, true},
		{"lookup failed", fakeReach{err: errors.New("unavailable")}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deployed, exposed, unknown, err := (SupplyChainExposure{Graph: lineage, Reach: tt.reach}).PackageDeployExposure(context.Background(), pkg)
			require.NoError(t, err)
			require.True(t, deployed)
			require.Equal(t, tt.exposed, exposed)
			require.Equal(t, tt.unknown, unknown)
		})
	}
}
