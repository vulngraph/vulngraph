package throughput

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// These are logical rows; version churn adds physical rows separately.
type profile struct {
	Name        string `json:"name"`
	Workloads   uint64 `json:"workloads"`
	Images      uint64 `json:"images"`
	Groups      uint64 `json:"groups"`
	Packages    uint64 `json:"packages"`
	Memberships uint64 `json:"package_memberships"`
}

func dataset(name string) (profile, error) {
	p := profile{Name: name}
	switch name {
	case "smoke":
		p.Workloads, p.Packages, p.Memberships = 1000, 1000, 20000
	case "medium":
		p.Workloads, p.Packages, p.Memberships = 20000, 10000, 2000000
	case "core", "2m", "20m":
		p.Workloads, p.Packages = 600000, 50000
		if name == "2m" {
			p.Memberships = 2000000
		}
		if name == "20m" {
			p.Memberships = 20000000
		}
	default:
		return p, fmt.Errorf("unknown profile %q; choose smoke, medium, core, 2m or 20m", name)
	}
	p.Images, p.Groups = p.Workloads/20, p.Workloads/10
	return p, nil
}

func (p profile) coreEdges() uint64 { return 3*p.Workloads + 2*p.Groups + p.Groups/2 }

func TestProfilesHaveUniqueMembershipCapacity(t *testing.T) {
	for _, name := range []string{"smoke", "medium", "core", "2m", "20m"} {
		p, err := dataset(name)
		require.NoError(t, err)
		require.LessOrEqual(t, (p.Memberships+p.Images-1)/p.Images, p.Packages,
			"each image must have enough distinct packages; duplicate edges inflate throughput")
	}
	p, err := dataset("20m")
	require.NoError(t, err)
	require.EqualValues(t, 1950000, p.coreEdges())
	require.EqualValues(t, 20000000, p.Memberships)
	_, err = dataset("typo")
	require.Error(t, err)
}
