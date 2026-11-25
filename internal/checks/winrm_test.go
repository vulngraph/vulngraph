package checks

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// WinRM joined the admin-port set; the Azure NSG sibling has its own check.
func TestAWSAdminPortsIncludeWinRM(t *testing.T) {
	sg := func(port int) asset.Asset {
		rules := `[{"protocol":"tcp","from_port":` + strconv.Itoa(port) + `,"to_port":` + strconv.Itoa(port) + `,"cidrs":["0.0.0.0/0"]}]`
		return asset.Asset{Metadata: map[string]string{"ingress": rules}}
	}
	for _, p := range []int{22, 3389, 5985, 5986} {
		require.True(t, sgWorldOpenAdminPort(sg(p)), "port %d", p)
	}
	require.False(t, sgWorldOpenAdminPort(sg(443)))
}
