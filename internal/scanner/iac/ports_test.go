package iac

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The IaC scanner's management-port set must match the runtime check's
// (internal/checks adminPorts), or a world-open WinRM rule is High in the live
// security group and Medium in the Terraform that created it.
func TestPortSeverity_ManagementPorts(t *testing.T) {
	num := func(n int64) Value { return Value{Kind: "number", Num: n} }
	for _, p := range []int64{22, 3389, 5985, 5986} {
		sev, detail := portSeverity(num(p), num(p))
		require.Equal(t, SeverityHigh, sev, "port %d", p)
		require.Contains(t, detail, "0.0.0.0/0")
	}
	sev, _ := portSeverity(num(443), num(443))
	require.Equal(t, SeverityMedium, sev)
}
