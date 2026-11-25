package checks

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNodeFileFix_NamesTheCommandAndTheProduct(t *testing.T) {
	fix := nodeFileFix("/etc/kubernetes/kubelet.conf", "600", "root:root")
	require.Contains(t, fix, "chmod 600 /etc/kubernetes/kubelet.conf")
	require.Contains(t, fix, "chown root:root /etc/kubernetes/kubelet.conf")
	require.Contains(t, fix, "Vulngraph's node posture reader")
}
