package k8sns

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigMapSkipped(t *testing.T) {
	require.True(t, ConfigMapSkipped("kube-system"))
	require.False(t, ConfigMapSkipped("payments"))

	got := ConfigMapSkippedNamespaces()
	got["payments"] = true
	require.False(t, ConfigMapSkipped("payments"), "the returned set is a copy")
}
