package benchconfig

import (
	"os"
	"testing"
)

// MaxSize bounds the PR fixture while keeping the full local/manual profile.
func MaxSize(t *testing.T) int {
	t.Helper()
	switch os.Getenv("PERF_CONNECTOR_MAX") {
	case "", "10000":
		return 10000
	case "1000":
		return 1000
	case "100":
		return 100
	default:
		t.Fatal("PERF_CONNECTOR_MAX must be 100, 1000 or 10000")
		return 0
	}
}
