package obs

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// chTuningFiles are every file that declares clickhouse.tuning. Helm merges the
// values maps key-by-key, so an env file that sets maxServerMemoryBytes but omits
// a cache ceiling silently inherits the base chart's — sized for a different
// memory limit entirely.
var chTuningFiles = []string{
	"../../deploy/helm-chart/graph/values.yaml",
	"../../deploy/helm-values/example.yaml",
}

// chCacheCeilingBudget is the share of max_server_memory_usage the caches may
// claim between them. They are charged against the same tracker as queries, so
// whatever they hold is not available to a SELECT.
const chCacheCeilingBudget = 0.40

type chValues struct {
	ClickHouse struct {
		Tuning struct {
			MaxServerMemoryBytes   string `yaml:"maxServerMemoryBytes"`
			MarkCacheBytes         string `yaml:"markCacheBytes"`
			IndexMarkCacheBytes    string `yaml:"indexMarkCacheBytes"`
			UncompressedCacheBytes string `yaml:"uncompressedCacheBytes"`
		} `yaml:"tuning"`
	} `yaml:"clickhouse"`
}

// TestCHCacheCeilingsLeaveRoomForQueries guards a defect that is invisible in
// every other way: the mark caches count against max_server_memory_usage, but
// their upstream defaults do not know what that number is, so left alone they
// can claim most of the server's memory budget before a single query runs.
//
// Against a squeezed budget, ordinary concurrent queries become fatal, and the
// failure has no symptom that points at the cause: it surfaces as a
// memory-limit-exceeded kill on whichever unrelated query the OvercommitTracker
// picks. Nothing in the Go tree, no metric, and no alert relates a cache
// ceiling to a server budget — this test is the only place that arithmetic is
// checked.
func TestCHCacheCeilingsLeaveRoomForQueries(t *testing.T) {
	for _, path := range chTuningFiles {
		t.Run(path, func(t *testing.T) {
			raw, err := os.ReadFile(path)
			require.NoError(t, err)

			var v chValues
			require.NoError(t, yaml.Unmarshal(raw, &v))
			tn := v.ClickHouse.Tuning

			if tn.MaxServerMemoryBytes == "" {
				t.Skip("declares no clickhouse.tuning.maxServerMemoryBytes")
			}

			// Every ceiling must be declared HERE, alongside the budget it is
			// sized against. Inheriting one across a values file means inheriting
			// it from a different memory limit.
			caches := map[string]string{
				"markCacheBytes":         tn.MarkCacheBytes,
				"indexMarkCacheBytes":    tn.IndexMarkCacheBytes,
				"uncompressedCacheBytes": tn.UncompressedCacheBytes,
			}
			var sum int64
			for name, val := range caches {
				require.NotEmptyf(t, val,
					"%s sets maxServerMemoryBytes but not %s. Helm merges key-by-key, so this "+
						"file inherits the base chart's ceiling — sized for the base chart's "+
						"memory limit, not this one. Declare it next to the budget it spends.",
					path, name)
				sum += mustParseBytes(t, name, val)
			}

			budget := mustParseBytes(t, "maxServerMemoryBytes", tn.MaxServerMemoryBytes)
			limit := int64(float64(budget) * chCacheCeilingBudget)
			require.LessOrEqualf(t, sum, limit,
				"%s: cache ceilings total %d bytes of a %d-byte server budget (%.0f%%, cap %.0f%%). "+
					"Caches are charged to the same tracker as queries, so this is memory a SELECT "+
					"cannot have — and the symptom is a code-241 kill on an unrelated query, never "+
					"on the cache.",
				path, sum, budget, 100*float64(sum)/float64(budget), 100*chCacheCeilingBudget)
		})
	}
}

func mustParseBytes(t *testing.T, name, val string) int64 {
	t.Helper()
	var n int64
	_, err := fmt.Sscanf(val, "%d", &n)
	require.NoErrorf(t, err, "%s is not a plain byte count: %q (quote it in YAML so it cannot "+
		"render as a float or in scientific notation)", name, val)
	require.Positivef(t, n, "%s must be positive, got %d", name, n)
	return n
}
