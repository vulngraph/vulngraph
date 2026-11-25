package jobs

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// scripts/check-chart-schedule-env.sh fails CI when the rendered worker and
// scanner disagree on an env var PeriodicConfigFromEnv reads. Its list of vars
// is hand-written, so a key the derivation reads but the list omits (the feed
// switches behind FeedsFromEnv) can differ between the pods unnoticed. The list
// must be exactly the set of keys PeriodicConfigFromEnv reads.
func TestChartScheduleEnvCheckCoversPeriodicConfig(t *testing.T) {
	read := map[string]bool{}
	_, err := PeriodicConfigFromEnv(func(key string) string {
		read[key] = true
		return ""
	})
	require.NoError(t, err)

	src, err := os.ReadFile("../../scripts/check-chart-schedule-env.sh")
	require.NoError(t, err)
	m := regexp.MustCompile(`(?m)^vars=\(([^)]*)\)`).FindStringSubmatch(string(src))
	require.NotNil(t, m, "no vars=(...) line in check-chart-schedule-env.sh")
	listed := strings.Fields(m[1])
	sort.Strings(listed)

	want := make([]string, 0, len(read))
	for k := range read {
		want = append(want, k)
	}
	sort.Strings(want)
	require.Equal(t, want, listed,
		"check-chart-schedule-env.sh vars must be every env key PeriodicConfigFromEnv reads")
}
