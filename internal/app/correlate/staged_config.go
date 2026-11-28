package correlate

import (
	"fmt"
	"strconv"
	"strings"
)

// StagedViewLimitsFromEnv configures separate byte budgets. They are logical
// working-set/spool charges, not an assertion that Go heap or RSS equals them.
func StagedViewLimitsFromEnv(getenv func(string) string) (StagedViewLimits, error) {
	limits := DefaultStagedViewLimits()
	for _, setting := range []struct {
		name  string
		value *int64
	}{
		{"CORRELATE_INDEX_MIB", &limits.IndexBytes},
		{"CORRELATE_CONTEXT_MIB", &limits.ContextBytes},
		{"CORRELATE_SPOOL_MIB", &limits.DiskBytes},
		{"CORRELATE_OUTPUT_MIB", &limits.OutputBytes},
	} {
		text := strings.TrimSpace(getenv(setting.name))
		if text == "" {
			continue
		}
		value, err := strconv.ParseUint(text, 10, 32)
		if err != nil || value == 0 {
			return StagedViewLimits{}, fmt.Errorf("%s must be a positive integer MiB budget", setting.name)
		}
		*setting.value = int64(value) << 20
	}
	if limits.OutputBytes > limits.DiskBytes || limits.PageBytes > limits.DiskBytes {
		return StagedViewLimits{}, fmt.Errorf("correlation output and page budgets must fit CORRELATE_SPOOL_MIB")
	}
	return limits, nil
}
