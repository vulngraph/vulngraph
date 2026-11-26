package jobs

import (
	"fmt"

	"github.com/vulngraph/vulngraph/pkg/envswitch"
)

// Local-footprint kill switches, parsed by envswitch.Parse: an unrecognised
// value stops the pod at startup, so a typo is never silently read either way.
const (
	// ScanWorkerDisabledEnv stops the main worker from consuming the scan
	// queue; the dedicated scanner pod runs disk-volume reads instead.
	ScanWorkerDisabledEnv = "SCAN_WORKER_DISABLED"
	// ImageScanDisabledEnv turns off the container-image vulnerability sweep.
	ImageScanDisabledEnv = "IMAGE_SCAN_DISABLED"
	// AdjudicatorEnabledEnv turns on the LLM severity adjudicator sweep.
	AdjudicatorEnabledEnv = "ADJUDICATOR_ENABLED"
	// DriftAnalysisEnabledEnv turns on the advisory LLM drift analysis sweep.
	DriftAnalysisEnabledEnv = "DRIFT_ANALYSIS_ENABLED"
	// DiskScanEnabledEnv turns on the agentless VM disk scan jobs. Each
	// connector still has to opt in; this only decides whether the jobs exist.
	DiskScanEnabledEnv = "DISK_SCAN_ENABLED"
)

// SwitchFromEnv reads one of the switches above, or any other on/off switch
// held to the same strict parsing (REQUIRE_ADMIN_TOTP).
func SwitchFromEnv(getenv func(string) string, key string) (bool, error) {
	on, err := envswitch.Parse(getenv, key)
	if err != nil {
		return false, fmt.Errorf("SwitchFromEnv: %w", err)
	}
	return on, nil
}
