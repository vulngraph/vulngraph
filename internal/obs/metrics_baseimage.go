package obs

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Base-image identification coverage (ADR 088), pushed by the base-image job
// after every run. Split into its own file for metrics.go's 800-line ceiling.

// Base identity states of a running image, the label values of
// graph_base_image_running_images.
const (
	BaseIdentityAnnotation = "annotation"
	BaseIdentityOSRelease  = "os_release"
	BaseIdentityUnknown    = "unknown"
	BaseIdentityUnscanned  = "unscanned"
)

func newBaseImageRunning() *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Subsystem: "base_image", Name: "running_images",
		Help: "Running container images (a live container_image with a fresh runs_image edge) by base identity: annotation = the image names its base in its OCI annotations; os_release = only the base OS release is known; unknown = scanned, but nothing identifies the base (scratch/static, or no readable release); unscanned = the image-vuln sweep has no identity for it yet (never scanned, pull failing, or no package manifests at all). Coverage is (annotation + os_release) / sum. unknown and unscanned images are never graded by container-image-os-end-of-life and never grouped, so a rising share of them is lost visibility, not a cleaner estate.",
	}, []string{"identity"})
}

// ObserveBaseImageCoverage records how many running images are in each base
// identity state. counts is keyed by the BaseIdentity* constants; a state
// missing from counts is published as zero so a series never goes stale.
func (m *Metrics) ObserveBaseImageCoverage(counts map[string]int) {
	if m == nil {
		return
	}
	for _, state := range []string{BaseIdentityAnnotation, BaseIdentityOSRelease, BaseIdentityUnknown, BaseIdentityUnscanned} {
		m.baseImageRunning.WithLabelValues(state).Set(float64(counts[state]))
	}
}
