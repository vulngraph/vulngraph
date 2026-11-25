package obs

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Package departure outcomes, pushed by the package reconciles (OSV refresh,
// distro advisories) after every run. Split into its own file for metrics.go's
// 800-line ceiling.

// Outcomes of one reconcile's departure judgement, the label values of
// graph_package_departures.
const (
	DepartureFixed           = "fixed"
	DepartureGone            = "resource_gone"
	DepartureAgedOut         = "aged_out"
	DepartureWithheld        = "withheld_unproven"
	DepartureWithheldReadErr = "withheld_read_error"
)

func newPackageDepartures() *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Subsystem: "package", Name: "departures",
		Help: "Package findings on packages that left the live inventory, by the last run's outcome: fixed = an upgrade to a newer version was seen on the same runner or its fleet/image lineage; resource_gone = every runner was re-read without the package or proven deleted; aged_out = no runner evidence remains inside the edge TTL and the finding was last observed before it (the bounded fallback); withheld_unproven = some runner is neither re-read nor proven deleted (a producer outage reads exactly like this); withheld_read_error = the evidence could not be read this run. A withheld share that stays high is findings held open on missing evidence, not a clean estate.",
	}, []string{"job", "outcome"})
}

// ObservePackageDepartures records one reconcile's departure outcome counts,
// keyed by the Departure* constants; a missing outcome is published as zero.
func (m *Metrics) ObservePackageDepartures(job string, counts map[string]int) {
	if m == nil {
		return
	}
	for _, o := range []string{DepartureFixed, DepartureGone, DepartureAgedOut, DepartureWithheld, DepartureWithheldReadErr} {
		m.packageDepartures.WithLabelValues(job, o).Set(float64(counts[o]))
	}
}
