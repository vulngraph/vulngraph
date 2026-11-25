package jobs

import (
	"errors"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/internal/intel/updateinfo"
	"github.com/vulngraph/vulngraph/pkg/egress"
)

// Opt-out switches for the outbound feeds the worker runs by default, parsed by
// egress.Disabled (envswitch.Parse spellings; an unrecognised value is a startup
// error); egress.OfflineEnv (OFFLINE_MODE=true) turns them all off at once. docs/configuration.md#network-egress is the operator-facing list.
const (
	KEVDisabledEnv           = "INTEL_KEV_DISABLED"      // CISA KEV catalog
	EPSSDisabledEnv          = "INTEL_EPSS_DISABLED"     // FIRST.org EPSS scores
	MalFeedDisabledEnv       = "INTEL_MALFEED_DISABLED"  // OSV malicious-packages feed on GitHub
	OSVDisabledEnv           = "INTEL_OSV_DISABLED"      // api.osv.dev package queries
	ALASDisabledEnv          = "INTEL_ALAS_DISABLED"     // Amazon Linux advisories (cdn.amazonlinux.com updateinfo)
	ELSADisabledEnv          = "INTEL_ELSA_DISABLED"     // Oracle Linux advisories (yum.oracle.com updateinfo)
	DomainMonitorDisabledEnv = "DOMAIN_MONITOR_DISABLED" // crt.sh certificate-transparency lookups
)

// Feeds says which default-on outbound feeds are enabled. True means enabled, so
// the zero value is "everything off" and a forgotten field fails closed.
//
// Both the worker (cmd/graph builds its deps from it) and the scanner
// (PeriodicConfigFromEnv) read the switches through FeedsFromEnv, so the two
// leader-electable pods cannot disagree about which feeds exist.
type Feeds struct {
	KEV           bool
	EPSS          bool
	MalFeed       bool
	OSV           bool
	ALAS          bool
	ELSA          bool
	DomainMonitor bool
}

// FeedsFromEnv reads the per-feed switches and OFFLINE_MODE. An unrecognised
// value in any of them is an error, returned with every feed off.
func FeedsFromEnv(getenv func(string) string) (Feeds, error) {
	var errs []error
	on := func(key string) bool {
		off, err := egress.Disabled(getenv, key)
		if err != nil {
			errs = append(errs, err)
		}
		return !off
	}
	f := Feeds{
		KEV:           on(KEVDisabledEnv),
		EPSS:          on(EPSSDisabledEnv),
		MalFeed:       on(MalFeedDisabledEnv),
		OSV:           on(OSVDisabledEnv),
		ALAS:          on(ALASDisabledEnv),
		ELSA:          on(ELSADisabledEnv),
		DomainMonitor: on(DomainMonitorDisabledEnv),
	}
	if len(errs) > 0 {
		return Feeds{}, fmt.Errorf("FeedsFromEnv: %w", errors.Join(errs...))
	}
	return f, nil
}

// Disabled names the switched-off feeds by their env var, for the one startup
// log line that tells an operator what this pod will not fetch.
func (f Feeds) Disabled() []string {
	var out []string
	for _, feed := range []struct {
		on  bool
		env string
	}{
		{f.KEV, KEVDisabledEnv},
		{f.EPSS, EPSSDisabledEnv},
		{f.MalFeed, MalFeedDisabledEnv},
		{f.OSV, OSVDisabledEnv},
		{f.ALAS, ALASDisabledEnv},
		{f.ELSA, ELSADisabledEnv},
		{f.DomainMonitor, DomainMonitorDisabledEnv},
	} {
		if !feed.on {
			out = append(out, feed.env)
		}
	}
	return out
}

// DistroAdvisorySources is the releases the distro advisory refresh reads:
// Amazon Linux when ALAS is on, Oracle Linux when ELSA is on.
func (f Feeds) DistroAdvisorySources() []updateinfo.Source {
	var out []updateinfo.Source
	if f.ALAS {
		out = append(out, updateinfo.ALASSources()...)
	}
	if f.ELSA {
		out = append(out, updateinfo.ELSASources()...)
	}
	return out
}

// AdvisorySources is the advisory sources this deployment queries, for the VM
// inventory collectors' package_cve_gap: a VM on a distribution whose source is
// off is matched against nothing, which must not read as clean.
func (f Feeds) AdvisorySources() distro.Sources {
	return distro.Sources{distro.SourceOSV: f.OSV, distro.SourceALAS: f.ALAS, distro.SourceELSA: f.ELSA}
}
