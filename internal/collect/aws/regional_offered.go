package aws

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	smithyendpoints "github.com/aws/smithy-go/endpoints"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// A regional service AWS does not run in a region has no endpoint there: its
// hostname does not resolve. That is the only signal a read-only connector
// has (the authoritative SSM global-infrastructure parameters need
// ssm:GetParametersByPath, which neither SecurityAudit nor ViewOnlyAccess
// grants), and an NXDOMAIN is also what a DNS firewall, an allowlisting proxy,
// a FIPS or dual-stack endpoint that does not exist, or a mistyped custom
// endpoint produce. So an NXDOMAIN reads as "not offered here" only when all
// of these hold, and as an ordinary failed read (the sweep goes partial)
// otherwise:
//
//  1. the name that failed is exactly the service's standard endpoint host
//     for the region, as the SDK's own endpoint rules resolve it;
//  2. no FIPS, dual-stack or custom endpoint is configured, so that host is
//     the one the client really dialled;
//  3. the region's core EC2 read succeeded in the same sweep, so the region
//     itself is reachable through this network path (regionLedger.settle);
//  4. the service is region-limited (regionalService.regionLimited): one AWS
//     runs in every commercial region is never absent, so its NXDOMAIN is a
//     DNS firewall or proxy, never a withdrawal.
//
// Every withdrawal is logged (warnWithdrawn): a silent one would be
// indistinguishable from a clean read.

// endpointResolver is the shape every SDK client's default endpoint resolver
// has, so one helper reads the standard host for any service.
type endpointResolver[P any] interface {
	ResolveEndpoint(context.Context, P) (smithyendpoints.Endpoint, error)
}

// standardHost is the host the SDK's endpoint rules give for params (region
// only: FIPS and dual-stack off), or "" when they give none.
func standardHost[P any](r endpointResolver[P], params P) string {
	ep, err := r.ResolveEndpoint(context.Background(), params)
	if err != nil {
		return ""
	}
	return ep.URI.Hostname()
}

// endpointNotFound reports whether err is NXDOMAIN for exactly host.
func endpointNotFound(err error, host string) bool {
	if host == "" {
		return false
	}
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound &&
		strings.EqualFold(strings.TrimSuffix(dnsErr.Name, "."), host)
}

// endpointsOverridden reports whether the sweep's AWS config can send a client
// anywhere but the standard regional endpoint: a base endpoint, a
// service-specific endpoint URL, or FIPS / dual-stack, from code, the
// environment or the shared config file.
func endpointsOverridden(cfg awssdk.Config) bool {
	if cfg.BaseEndpoint != nil {
		return true
	}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "AWS_ENDPOINT_URL") {
			return true
		}
	}
	for _, src := range cfg.ConfigSources {
		switch s := src.(type) {
		case config.EnvConfig:
			if s.UseFIPSEndpoint == awssdk.FIPSEndpointStateEnabled || s.UseDualStackEndpoint == awssdk.DualStackEndpointStateEnabled || s.BaseEndpoint != "" {
				return true
			}
		case config.SharedConfig:
			if s.UseFIPSEndpoint == awssdk.FIPSEndpointStateEnabled || s.UseDualStackEndpoint == awssdk.DualStackEndpointStateEnabled ||
				s.BaseEndpoint != "" || len(s.Services.ServiceValues) > 0 {
				return true
			}
		}
	}
	return false
}

// regionLedger holds one region's provisional "not offered" verdicts until
// every task has run, because rule 3 needs the core EC2 read's outcome.
type regionLedger struct {
	mu         sync.Mutex
	coreOK     bool
	candidates []regionFailure
	// unprovenTasks ran but proved nothing either way: denied a capability
	// never yet proven for the connector (errCapabilityUnproven).
	unprovenTasks int
	withdrawn     []regionFailure
}

// coreSucceeded records that the region's EC2 instance listing succeeded.
func (l *regionLedger) coreSucceeded() {
	l.mu.Lock()
	l.coreOK = true
	l.mu.Unlock()
}

// notOffered records a task whose endpoint did not resolve (rules 1 and 2
// already held).
func (l *regionLedger) notOffered(err error, what string) {
	l.mu.Lock()
	l.candidates = append(l.candidates, regionFailure{err: err, what: what})
	l.mu.Unlock()
}

// unproven records a task skipped as errCapabilityUnproven. It is neither a
// success nor a failure, so it leaves the region's task count: otherwise a
// deny-SCP region, where that task too was refused, never reads as denied.
func (l *regionLedger) unproven() {
	l.mu.Lock()
	l.unprovenTasks++
	l.mu.Unlock()
}

// settle judges the region once all its tasks have run. With the core read up,
// each not-offered task is withdrawn from the task count and the sweep tally.
// Otherwise the candidates are ordinary failures — except in a region every
// other task was denied in (a deny SCP), which is denied as a whole and
// excluded from coverage, so the candidates change nothing there.
func (l *regionLedger) settle(tasks int, failures []regionFailure, tally *sweepTally) (denied bool, report []regionFailure) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for range l.unprovenTasks {
		tally.withdraw()
	}
	offered := tasks - len(l.candidates) - l.unprovenTasks
	if l.coreOK {
		for range l.candidates {
			tally.withdraw()
		}
		l.withdrawn = l.candidates
		return regionDenied(offered, failures), failures
	}
	if regionDenied(offered, failures) {
		return true, failures
	}
	for _, c := range l.candidates {
		tally.failed(c.err)
	}
	return false, append(failures, l.candidates...)
}

// warnWithdrawn logs every service settle withdrew as not offered, with the
// host that did not resolve, so a withdrawal is never silent.
func (l *regionLedger) warnWithdrawn(ctx context.Context, region string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.withdrawn {
		host := ""
		var dnsErr *net.DNSError
		if errors.As(c.err, &dnsErr) {
			host = dnsErr.Name
		}
		log.FromContext(ctx).Warn().Str("region", region).Str("service", c.what).Str("host", host).
			Msg("regional service endpoint does not resolve; withdrawn as not offered in this region")
	}
}
