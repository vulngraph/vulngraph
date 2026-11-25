package aws

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// regionalFn is a list-and-emit regional collector. partial reports that a
// sub-listing failed while the primary listing succeeded: the assets are
// real, but the sweep must not read anything missing as deleted.
type regionalFn func(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) (assets []asset.Asset, partial bool, err error)

// simpleFn is a regional collector with no partial outcome.
type simpleFn func(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error)

func whole(fn simpleFn) regionalFn {
	return func(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, bool, error) {
		assets, err := fn(ctx, cfg, region, accountID, now)
		return assets, false, err
	}
}

// regionalService is one list-and-emit regional collector (regionalServices,
// regional_catalogue.go). Each runs once per region as its own best-effort
// task: an unused service lists nothing and emits no asset, so it produces no
// finding; a failed listing is a skipped collector (the sweep goes partial),
// never an empty one.
type regionalService struct {
	name string
	fn   regionalFn
	// host is the service's standard endpoint host in a region; an NXDOMAIN
	// for exactly that host may read as "not offered here"
	// (regional_offered.go). No collector judges a DNS failure itself.
	host func(region string) string
	// regionLimited marks a service AWS does not run in every commercial
	// region. Only such a service may be withdrawn as not offered; for any
	// other an NXDOMAIN is a DNS firewall or proxy and a skipped collector.
	// Unsure means false: the service fails closed.
	regionLimited bool
	// family and types name the enumeration a nil error proves complete
	// (collect.Result.MarkComplete). A collector may set them only when every
	// page of its listing either succeeded or failed the call: a per-resource
	// read that fails leaves that resource's keys absent but the listing whole.
	// A partial outcome never marks the family complete.
	family string
	types  []string
	// proves is the capability a successful run proves
	// (collect.Result.MarkCapabilityProven). A run that returns
	// errCapabilityUnproven was denied a permission never yet proven for the
	// connector: it is skipped without flagging the sweep partial.
	proves string
}

// regionalHooks are the region loop's closures a regional service task
// reports through (collectAll, aws.go).
type regionalHooks struct {
	skip       func(err error, region, what string)
	notOffered func(err error, what string)
	// unproven records a run denied a capability never yet proven
	// (errCapabilityUnproven): neither success nor failure.
	unproven func()
	complete func(region, family string, types []string, n int)
	// add records a successful run's assets; partial and proven carry its
	// partial outcome and the capability it proved.
	add func(assets []asset.Asset, partial bool, proven string)
}

// regionalServiceTasks builds one task per regionalServices entry for one
// region. A task whose listing failed only because the service's endpoint
// does not resolve reports notOffered, and the region decides once all tasks
// have run whether that means "none here" (regionLedger.settle); any other
// failure is a skip.
func regionalServiceTasks(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time, h regionalHooks) []func() {
	awsCfg, err := baseConfig(ctx, cfg)
	overridden := err != nil || endpointsOverridden(awsCfg)
	tasks := make([]func(), 0, len(regionalServices))
	for _, svc := range regionalServices {
		tasks = append(tasks, func() {
			more, partial, err := svc.fn(ctx, cfg, region, accountID, now)
			switch {
			case errors.Is(err, errCapabilityUnproven):
				h.unproven()
			case err != nil && svc.regionLimited && !overridden && endpointNotFound(err, svc.host(region)):
				h.notOffered(err, svc.name+" service")
			case err != nil:
				h.skip(err, region, svc.name+" service")
			default:
				h.add(more, partial, svc.proves)
				if svc.family != "" && !partial {
					h.complete(region, svc.family, svc.types, countTypes(more, svc.types))
				}
			}
		})
	}
	return tasks
}

func countTypes(assets []asset.Asset, types []string) int {
	n := 0
	for _, a := range assets {
		if slices.Contains(types, a.Type) {
			n++
		}
	}
	return n
}
