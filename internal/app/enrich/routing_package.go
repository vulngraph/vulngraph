package enrich

import (
	"context"
	"fmt"
	"sort"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// A supply-chain package finding's resource is a purl: no tag, no defined_in,
// no namespace — so its own owner resolves to nobody and its environment to
// unknown, and every package alert landed on the unowned default with an
// env-scoped channel rejecting it. The package matters where it RUNS, so it
// routes to its runners: the most common owner among the internet-exposed ones
// (they are why it is urgent), else among any; the most production-like
// environment among the same set.

// maxRoutingRunners bounds the exposure probe over a package's runners; a base
// OS package can be installed on every host in the estate.
const maxRoutingRunners = 200

// maxOwnerRunners bounds the owner resolutions per package finding — each one
// is a defined_in read plus a repo read.
const maxOwnerRunners = 5

// RunnerLineage reads what runs a package. asset.Service implements it.
type RunnerLineage interface {
	EdgesInto(ctx context.Context, dstID, edgeType string) ([]asset.Edge, error)
	EdgesOutBatch(ctx context.Context, srcIDs []string, edgeType string) ([]asset.Edge, error)
	ByIDs(ctx context.Context, ids []string) ([]asset.Asset, error)
}

// WithPackageRunners routes supply-chain package findings to their runners'
// owner and environment. Without it they keep the purl's own (unowned,
// unknown) routing.
func WithPackageRunners(r RunnerLineage) Option {
	return func(s *Service) { s.runners = r }
}

// packageRouting resolves a package finding's owner and environment from its
// runners. Any failed read is an error — the caller leaves routing unresolved,
// never "unowned".
func (s *Service) packageRouting(ctx context.Context, f finding.Finding) (asset.Ownership, string, error) {
	var ids []string
	for _, et := range []string{"runs_package", "depends_on"} {
		edges, err := s.runners.EdgesInto(ctx, f.ResourceID, et)
		if err != nil {
			return asset.Ownership{}, "", fmt.Errorf("packageRouting: %s: %w", et, err)
		}
		ids = append(ids, uniqueSrcIDs(edges)...)
	}
	ids = uniqueStrings(ids)
	if len(ids) == 0 {
		return asset.Ownership{Source: asset.OwnerSourceNone}, string(asset.EnvUnknown), nil
	}
	sort.Strings(ids)
	ids = ids[:min(len(ids), maxRoutingRunners)]
	exp, err := s.runners.EdgesOutBatch(ctx, ids, "exposed_to_internet")
	if err != nil {
		return asset.Ownership{}, "", fmt.Errorf("packageRouting: exposure: %w", err)
	}
	exposed := map[string]bool{}
	for _, e := range exp {
		exposed[e.SrcID] = true
	}
	// Exposed runners first, each group in id order, so the pick is stable.
	sort.SliceStable(ids, func(i, j int) bool { return exposed[ids[i]] && !exposed[ids[j]] })
	pick := ids[:min(len(ids), maxOwnerRunners)]
	assets, err := s.runners.ByIDs(ctx, pick)
	if err != nil {
		return asset.Ownership{}, "", fmt.Errorf("packageRouting: runners: %w", err)
	}
	byID := make(map[string]asset.Asset, len(assets))
	for _, a := range assets {
		byID[a.ID] = a
	}

	var exposedRunners, allRunners []runnerRouting
	for _, id := range pick {
		a, ok := byID[id]
		if !ok {
			a = asset.Asset{ID: id} // not in inventory: defined_in may still name it
		}
		o, err := s.owners.ResolveOwner(ctx, a, s.ownerTagKeys)
		if err != nil {
			return asset.Ownership{}, "", fmt.Errorf("packageRouting: owner of %s: %w", id, err)
		}
		r := runnerRouting{id: id, owner: o, env: asset.ClassifyEnvironment(a).Env}
		allRunners = append(allRunners, r)
		if exposed[id] {
			exposedRunners = append(exposedRunners, r)
		}
	}
	owner, ok := commonOwner(exposedRunners)
	if !ok {
		owner, ok = commonOwner(allRunners)
	}
	if !ok {
		owner = asset.Ownership{Source: asset.OwnerSourceNone}
	}
	env := mostProdEnv(exposedRunners)
	if env == asset.EnvUnknown {
		env = mostProdEnv(allRunners)
	}
	return owner, string(env), nil
}

type runnerRouting struct {
	id    string
	owner asset.Ownership
	env   asset.Environment
}

// commonOwner picks the team owning the most runners (ties by name). The
// result keeps the tier that named it, with the runner in the evidence and
// confidence capped at medium: it is an inference one hop from the resource.
func commonOwner(rs []runnerRouting) (asset.Ownership, bool) {
	counts := map[string]int{}
	first := map[string]runnerRouting{}
	best := ""
	for _, r := range rs {
		if r.owner.Team == "" || r.owner.Unowned() {
			continue
		}
		t := r.owner.Team
		counts[t]++
		if _, ok := first[t]; !ok {
			first[t] = r
		}
		if best == "" || counts[t] > counts[best] || (counts[t] == counts[best] && t < best) {
			best = t
		}
	}
	if best == "" {
		return asset.Ownership{}, false
	}
	r := first[best]
	o := r.owner
	if o.Confidence == asset.OwnerConfidenceHigh {
		o.Confidence = asset.OwnerConfidenceMedium
	}
	o.Evidence = "runner:" + r.id + " " + o.Evidence
	return o, true
}

// envRank orders environments for routing: a package running in production
// anywhere routes as production.
var envRank = map[asset.Environment]int{asset.EnvProd: 3, asset.EnvStaging: 2, asset.EnvDev: 1}

func mostProdEnv(rs []runnerRouting) asset.Environment {
	best := asset.EnvUnknown
	for _, r := range rs {
		if envRank[r.env] > envRank[best] {
			best = r.env
		}
	}
	return best
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
