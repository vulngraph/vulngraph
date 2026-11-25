package enrich

import (
	"context"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// reachNone mirrors graphstore.ReachNone (-1): the resource is definitively NOT
// reachable from the internet. Duplicated here so enrich does not import
// graphstore (layering); the provider returns raw hop ints.
const reachNone = -1

// ReachProvider reports the shortest attacker-movement distance from an internet-
// exposed node to a resource (0 = directly exposed, 1..N = transitively reachable,
// reachNone = definitively unreachable). ok=false means "unknown" — the graph is
// unavailable or the node was not found — in which case the source and the must-
// fix classifier contribute nothing, so absence of data never changes a score.
type ReachProvider interface {
	InternetHops(ctx context.Context, resourceID string) (hops int, ok bool, err error)
}

// InternetReach scores whether an attacker can actually REACH a finding's resource
// from the internet — the "is this exploitable in practice" axis the score lacked.
// It promotes transitively-reachable resources and strongly DEMOTES definitively-
// unreachable ones (negative points, not suppression — per the "strong demote, not
// silence" decision: internal/lateral risk is real, so the finding stays visible,
// just far lower). Fail-open: unknown reachability contributes nothing.
//
// Direct exposure (hops 0) is scored here too, UNLESS ExposureType already covers
// it (Type=="exposure" AND Medium severity) — avoiding double-counting the same
// signal. Without this, a directly-internet-exposed EC2/k8s/etc. resource gets
// zero credit for its exposure whenever the finding isn't literally typed
// "exposure" (e.g. a GuardDuty threat detection or a misconfiguration check on
// an internet-facing instance), even though it sits on a resource with a live
// exposed_to_internet edge.
type InternetReach struct{ Reach ReachProvider }

func (InternetReach) Name() string { return sourceInternetReach }

// reachUnreachablePenalty is the strong demotion for a finding whose dominant risk
// is external reachability when no internet path exists. Large enough to drop a
// high-scoring privesc out of the high/page bands, but not a hard cap to monitor —
// a KEV finding keeps its Page floor, and a very high base stays visible.
const reachUnreachablePenalty = -25

func (r InternetReach) Evaluate(ctx context.Context, f finding.Finding) (Factor, bool, error) {
	if r.Reach == nil || f.ResourceID == "" {
		return Factor{}, false, nil
	}
	// Only findings where external reachability is the dominant risk driver.
	if !reachabilityMeaningful(f) {
		return Factor{}, false, nil
	}
	hops, ok, err := r.Reach.InternetHops(ctx, f.ResourceID)
	if err != nil {
		return Factor{}, false, err
	}
	if !ok {
		return Factor{}, false, nil // unknown → no signal (fail-open)
	}
	switch {
	case hops == 0:
		// Direct exposure. ExposureType already scores Type=="exposure"+Medium
		// findings (+12) — skip here to avoid double-counting the same signal.
		if exposureTypeCovers(f) {
			return Factor{}, false, nil
		}
		return Factor{
			Source: sourceInternetReach,
			Points: directExposurePoints,
			Detail: "directly reachable from the internet (0-hop)",
		}, true, nil
	case hops >= 1 && hops <= 3:
		return Factor{
			Source: sourceInternetReach,
			Points: reachPoints(hops),
			Detail: fmt.Sprintf("reachable from the internet via a %d-hop attack path", hops),
		}, true, nil
	case hops == reachNone:
		// Definitively unreachable. Never demote a known-exploited finding (the
		// exploit may not need internet reachability, and KEV must stay urgent).
		if f.KnownExploited {
			return Factor{}, false, nil
		}
		return Factor{
			Source: sourceInternetReach,
			Points: reachUnreachablePenalty,
			Detail: "no internet path in the collected graph; other entry points and lateral risk remain possible",
		}, true, nil
	}
	return Factor{}, false, nil
}

// directExposurePoints is the highest reach tier — a directly internet-facing
// resource is at least as urgent as a 1-hop path, so it scores at or above
// reachPoints(1).
const directExposurePoints = 18

// exposureTypeCovers reports whether ExposureType (sources.go) already scores
// this finding's direct exposure, so InternetReach must skip hop 0 to avoid
// awarding the same "internet-facing" signal twice.
func exposureTypeCovers(f finding.Finding) bool {
	return f.Type == "exposure" && f.Severity == finding.SeverityMedium
}

func reachPoints(hops int) int {
	switch hops {
	case 1:
		return 14
	case 2:
		return 10
	default:
		return 6
	}
}

// reachabilityMeaningful reports whether internet reachability is a dominant risk
// driver for a finding — privilege escalation, internet-exposure classes, and any
// finding on a network-addressable resource type (EC2, security group, k8s pod,
// load balancer, …) where a reverse internet path is a real risk axis. The last
// clause is what lets this source run on the largest classes: an
// EC2/security-group misconfiguration is neither privesc nor an
// "exposure"/"public" check by string, so without it the source would skip them
// even though the BFS exists precisely for those asset types. A supply-chain or config-hygiene
// finding on a non-network resource still doesn't hinge on a reverse internet
// path, so this source leaves those alone.
func reachabilityMeaningful(f finding.Finding) bool {
	return isPrivesc(f) || isExposure(f) || IsNetworkReachableResource(f.ResourceType)
}
