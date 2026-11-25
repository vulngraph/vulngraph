package enrich

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// ResourceFindings lists the other findings on a given resource. finding.Service
// implements it (List with a ResourceID filter). It is the read seam the
// graph-aware sources share, so they reason about an asset's full finding set
// rather than the single finding in isolation.
type ResourceFindings interface {
	List(ctx context.Context, f finding.Filter) ([]finding.Finding, error)
}

// ── attack paths ─────────────────────────────────────────────────────────────

// AttackPaths scores the privilege-escalation reach of a finding's resource: an
// IAM principal that also carries ciem_privesc findings can escalate, and more
// distinct techniques mean more reach. It reads the CIEM findings the privesc
// checks produced — the can_assume/can_escalate edges feed blast radius
// separately; this source counts the escalation techniques themselves.
//
// Two things this source must NOT do:
//
//   - Count the finding being scored. The peer list is "all findings on this
//     resource", which includes f itself, so a lone privesc finding would award
//     itself points. This source measures the OTHER escalation reach around a
//     finding — f's own privesc nature is already scored by BaseSeverity and
//     PrincipalClass — so f.ID is excluded.
//   - Count findings and call them techniques. Multiple distinct checks can trip
//     on the same over-permissioned grant, so a single fact (one bad IAM
//     binding) can produce many peer findings that would each award every other
//     one points — a mutual-reinforcement clique with no extra information in
//     it. The count is DISTINCT CheckIDs (one per escalation technique, which is
//     what the check catalog is keyed on), so the same grant seen many ways
//     counts as the handful of techniques it actually is.
type AttackPaths struct{ Findings ResourceFindings }

func (AttackPaths) Name() string { return sourceAttackPaths }

func (a AttackPaths) Evaluate(ctx context.Context, f finding.Finding) (Factor, bool, error) {
	if f.ResourceID == "" {
		return Factor{}, false, nil
	}
	peers, err := a.Findings.List(ctx, finding.Filter{ResourceID: f.ResourceID, Limit: 200})
	if err != nil {
		return Factor{}, false, fmt.Errorf("attack paths: %w", err)
	}
	seen := make(map[string]struct{}, len(peers))
	for _, p := range peers {
		if p.Type != "ciem_privesc" {
			continue
		}
		if f.ID != "" && p.ID == f.ID {
			continue // never count the finding being scored
		}
		// CheckID identifies the escalation technique (aws-privesc-NN /
		// gcp-privesc-NN / azure-privesc-NN). Fall back to the finding ID only
		// when a producer left CheckID empty, so unkeyed peers are not collapsed
		// into one another (fail toward counting, not toward silence).
		key := p.CheckID
		if key == "" {
			key = "\x00id:" + p.ID
		}
		seen[key] = struct{}{}
	}
	techniques := len(seen)
	if techniques == 0 {
		return Factor{}, false, nil
	}
	return Factor{
		Source: sourceAttackPaths,
		Points: attackPathPoints(techniques),
		Detail: fmt.Sprintf("%d other privilege-escalation technique(s) on this principal", techniques),
	}, true, nil
}

func attackPathPoints(n int) int {
	switch {
	case n <= 0:
		return 0
	case n == 1:
		return 8
	case n <= 3:
		return 14
	default:
		return 20
	}
}

// ── toxic combination ────────────────────────────────────────────────────────

// ToxicCombo fires when a resource has a privilege-escalation path AND is reachable
// from the internet — the classic "public + admin" combination that is critical
// regardless of either finding's individual score. A hit floors the score to the
// pipeline threshold so the combination is always actioned. "Reachable" is a
// co-located exposure finding OR (when Reach is wired) a transitive attack path
// within 2 hops — so an admin role behind an exposed load balancer counts, not
// just a directly-public resource.
//
// POINTS vs FLOOR. Both halves of the combination are already scored elsewhere
// for the same resource: the privesc half by AttackPaths/PrincipalClass, and the
// reach half by InternetReach (+18/+14/+10/+6, graded by the very hop count this
// source re-queries) or by ExposureType (+12). Awarding points here on top of
// the Floor would double-count that reach fact.
//
// The documented purpose of a hit is "this combination is always actioned",
// which the Floor alone achieves (ThresholdPipeline). So when the reach half is
// already being scored by InternetReach, this source contributes Floor only and
// 0 points — see internetReachCovers, which mirrors the existing
// exposureTypeCovers de-dup in sources_reach.go. When it is NOT (no Reach
// provider wired, reachability not a meaningful axis for this finding class, or
// the graph has no answer), the signal would otherwise be lost entirely, so the
// full +20 still applies. Net effect: the combination never scores zero and
// never scores twice.
type ToxicCombo struct {
	Findings ResourceFindings
	Reach    ReachProvider // optional; nil → co-located exposure only (original behavior)
}

func (ToxicCombo) Name() string { return sourceToxicCombo }

func (t ToxicCombo) Evaluate(ctx context.Context, f finding.Finding) (Factor, bool, error) {
	if f.ResourceID == "" {
		return Factor{}, false, nil
	}
	peers, err := t.Findings.List(ctx, finding.Filter{ResourceID: f.ResourceID, Limit: 200})
	if err != nil {
		return Factor{}, false, fmt.Errorf("toxic combo: %w", err)
	}
	var exposed, privesc bool
	for _, p := range peers {
		switch {
		case p.Type == "ciem_privesc":
			privesc = true
		case isExposure(p):
			exposed = true
		}
	}
	if !privesc {
		return Factor{}, false, nil
	}
	detail := "internet exposure combined with a privilege-escalation path"
	// One hop lookup, used for two purposes: establishing transitive exposure,
	// and deciding whether InternetReach is already scoring that same distance.
	// Served from the pre-warmed node-signal cache, so this is not a new query
	// per finding in the co-located-exposure case.
	hops, hopsOK := 0, false
	if t.Reach != nil {
		if h, ok, herr := t.Reach.InternetHops(ctx, f.ResourceID); herr == nil && ok {
			hops, hopsOK = h, true
		}
	}
	if !exposed && hopsOK && hops >= 0 && hops <= 2 {
		exposed = true
		detail = fmt.Sprintf("privilege-escalation path %d hop(s) from an internet-exposed asset", hops)
	}
	if !exposed {
		return Factor{}, false, nil
	}
	points := 20
	if internetReachCovers(f, hops, hopsOK) {
		points = 0
		detail += " (reach scored by internet_reach; this source floors the score)"
	}
	return Factor{
		Source: sourceToxicCombo,
		Points: points,
		Floor:  ThresholdPipeline,
		Detail: detail,
	}, true, nil
}

// internetReachCovers reports whether InternetReach (sources_reach.go) is
// already awarding points for this finding's internet distance, in which case
// ToxicCombo must not award them a second time. It is the mirror image of
// exposureTypeCovers: same de-dup principle, opposite direction.
//
// It reproduces InternetReach's own gate exactly — a wired provider, a
// reachability-meaningful finding class, and a concrete hop count in the scoring
// range 0..3. Hop 0 counts as covered either way: InternetReach awards
// directExposurePoints, or (when exposureTypeCovers sends it there) ExposureType
// awards +12. Anything else — no provider, unknown reachability, or a class where
// reachability is not the risk driver — is NOT covered, and ToxicCombo keeps its
// points so the combination signal is never silently dropped.
func internetReachCovers(f finding.Finding, hops int, hopsOK bool) bool {
	if !hopsOK || !reachabilityMeaningful(f) {
		return false
	}
	return hops >= 0 && hops <= 3
}

// isExposure reports whether a peer finding represents internet exposure.
func isExposure(f finding.Finding) bool {
	return f.Type == "exposure" || strings.Contains(f.CheckID, "public")
}

// ── cross-cluster recurrence ─────────────────────────────────────────────────

// CrossClusterCounter counts distinct resources affected by a check_id within a
// source — one indexed CH query vs loading all findings into Go. finding.Service
// implements it via CountByCheckID.
type CrossClusterCounter interface {
	CountByCheckID(ctx context.Context, source, checkID string) (int, error)
}

// crossClusterEntry is a cached count with its expiry.
type crossClusterEntry struct {
	count   int
	expires time.Time
}

// crossClusterCacheTTL: counts only change when new findings arrive via sync
// (~every 15-30 min). A 30-min TTL eliminates near-duplicate CH queries for
// the same (source, check_id) within one enrich sweep — e.g. 600 findings
// with check_id="iam:AttachRolePolicy" would otherwise fire 600 identical
// COUNT queries and get the same answer each time.
const crossClusterCacheTTL = 30 * time.Minute

// CrossCluster raises systemic findings: the same check failing across many
// resources (accounts/regions) is a wider problem than one instance.
type CrossCluster struct {
	Findings CrossClusterCounter
	mu       sync.Mutex
	cache    map[string]crossClusterEntry
}

func (*CrossCluster) Name() string { return sourceCrossCluster }

func (c *CrossCluster) Evaluate(ctx context.Context, f finding.Finding) (Factor, bool, error) {
	if f.CheckID == "" || f.Source == "" {
		return Factor{}, false, nil
	}

	key := f.Source + "\x00" + f.CheckID
	now := time.Now()

	c.mu.Lock()
	if c.cache == nil {
		c.cache = make(map[string]crossClusterEntry)
	}
	if e, ok := c.cache[key]; ok && now.Before(e.expires) {
		n := e.count
		c.mu.Unlock()
		if n < 3 {
			return Factor{}, false, nil
		}
		return Factor{
			Source: sourceCrossCluster,
			Points: crossClusterPoints(n),
			Detail: fmt.Sprintf("%s affects %d resources (systemic)", f.CheckID, n),
		}, true, nil
	}
	c.mu.Unlock()

	n, err := c.Findings.CountByCheckID(ctx, f.Source, f.CheckID)
	if err != nil {
		return Factor{}, false, fmt.Errorf("cross cluster: %w", err)
	}

	c.mu.Lock()
	c.cache[key] = crossClusterEntry{count: n, expires: now.Add(crossClusterCacheTTL)}
	c.mu.Unlock()
	if n < 3 {
		return Factor{}, false, nil // not yet systemic
	}
	return Factor{
		Source: sourceCrossCluster,
		Points: crossClusterPoints(n),
		Detail: fmt.Sprintf("%s affects %d resources (systemic)", f.CheckID, n),
	}, true, nil
}

// crossClusterPoints weights "how systemic is this check?" — deliberately small
// and capped.
//
// The count behind it (CountByCheckID) is distinct RESOURCES affected by a
// check within a source, which is a proxy for blast domains and a poor one: it
// saturates. A check firing across hundreds of resources in one class would
// otherwise hand every finding in that class an identical top-tier bonus — a
// constant carrying zero discriminating information that lifts the whole
// cluster together.
//
// Capping at +6 keeps the signal ("this check is failing broadly, not once")
// while leaving the headroom for the per-finding signals — reach, blast,
// exploitability — that actually distinguish one finding from another. The tiers
// are widened so the count still discriminates in the range real checks occupy
// instead of pinning at the top from n=11 onwards.
//
// The right fix for the semantics is to count distinct ACCOUNTS/PROJECTS rather
// than resources, so "systemic" means "crosses blast domains". That needs a new
// repo query (finding.Service.CountByCheckID only returns a resource count);
// until it exists, the points are capped rather than the count re-scoped.
func crossClusterPoints(n int) int {
	switch {
	case n < 3:
		return 0
	case n <= 10:
		return 2
	case n <= 50:
		return 4
	default:
		return 6
	}
}
