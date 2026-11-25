package findingctx

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/respond"
)

// buildNarrative turns a finding's graph context into a plain-English risk story
// — the "why this matters (or doesn't)" an analyst would otherwise assemble by
// hand from the exposure flags, blast radius, identity chain, and supply-chain
// path. It is deterministic templating over signals already in the pack (no LLM
// call), so it is free, stable, and unit-testable. The reasoner's rationale
// (respond.Decide) stays the authoritative judgement; this is the readable
// framing rendered above it and returned by the MCP get_finding_context tool.
//
// The verdict clause deliberately names the deployed-vs-installed / not-reachable
// no meaningful risk when the signals support it — the graph-grounded answer that is
// the platform's flagship differentiator.
func buildNarrative(pack respond.ContextPack) string {
	f := pack.Finding
	var s []string

	// 1. What and where, with CVE exploitability if present.
	subject := f.ResourceName
	if subject == "" {
		subject = f.ResourceID
	}
	lead := f.Title
	if subject != "" {
		lead += fmt.Sprintf(" on %s", subject)
		if f.ResourceType != "" {
			lead += fmt.Sprintf(" (%s)", f.ResourceType)
		}
	}
	s = append(s, lead+".")
	if cve := pack.CVE; cve != nil && cve.CVEID != "" {
		var q []string
		if cve.KEV {
			q = append(q, "actively exploited (CISA KEV)")
		}
		if cve.EPSS > 0 {
			q = append(q, fmt.Sprintf("EPSS %.0f%%", cve.EPSS*100))
		}
		if cve.FixedVersion != "" {
			q = append(q, "fixed in "+cve.FixedVersion)
		}
		if len(q) > 0 {
			s = append(s, fmt.Sprintf("%s is %s.", cve.CVEID, strings.Join(q, ", ")))
		}
	}

	// 2. Exposure. InternetFacing is the DIRECT edge (ExposedToInternet on this
	// resource itself); transitivelyReachable is the separate BFS verdict the
	// enrich pipeline already computed and persisted on must_fix_reason (e.g.
	// "reachable from an internet-exposed asset (2 hops)"). The two can and do
	// disagree — a resource can be not directly internet-facing yet still
	// transitively reachable from one that is — so the narrative must name both
	// facts explicitly rather than flatly asserting "not internet-facing", which
	// would contradict must_fix_reason in the same payload.
	transitive := !pack.Exposure.InternetFacing && transitivelyReachable(pack.Finding)
	switch {
	case pack.Exposure.InternetFacing && pack.Exposure.Privileged:
		s = append(s, "The resource is internet-facing and runs with a privileged identity.")
	case pack.Exposure.InternetFacing:
		s = append(s, "The resource is internet-facing.")
	case pack.Exposure.Privileged && transitive:
		s = append(s, "The resource runs with a privileged identity and is not directly internet-facing, but is "+pack.Finding.MustFixReason+".")
	case pack.Exposure.Privileged:
		s = append(s, "The resource runs with a privileged identity but is not internet-facing.")
	case transitive:
		s = append(s, "The resource is not directly internet-facing, but is "+pack.Finding.MustFixReason+".")
	default:
		s = append(s, "The resource is not internet-facing.")
	}

	// 3. Reachability / blast radius.
	if pack.Blast.Count > 0 {
		reach := fmt.Sprintf("An attacker who compromised it could reach %d other asset%s", pack.Blast.Count, plural(pack.Blast.Count))
		if bt := topByType(pack.Blast.ByType); bt != "" {
			reach += " (" + bt + ")"
		}
		s = append(s, reach+".")
	} else {
		s = append(s, "Its blast radius is empty — no other asset is reachable from it.")
	}

	// 4. Identity chain.
	if id := pack.Identity; id != nil && id.ExecutesAsID != "" {
		clause := "It executes as " + id.ExecutesAsID
		if n := len(id.FederatedRepoIDs); n > 0 {
			clause += fmt.Sprintf(", whose role %d repo%s can assume via federated access", n, plural(n))
		}
		s = append(s, clause+".")
	}

	// 5. Supply-chain deployed-vs-installed.
	if sc := pack.SupplyChain; sc != nil {
		switch {
		case len(sc.Workloads) > 0:
			s = append(s, fmt.Sprintf("The package is included by %d repo%s and deployed to %d workload%s.",
				len(sc.RepoIDs), plural(len(sc.RepoIDs)), len(sc.Workloads), plural(len(sc.Workloads))))
		case len(sc.RepoIDs) > 0:
			s = append(s, fmt.Sprintf("The package is present in %d repo%s' SBOM but no workload deploys it — installed, not deployed.",
				len(sc.RepoIDs), plural(len(sc.RepoIDs))))
		}
	}

	// 6. Verdict — the graph-grounded "so what".
	s = append(s, verdict(pack))

	// 7. Where the fix lands, if known.
	if hint := pack.Impact.FixLocation.Hint; hint != "" {
		s = append(s, "Fix: "+hint)
	}

	return strings.Join(s, " ")
}

// transitivelyReachable reports whether the enrich pipeline's internet-hops BFS
// (sources_reach.go) found this finding reachable from an internet-exposed asset
// via a transitive (>=1 hop) path — the SAME fact must_fix_reason already renders
// (e.g. "reachable from an internet-exposed asset (2 hops)", "internet-reachable
// (2 hops)", or the identity-assumable phrasing). It deliberately reuses
// enrich.ReachabilityEvidenced — the exact predicate consistency.go's INV-1 gate
// uses to decide whether a must-fix class rests on reachability evidence — rather
// than re-parsing the reason string with a second, potentially drifting pattern.
// findingctx has no separate hop-count field; this is read off the persisted
// finding, not recomputed.
func transitivelyReachable(f finding.Finding) bool {
	return enrich.ReachabilityEvidenced(f.MustFixClass, f.MustFixReason)
}

// verdict is the one-line risk call derived purely from the signals.
func verdict(pack respond.ContextPack) string {
	kev := pack.CVE != nil && pack.CVE.KEV
	exposed := pack.Exposure.InternetFacing
	reachable := pack.Blast.Count > 0
	notDeployed := pack.SupplyChain != nil && len(pack.SupplyChain.Workloads) == 0 && len(pack.SupplyChain.RepoIDs) > 0

	switch {
	case exposed && (kev || pack.Finding.Score >= 61) && reachable:
		return "Exposed, exploitable, and connected — a real attack path, not noise."
	case notDeployed && !reachable && !exposed:
		return "Not deployed and not reachable — low real risk despite the severity label."
	case !exposed && !reachable:
		return "Isolated with no reachable neighbours — limited real risk in place."
	case exposed && !reachable:
		return "Exposed but with no onward blast radius — contained if compromised."
	default:
		return "Weigh the exposure and blast radius above against the fix's remediation impact."
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// topByType renders the blast breakdown as "12 ec2_instance, 6 rds_instance",
// largest first, capped so the sentence stays readable.
func topByType(byType map[string]int) string {
	if len(byType) == 0 {
		return ""
	}
	type kv struct {
		t string
		n int
	}
	kvs := make([]kv, 0, len(byType))
	for t, n := range byType {
		kvs = append(kvs, kv{t, n})
	}
	sort.Slice(kvs, func(i, j int) bool {
		if kvs[i].n != kvs[j].n {
			return kvs[i].n > kvs[j].n
		}
		return kvs[i].t < kvs[j].t
	})
	const max = 3
	parts := make([]string, 0, max)
	for i, e := range kvs {
		if i == max {
			parts = append(parts, "…")
			break
		}
		parts = append(parts, fmt.Sprintf("%d %s", e.n, e.t))
	}
	return strings.Join(parts, ", ")
}
