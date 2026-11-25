package jobs

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// openFleetFindings reads every open vm_vuln finding, by id.
func (w *VMVulnWorker) openFleetFindings(ctx context.Context) (map[string]finding.Finding, error) {
	out := map[string]finding.Finding{}
	cursor := ""
	for {
		batch, err := w.findings.List(ctx, finding.Filter{Source: vmVulnSource, Limit: vmVulnPageLimit, Cursor: cursor})
		if err != nil {
			return nil, fmt.Errorf("openFleetFindings: %w", err)
		}
		for _, f := range batch {
			if !f.Resolved() {
				out[f.ID] = f
			}
		}
		if len(batch) < vmVulnPageLimit {
			return out, nil
		}
		cursor = finding.EncodeCursor(batch[len(batch)-1], false)
	}
}

// reconcile resolves open fleet findings this pass no longer produced. It never
// acts on an incomplete pass, and never without evidence:
//
//   - a fleet with a live member whose inventory is unknown: absence there
//     means "not observed", not "patched" — withheld;
//   - a fleet with no live member: resource_gone only when every member is
//     gone (goneFleets), or when no listed VM maps to the fleet any more and
//     the finding was last observed before the absence fallback; a fleet that
//     merely stopped being collected is withheld;
//   - a live, inventoried fleet that no longer runs the purl: fixed when its
//     members run the same package at a NEWER version (versionNewer) that
//     does not still carry the same CVE, else resource_gone (removed, or
//     upgraded to a version still vulnerable);
//   - a live fleet still running the purl: the finding went unproduced because
//     its package finding is no longer open, so it takes that finding's reason
//     — except resource_gone, which contradicts a fleet running the package.
func (w *VMVulnWorker) reconcile(ctx context.Context, run vmVulnRun, open map[string]finding.Finding, seen fleetPackages, found []finding.Finding) (int, error) {
	if !run.complete {
		return 0, nil
	}
	current := make(map[string]bool, len(found))
	// stillVulnerable: a fleet × check this pass reproduced on some purl — an
	// upgrade that still carries the CVE did not fix it.
	stillVulnerable := map[string]bool{}
	for _, f := range found {
		current[f.ID] = true
		stillVulnerable[f.Metadata["fleet_kind"]+":"+f.Metadata["fleet_id"]+"\x00"+f.CheckID] = true
	}
	ids := make([]string, 0, len(open))
	for id := range open {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	now := time.Now()
	byReason := map[finding.ResolutionReason][]finding.Finding{}
	var stillRun []finding.Finding
	for _, id := range ids {
		f := open[id]
		if current[id] {
			continue
		}
		fleet := f.Metadata["fleet_kind"] + ":" + f.Metadata["fleet_id"]
		switch {
		case run.unknownFleets[fleet]:
		case !run.liveFleets[fleet]:
			if run.goneFleets[fleet] || (!run.listedFleets[fleet] && agedOut(f, now)) {
				byReason[finding.ReasonResourceGone] = append(byReason[finding.ReasonResourceGone], f)
			}
		default:
			purl := f.Metadata["purl"]
			if purl == "" {
				continue // nothing to compare against — withheld
			}
			purls := seen[fleetPurlKey(fleet, purl)]
			if purls[purl] {
				stillRun = append(stillRun, f)
				continue
			}
			reason := finding.ReasonResourceGone
			if !stillVulnerable[fleet+"\x00"+f.CheckID] && upgradedTo(purl, purls) {
				reason = finding.ReasonFixed
			}
			byReason[reason] = append(byReason[reason], f)
		}
	}
	mirrored, err := w.packageReasons(ctx, stillRun)
	if err != nil {
		return 0, fmt.Errorf("reconcile: %w", err)
	}
	for _, f := range stillRun {
		if r, ok := mirrored[f.Metadata["package_finding_id"]]; ok {
			byReason[r] = append(byReason[r], f)
		}
	}

	reasons := make([]finding.ResolutionReason, 0, len(byReason))
	for r := range byReason {
		reasons = append(reasons, r)
	}
	sort.Slice(reasons, func(i, j int) bool { return reasons[i] < reasons[j] })
	resolved := 0
	for _, r := range reasons {
		if err := w.findings.Resolve(ctx, byReason[r], r); err != nil {
			return resolved, fmt.Errorf("reconcile: resolve %s: %w", r, err)
		}
		resolved += len(byReason[r])
	}
	return resolved, nil
}

// upgradedTo reports whether any of purls is the same package as purl at a
// NEWER version under its ecosystem's comparator (versionNewer).
func upgradedTo(purl string, purls map[string]bool) bool {
	key, version := purlParts(purl)
	for p := range purls {
		k, v := purlParts(p)
		if k != key {
			continue
		}
		if newer, ok := versionNewer(purlType(purl), version, v); ok && newer {
			return true
		}
	}
	return false
}

// packageReasons returns, by package finding id, the resolution reason of each
// RESOLVED package finding the given fleet findings derive from — the reason a
// fleet still running the package inherits. resource_gone is left out: the
// fleet running the package contradicts it, so the fleet finding is withheld.
func (w *VMVulnWorker) packageReasons(ctx context.Context, fleetFindings []finding.Finding) (map[string]finding.ResolutionReason, error) {
	out := map[string]finding.ResolutionReason{}
	want := map[string]bool{}
	purlSet := map[string]bool{}
	var purls []string
	for _, f := range fleetFindings {
		want[f.Metadata["package_finding_id"]] = true
		if p := f.Metadata["purl"]; !purlSet[p] {
			purlSet[p] = true
			purls = append(purls, p)
		}
	}
	sort.Strings(purls)
	for start := 0; start < len(purls); start += vmPurlBatch {
		rows, err := w.findings.ByResourceIDs(ctx, purls[start:min(start+vmPurlBatch, len(purls))])
		if err != nil {
			return nil, fmt.Errorf("packageReasons: %w", err)
		}
		for _, p := range rows {
			if want[p.ID] && p.Resolved() && p.ResolutionReason.Valid() && p.ResolutionReason != finding.ReasonResourceGone {
				out[p.ID] = p.ResolutionReason
			}
		}
	}
	return out, nil
}
