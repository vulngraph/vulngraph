package jobs

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// openBaseFindings reads every open base_image finding, by id.
func (w *BaseImageWorker) openBaseFindings(ctx context.Context) (map[string]finding.Finding, error) {
	out := map[string]finding.Finding{}
	cursor := ""
	for {
		batch, err := w.findings.List(ctx, finding.Filter{Source: baseImageSource, Limit: baseImagePageLimit, Cursor: cursor})
		if err != nil {
			return nil, fmt.Errorf("openBaseFindings: %w", err)
		}
		for _, f := range batch {
			if !f.Resolved() {
				out[f.ID] = f
			}
		}
		if len(batch) < baseImagePageLimit {
			return out, nil
		}
		cursor = finding.EncodeCursor(batch[len(batch)-1], false)
	}
}

// reconcile resolves open base_image findings this pass no longer produced.
// It never acts on a truncated listing, and never on evidence that is merely
// missing: an end-of-life finding on a running image whose identity is gone,
// a root-cause finding with a running member that is unscanned or whose
// package edges are absent, and any finding whose images stopped being
// collected without being proven deleted, all stay open.
func (w *BaseImageWorker) reconcile(ctx context.Context, run baseImageRun, groups map[string]*baseGroup, open map[string]finding.Finding, found []finding.Finding) (int, error) {
	if !run.complete {
		return 0, nil
	}
	current := make(map[string]bool, len(found))
	for _, f := range found {
		current[f.ID] = true
	}
	ids := make([]string, 0, len(open))
	for id := range open {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	now := time.Now()
	var fixed, gone []finding.Finding
	for _, id := range ids {
		if current[id] {
			continue
		}
		f := open[id]
		switch resolutionOf(f, run, groups, now) {
		case finding.ReasonFixed:
			fixed = append(fixed, f)
		case finding.ReasonResourceGone:
			gone = append(gone, f)
		}
	}
	if len(fixed) > 0 {
		if err := w.findings.Resolve(ctx, fixed, finding.ReasonFixed); err != nil {
			return 0, fmt.Errorf("reconcile: resolve fixed: %w", err)
		}
	}
	if len(gone) > 0 {
		if err := w.findings.Resolve(ctx, gone, finding.ReasonResourceGone); err != nil {
			return len(fixed), fmt.Errorf("reconcile: resolve gone: %w", err)
		}
	}
	return len(fixed) + len(gone), nil
}

// resolutionOf decides an unemitted finding's fate; "" withholds it.
func resolutionOf(f finding.Finding, run baseImageRun, groups map[string]*baseGroup, now time.Time) finding.ResolutionReason {
	if f.CheckID == baseImageGroupCheckID {
		return groupResolution(f, run, groups, now)
	}
	r := run.byID[f.ResourceID]
	_, listed := run.listed[f.ResourceID]
	switch {
	case r == nil && run.deleted[f.ResourceID]:
		return finding.ReasonResourceGone
	case r == nil && !listed && agedOut(f, now):
		return finding.ReasonResourceGone // no row left to judge, and long unobserved
	case r == nil, !r.scanned, r.base.BaseOS == "":
		return "" // not running but not proven deleted, or identity unknown
	}
	return finding.ReasonFixed
}

// groupResolution: a base that still has running images and produced no
// finding was fixed in place (no base-layer CVE left, no longer end-of-life).
// A base nothing runs any more needs every image ever listed on it (the full
// membership, groupMembers — not the capped affected_image_ids) to be gone;
// it was then fixed when a former member's repository now runs on another
// base (the image was rebuilt — the remediation the finding asks for), else
// it is resource_gone. A base with no listed image left resolves only once
// the finding is older than the absence fallback.
func groupResolution(f finding.Finding, run baseImageRun, groups map[string]*baseGroup, now time.Time) finding.ResolutionReason {
	members := strings.Split(f.Metadata["affected_image_ids"], ",")
	for _, id := range members {
		if r := run.byID[id]; r != nil && !r.scanned {
			return "" // a member still runs and its identity is unknown
		}
	}
	if g := groups[f.Metadata["base_group"]]; g != nil {
		if g.inventoryUnknown() {
			return ""
		}
		return finding.ReasonFixed
	}
	all := run.groupMembers[f.Metadata["base_group"]]
	if len(all) == 0 {
		if agedOut(f, now) {
			return finding.ReasonResourceGone
		}
		return ""
	}
	repos := map[string]bool{}
	for _, id := range all {
		if !run.deleted[id] {
			return "" // still collected, or stopped being collected without proof
		}
		if img, ok := run.listed[id]; ok && img.Name != "" {
			repos[asset.NormalizeImageRef(img.Name)] = true
		}
	}
	for _, r := range run.running {
		key, ok := groupKeyOf(r.base)
		if ok && r.scanned && key != f.Metadata["base_group"] && repos[asset.NormalizeImageRef(r.img.Name)] {
			return finding.ReasonFixed
		}
	}
	return finding.ReasonResourceGone
}
