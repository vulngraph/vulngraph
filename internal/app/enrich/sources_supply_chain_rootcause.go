package enrich

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/distro"
)

// Root-cause findings are the alerting unit (ADR 088 amendment). A per-CVE
// package finding that an open root-cause finding already carries stays open
// and visible, linked to its root cause, but does not alert on its own: one
// KEV in debian:12's openssl on forty images is one page (the base), not forty
// one (the base plus every CVE). Two root causes carry package findings:
//
//   - the per-fleet vm_vuln findings (jobs/vmvuln.go), when only inventoried
//     VMs run the package and the fleets cover every one (FleetCanonical);
//   - the base-image root cause (jobs/baseimage.go), when only container
//     images run a BASE-LAYER package and every one of them is listed on an
//     open base-image-root-cause finding.
//
// Carrying is not enough on its own: the carrier must CURRENTLY hold at least
// the member's band. A member that pages on points while its base sits in the
// high band, or that turned KEV before the base-image job recounted the base,
// is carried by a finding that never raised its page — so it alerts itself.
const (
	baseImageSource      = "base_image"
	baseImageRootCauseID = "base-image-root-cause"
)

// AlertCarrier names the open root-cause finding(s) carrying a package
// finding's alerting at band memberBand, or "" when nothing does and the
// package finding must alert for itself. Every doubt answers "": a repo or VM
// also running the package, an image on no identified base, an
// application-layer package (a base rebuild does not fix it), a root-cause
// listing that may be truncated, or a carrier below the member's band.
func (s SupplyChainExposure) AlertCarrier(ctx context.Context, f finding.Finding, memberBand Band) (string, error) {
	if s.Fleets == nil || !isSupplyChainPackage(f) {
		return "", nil
	}
	r, err := s.runnersOf(ctx, f.ResourceID)
	if err != nil {
		return "", fmt.Errorf("AlertCarrier: %w", err)
	}
	canonical, cov, err := s.fleetCoverage(ctx, f, r)
	if err != nil {
		return "", fmt.Errorf("AlertCarrier: %w", err)
	}
	if canonical {
		if !BandAtLeast(cov.minBand, memberBand) {
			return "", nil
		}
		return fmt.Sprintf("vm_vuln fleet findings (%d instances)", cov.instances), nil
	}
	if r.truncated || len(r.repos) > 0 || len(r.images) == 0 || len(r.vms) > 0 || !isBaseLayerPackage(f) {
		return "", nil
	}
	covering, err := s.baseImageRootCauses(ctx)
	if err != nil {
		return "", fmt.Errorf("AlertCarrier: %w", err)
	}
	carriers := map[string]bool{}
	for _, img := range r.images {
		rc, ok := covering[img]
		if !ok || !BandAtLeast(rc.band, memberBand) {
			return "", nil
		}
		carriers[rc.id] = true
	}
	ids := make([]string, 0, len(carriers))
	for id := range carriers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return "base-image root cause " + strings.Join(ids, ","), nil
}

type rootCauseRef struct {
	id   string
	band Band
}

// baseImageRootCauses maps each image listed on an open base-image root-cause
// finding to that finding and its current band. A finding whose listing is
// capped (fewer listed ids than running_images) contributes nothing: an image it
// did not list may still be one of its members, but "may" is not enough to stay
// silent.
func (s SupplyChainExposure) baseImageRootCauses(ctx context.Context) (map[string]rootCauseRef, error) {
	out := map[string]rootCauseRef{}
	cursor := ""
	for range maxFleetListPages {
		page, err := s.Fleets.List(ctx, finding.Filter{Source: baseImageSource, CheckID: baseImageRootCauseID, Limit: fleetListPageLimit, Cursor: cursor})
		if err != nil {
			return nil, fmt.Errorf("baseImageRootCauses: %w", err)
		}
		for _, rc := range page {
			listed := splitIDs(rc.Metadata["affected_image_ids"])
			running, err := strconv.Atoi(rc.Metadata["running_images"])
			if err != nil || running != len(listed) {
				continue
			}
			for _, id := range listed {
				out[id] = rootCauseRef{id: rc.ID, band: Band(rc.ScoreBand)}
			}
		}
		if len(page) < fleetListPageLimit {
			return out, nil
		}
		cursor = finding.EncodeCursor(page[len(page)-1], false)
	}
	// More root causes than the bounded read covers: an image on an unread one
	// reads as uncovered and keeps alerting, which is the safe direction.
	return out, nil
}

// isBaseLayerPackage mirrors the base-image job's attribution heuristic: a
// distribution package (its ecosystem is a distro's, or its purl type is a
// distro package manager's) belongs to the base layer a rebuild replaces.
func isBaseLayerPackage(f finding.Finding) bool {
	if _, ok := distro.FamilyOf(f.Metadata["ecosystem"]); ok {
		return true
	}
	typ, _, _ := strings.Cut(strings.TrimPrefix(f.ResourceID, "pkg:"), "/")
	return typ == "deb" || typ == "apk" || typ == "rpm"
}

func splitIDs(s string) []string {
	var out []string
	for _, id := range strings.Split(s, ",") {
		if id = strings.TrimSpace(id); id != "" {
			out = append(out, id)
		}
	}
	return out
}

const sourceRootCauseKEV = "root_cause_kev"

// RootCauseKEV floors a base-image root-cause finding to the page band when
// its base layer carries a known-exploited CVE. The per-CVE member findings it
// carries do not alert on their own (AlertCarrier), so the page their KEV
// floor asserts must be raised here instead — once per base, not once per CVE.
type RootCauseKEV struct{}

func (RootCauseKEV) Name() string { return sourceRootCauseKEV }

func (RootCauseKEV) Evaluate(_ context.Context, f finding.Finding) (Factor, bool, error) {
	if f.Source != baseImageSource || f.CheckID != baseImageRootCauseID {
		return Factor{}, false, nil
	}
	n, err := strconv.Atoi(f.Metadata["base_layer_kev"])
	if err != nil || n <= 0 {
		return Factor{}, false, nil
	}
	return Factor{
		Source: sourceRootCauseKEV,
		Floor:  ThresholdPage,
		Detail: fmt.Sprintf("base layer carries %d known-exploited (CISA KEV) CVEs — this root cause pages for its member findings", n),
	}, true, nil
}
