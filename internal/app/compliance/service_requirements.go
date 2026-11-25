package compliance

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/checks/benchmarks"
	"github.com/vulngraph/vulngraph/internal/checks/frameworks"
)

// OpenResources supplies, per check, the resources with an open finding.
// finding.Service implements it; only the auditor export reads it.
type OpenResources interface {
	OpenResourcesByCheck(ctx context.Context, checkIDs []string) (map[string][]string, error)
}

// Catalog is the requirement-level data a Service rolls up: the framework
// mappings and the benchmark matrices their control references resolve
// through (ADR 093).
type Catalog struct {
	frameworks []frameworks.Framework
	index      frameworks.Index
}

// LoadCatalog loads the embedded framework mappings and benchmark matrices.
func LoadCatalog() (Catalog, error) {
	bs, err := benchmarks.Load()
	if err != nil {
		return Catalog{}, fmt.Errorf("LoadCatalog: %w", err)
	}
	fws, err := frameworks.Load()
	if err != nil {
		return Catalog{}, fmt.Errorf("LoadCatalog: %w", err)
	}
	return NewCatalog(fws, bs), nil
}

// NewCatalog builds a catalog from already-loaded data (tests use it).
func NewCatalog(fws []frameworks.Framework, bs []benchmarks.Benchmark) Catalog {
	return Catalog{frameworks: fws, index: frameworks.NewIndex(bs)}
}

// WithRequirements wires the requirement-level rollup. Call once at
// construction.
func (s *Service) WithRequirements(c Catalog, open OpenResources) *Service {
	s.catalog, s.open = c, open
	return s
}

// checkEvidence is what the inventory says about one check.
type checkEvidence int

const (
	// evUnevaluated: applicable assets exist and some lack the evidence. The
	// zero value, so a check missing from the evidence map reads as
	// unevaluated, never as "nothing to evaluate".
	evUnevaluated checkEvidence = iota
	// evAbsent: no live asset the check applies to — nothing to evaluate.
	evAbsent
	// evEvaluated: every applicable asset carries the evidence.
	evEvaluated
)

// estate is the live evidence a rollup reads. clouds holds every provider
// with a configured connector or inventory.
type estate struct {
	failing  map[string]bool
	evidence map[string]checkEvidence
	clouds   map[string]CloudEvidence
}

// Frameworks returns every framework's summary.
func (s *Service) Frameworks(ctx context.Context) ([]FrameworkSummary, error) {
	all, err := s.frameworkStatuses(ctx)
	if err != nil {
		return nil, fmt.Errorf("Frameworks: %w", err)
	}
	out := make([]FrameworkSummary, 0, len(all))
	for _, fs := range all {
		out = append(out, fs.FrameworkSummary)
	}
	return out, nil
}

// Framework returns one framework's requirement-level status.
func (s *Service) Framework(ctx context.Context, id string) (FrameworkStatus, error) {
	all, err := s.frameworkStatuses(ctx)
	if err != nil {
		return FrameworkStatus{}, fmt.Errorf("Framework: %w", err)
	}
	for _, fs := range all {
		if fs.ID == id {
			return fs, nil
		}
	}
	return FrameworkStatus{}, fmt.Errorf("Framework %q: %w", id, ErrFrameworkNotFound)
}

// ExportFramework is Framework plus, per requirement, the distinct resources
// failing its checks — what an auditor's evidence sheet lists.
func (s *Service) ExportFramework(ctx context.Context, id string) (FrameworkStatus, error) {
	fs, err := s.Framework(ctx, id)
	if err != nil {
		return FrameworkStatus{}, fmt.Errorf("ExportFramework: %w", err)
	}
	var failing []string
	for _, r := range fs.Requirements {
		failing = append(failing, r.FailingChecks...)
	}
	slices.Sort(failing)
	failing = slices.Compact(failing)
	resources, err := s.open.OpenResourcesByCheck(ctx, failing)
	if err != nil {
		return FrameworkStatus{}, fmt.Errorf("ExportFramework: %w", err)
	}
	for i, r := range fs.Requirements {
		seen := map[string]bool{}
		known := true
		for _, chk := range r.FailingChecks {
			// A failing check with no resource-bearing finding failed on
			// findings that name no resource: its resources are unmeasured,
			// not zero.
			if len(resources[chk]) == 0 {
				known = false
			}
			for _, res := range resources[chk] {
				seen[res] = true
			}
		}
		fs.Requirements[i].FailingResources = len(seen)
		fs.Requirements[i].FailingResourcesKnown = known
	}
	return fs, nil
}

func (s *Service) frameworkStatuses(ctx context.Context) ([]FrameworkStatus, error) {
	if s.open == nil || s.conns == nil {
		return nil, errors.New("frameworkStatuses: requirement rollup not wired")
	}
	ids, err := s.findings.DistinctCheckIDs(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("frameworkStatuses: %w", err)
	}
	est := estate{failing: map[string]bool{}}
	for _, id := range ids {
		est.failing[id] = true
	}
	var inventory map[string]bool
	if est.evidence, inventory, err = s.checkEvidence(ctx, s.catalog.mappedChecks()); err != nil {
		return nil, fmt.Errorf("frameworkStatuses: %w", err)
	}
	if est.clouds, err = s.clouds(ctx, inventory); err != nil {
		return nil, fmt.Errorf("frameworkStatuses: %w", err)
	}
	clouds := sortedClouds(est.clouds)
	out := make([]FrameworkStatus, 0, len(s.catalog.frameworks))
	for _, fw := range s.catalog.frameworks {
		fs := FrameworkStatus{FrameworkSummary: FrameworkSummary{ID: fw.ID, Name: fw.Name, Version: fw.Version}, Clouds: clouds}
		for _, r := range fw.Requirements {
			st := rollupRequirement(r, s.catalog.index, est)
			fs.Total++
			switch st.State {
			case RequirementPassing:
				fs.Passing++
			case RequirementFailing:
				fs.Failing++
			case RequirementManual:
				fs.Manual++
			default:
				fs.Unknown++
			}
			fs.Requirements = append(fs.Requirements, st)
		}
		out = append(out, fs)
	}
	return out, nil
}

// mappedChecks is every check of every control a framework maps.
func (c Catalog) mappedChecks() []string {
	set := map[string]bool{}
	for _, fw := range c.frameworks {
		for _, r := range fw.Requirements {
			found, _ := c.index.Controls(r)
			for _, mc := range found {
				for _, id := range mc.CheckIDs {
					set[id] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// checkEvidence classifies each check against one inventory sample read and
// reports which providers have inventory. A check the registry does not know
// is unevaluated: nothing is known to evaluate it.
func (s *Service) checkEvidence(ctx context.Context, ids []string) (map[string]checkEvidence, map[string]bool, error) {
	samples, providers, err := s.sampleInventory(ctx, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("checkEvidence: %w", err)
	}
	out := make(map[string]checkEvidence, len(ids))
	for _, id := range ids {
		out[id] = s.classify(id, samples)
	}
	return out, providers, nil
}

// classify: evaluated only when EVERY applicable sample carries the evidence.
// Samples are one per distinct evidence shape, so one sample without the keys
// means some live assets of that type were never observed — an evaluable
// bucket next to it must not vouch for them.
func (s *Service) classify(id string, samples []asset.Asset) checkEvidence {
	chk, ok := s.registry.ByID(id)
	if !ok {
		return evUnevaluated
	}
	ev := evAbsent
	for _, a := range samples {
		if !chk.AppliesTo(a) {
			continue
		}
		if !chk.Evaluable(a) {
			return evUnevaluated
		}
		ev = evEvaluated
	}
	return ev
}

// rollupRequirement decides one requirement's state from its mapped controls
// and the estate. Failing wins over everything: an open finding is evidence
// whatever else is missing. Passing needs complete evidence; every hole is
// recorded and makes the requirement unknown.
func rollupRequirement(r frameworks.Requirement, ix frameworks.Index, est estate) RequirementStatus {
	st := RequirementStatus{ID: r.ID, Title: r.Title, Controls: r.Controls, UnjoinedSourceChecks: r.Unjoined}
	if len(r.Controls) == 0 {
		st.State = RequirementManual
		return st
	}
	found, missing := ix.Controls(r)
	st.Gaps = append(st.Gaps, missing...)
	seen := map[string]bool{}
	evaluated := 0
	asOfKnown := true
	for _, c := range found {
		if !inScope(c, est) {
			st.OutOfScope = append(st.OutOfScope, c.Ref())
			continue
		}
		if c.Status != benchmarks.StatusCovered {
			st.Gaps = append(st.Gaps, c.Ref())
		}
		stale := false
		for _, p := range c.Providers {
			ce, ok := est.clouds[p]
			if !ok {
				continue
			}
			stale = stale || ce.Stale
			switch {
			case ce.EvidenceAsOf.IsZero():
				asOfKnown = false
			case st.EvidenceAsOf.IsZero() || ce.EvidenceAsOf.Before(st.EvidenceAsOf):
				st.EvidenceAsOf = ce.EvidenceAsOf
			}
		}
		if stale {
			st.EvidenceGaps = append(st.EvidenceGaps, c.Ref())
		}
		for _, id := range c.CheckIDs {
			if seen[id] {
				continue
			}
			seen[id] = true
			st.CheckIDs = append(st.CheckIDs, id)
			switch {
			case est.failing[id]:
				st.FailingChecks = append(st.FailingChecks, id)
			case est.evidence[id] == evEvaluated:
				evaluated++
			case est.evidence[id] == evUnevaluated:
				st.UnevaluatedChecks = append(st.UnevaluatedChecks, id)
			}
		}
	}
	if !asOfKnown {
		st.EvidenceAsOf = time.Time{}
	}
	switch {
	case len(st.FailingChecks) > 0:
		st.State = RequirementFailing
	case len(st.Gaps) > 0 || len(st.EvidenceGaps) > 0 || len(st.UnevaluatedChecks) > 0 || st.UnjoinedSourceChecks > 0 || evaluated == 0:
		st.State = RequirementUnknown
	default:
		st.State = RequirementPassing
	}
	return st
}

// inScope: the control's benchmark covers a provider with a configured
// connector or inventory, or one of its checks has an open finding (a
// finding is evidence even when neither surfaced that provider).
func inScope(c frameworks.MappedControl, est estate) bool {
	for _, p := range c.Providers {
		if _, ok := est.clouds[p]; ok {
			return true
		}
	}
	for _, id := range c.CheckIDs {
		if est.failing[id] {
			return true
		}
	}
	return false
}
