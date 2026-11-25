package compliance

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/checks"
)

// CheckIDs supplies the set of check_ids that have open findings. finding.Service
// implements it. Using distinct check_ids (not paginated findings) ensures
// compliance coverage is accurate regardless of how many findings exist.
type CheckIDs interface {
	DistinctCheckIDs(ctx context.Context, source string) ([]string, error)
}

// Inventory supplies, among spec.Types, one representative live asset per
// distinct (provider, type, evidence), where evidence is the metadata
// projected onto spec.Keys and reduced as EvidenceSpec describes — every
// distinct evaluability shape in the estate. A sample's metadata holds only
// the projected keys, and a value evaluability does not read is "".
// CHInventory implements it.
type Inventory interface {
	Samples(ctx context.Context, spec EvidenceSpec) ([]asset.Asset, error)
}

// ciemEvidenceKeys are the metadata keys ciem.Graded reads.
var ciemEvidenceKeys = []string{ciem.MetaAWSOrganizationComplete, ciem.MetaPrivilegeTier, "policies", "permissions", "role_grants", "roles_complete", "permissions_complete", "role_grants_complete"}

// Grading now reads these values, including the structured Azure grant shape
// and completeness. Permission strings separately collapse to empty/nonempty
// in the inventory projection; their full action payload is not needed here.
var ciemEvidenceValueKeys = []string{ciem.MetaAWSOrganizationComplete, ciem.MetaPrivilegeTier, "role_grants", "roles_complete", "permissions_complete", "role_grants_complete"}

// ciemScope is what a CIEM privilege-escalation rule evaluates. CIEM rule IDs
// are stamped on findings but are not check-registry checks, so their scope is
// declared here: the engine reads the principals of these types.
type ciemScope struct {
	provider asset.Provider
	types    []string
}

var ciemScopes = map[string]ciemScope{
	"aws-privesc-": {provider: asset.ProviderAWS, types: []string{"iam_role", "iam_user"}},
	"gcp-privesc-": {provider: asset.ProviderGCP, types: []string{"gcp_service_account"}},
}

func ciemScopeFor(checkID string) (ciemScope, bool) {
	for prefix, sc := range ciemScopes {
		if strings.HasPrefix(checkID, prefix) {
			return sc, true
		}
	}
	return ciemScope{}, false
}

type Service struct {
	findings  CheckIDs
	inventory Inventory
	registry  *checks.Registry
	// catalog and open back the requirement-level rollup
	// (service_requirements.go); set by WithRequirements.
	catalog Catalog
	open    OpenResources
	conns   Connectors
	now     func() time.Time
}

// NewService wires coverage. conns says which clouds are configured: a cloud
// with a connector is in scope whether or not it has produced inventory yet.
func NewService(findings CheckIDs, inventory Inventory, registry *checks.Registry, conns Connectors) *Service {
	return &Service{findings: findings, inventory: inventory, registry: registry, conns: conns, now: time.Now}
}

// Compute reports control coverage. A control fails when any of its check_ids
// has at least one open finding; otherwise it passes only if every one of its
// in-scope checks evaluated every live asset it applies to, is partial when
// only some did, and is not assessed when none did.
// Uses a distinct-check_id query so accuracy is not bounded by the findings
// page size.
func (s *Service) Compute(ctx context.Context) (Coverage, error) {
	// Empty source = all sources; controls map to checks from cspm, ciem, k8s, etc.
	ids, err := s.findings.DistinctCheckIDs(ctx, "")
	if err != nil {
		return Coverage{}, fmt.Errorf("Compute: %w", err)
	}
	ev, err := s.assessedChecks(ctx)
	if err != nil {
		return Coverage{}, fmt.Errorf("Compute: %w", err)
	}

	failingChecks := make(map[string]bool, len(ids))
	for _, id := range ids {
		failingChecks[id] = true
	}

	cov := Coverage{Total: len(controls), Controls: make([]Status, 0, len(controls))}
	// Per-framework rollup: a control counts toward every framework it satisfies.
	fwCov := map[string]*FrameworkCoverage{}
	for _, c := range controls {
		state := controlState(c, failingChecks, ev)
		switch state {
		case StatePassing:
			cov.Passing++
		case StateFailing:
			cov.Failing++
		case StatePartial:
			cov.Partial++
		default:
			cov.NotAssessed++
		}
		c.Frameworks = frameworksFor(c.ID)
		for _, fw := range c.Frameworks {
			fc := fwCov[fw]
			if fc == nil {
				fc = &FrameworkCoverage{Framework: fw}
				fwCov[fw] = fc
			}
			fc.Total++
			switch state {
			case StatePassing:
				fc.Passing++
			case StateFailing:
				fc.Failing++
			case StatePartial:
				fc.Partial++
			default:
				fc.NotAssessed++
			}
		}
		cov.Controls = append(cov.Controls, Status{Control: c, State: state, Passing: state == StatePassing})
	}
	// Stable framework order for the UI.
	for _, fw := range []string{FrameworkCIS, FrameworkSOC2, FrameworkPCIDSS, FrameworkHIPAA} {
		if fc := fwCov[fw]; fc != nil {
			cov.Frameworks = append(cov.Frameworks, *fc)
		}
	}
	return cov, nil
}

// controlState: an open finding is evidence of failure whatever the inventory
// says; without one, the control passes only if every in-scope mapped check
// was evaluated. A check that evaluated nothing is not evidence of compliance,
// so a control with some unevaluated checks is partial, never passing. A check
// for a cloud with neither a configured connector nor inventory is out of
// scope (a two-cloud control in a single-cloud estate), not a hole in the
// evidence; a configured cloud with no inventory yet is in scope and
// unevaluated.
func controlState(c Control, failing map[string]bool, ev assessment) string {
	n, inScope := 0, 0
	for _, id := range c.CheckIDs {
		if failing[id] {
			return StateFailing
		}
		if ev.outOfScope[id] {
			continue
		}
		inScope++
		if ev.evaluated[id] {
			n++
		}
	}
	switch {
	case n == 0:
		return StateNotAssessed
	case n < inScope:
		return StatePartial
	default:
		return StatePassing
	}
}

// assessment is, per mapped check, whether it evaluated the estate and whether
// its cloud is out of scope (no configured connector and no inventory).
type assessment struct {
	evaluated  map[string]bool
	outOfScope map[string]bool
}

// assessedChecks classifies every check a control maps against one inventory
// sample read. A check is evaluated only when every live asset it applies to
// carries the evidence it reads (the requirements rollup's classify rule): a
// registry check by checks.Check.Evaluable, a CIEM rule by ciem.Graded on the
// principals of its scope. A check ID that is neither is never evaluated —
// nothing is known to evaluate it. Scope is the requirements rollup's rule: a
// cloud with a configured connector or inventory.
func (s *Service) assessedChecks(ctx context.Context) (assessment, error) {
	if s.conns == nil {
		return assessment{}, errors.New("assessedChecks: no connector source: which clouds are in scope is unknown")
	}
	var ids []string
	for _, c := range controls {
		ids = append(ids, c.CheckIDs...)
	}
	samples, inventory, err := s.sampleInventory(ctx, ids)
	if err != nil {
		return assessment{}, fmt.Errorf("assessedChecks: %w", err)
	}
	clouds, err := s.clouds(ctx, inventory)
	if err != nil {
		return assessment{}, fmt.Errorf("assessedChecks: %w", err)
	}

	ev := assessment{evaluated: map[string]bool{}, outOfScope: map[string]bool{}}
	for _, id := range ids {
		if p, ok := s.checkProvider(id); ok {
			if _, configured := clouds[string(p)]; !configured {
				ev.outOfScope[id] = true
				continue
			}
		}
		ev.evaluated[id] = s.checkEvaluated(id, samples)
	}
	return ev, nil
}

// sampleInventory reads the inventory samples the given checks are classified
// against, and which providers have inventory. The read is scoped to the
// checks' asset types and projected onto the evidence their evaluability
// reads (evidenceSpec).
func (s *Service) sampleInventory(ctx context.Context, ids []string) ([]asset.Asset, map[string]bool, error) {
	samples, err := s.inventory.Samples(ctx, s.evidenceSpec(ids))
	if err != nil {
		return nil, nil, fmt.Errorf("sampleInventory: %w", err)
	}
	providers := map[string]bool{}
	for _, a := range samples {
		providers[string(a.Provider)] = true
	}
	return samples, providers, nil
}

// evidenceSpec is what decides evaluability for the given checks: every
// registry check's RequiredKeys plus what ciem.Graded reads, the
// privilege_tier value, and each multi-key check's key set as a probe set.
func (s *Service) evidenceSpec(ids []string) EvidenceSpec {
	typeSet, keySet := map[string]bool{}, map[string]bool{}
	valueSet := map[string]bool{}
	for _, k := range ciemEvidenceValueKeys {
		valueSet[k] = true
	}
	seen := map[string]bool{}
	var probes []ProbeSet
	for _, id := range ids {
		if chk, ok := s.registry.ByID(id); ok {
			if chk.AssetType != "" {
				typeSet[chk.AssetType] = true
			}
			for _, k := range chk.RequiredKeys {
				keySet[k] = true
				// IAM evaluability removes partial role/tier evidence before
				// probing. Raw-present keys may therefore participate in a probe;
				// their values cannot be collapsed based on raw missingness alone.
				if chk.Provider == asset.ProviderGCP && chk.AssetType == "gcp_service_account" ||
					chk.Provider == asset.ProviderAWS && (chk.AssetType == "iam_role" || chk.AssetType == "iam_user") && slices.Contains(chk.RequiredKeys, ciem.MetaPrivilegeTier) {
					valueSet[k] = true
				}
			}
			if len(chk.RequiredKeys) > 1 && !seen[id] {
				seen[id] = true
				probes = append(probes, ProbeSet{Provider: string(chk.Provider), Type: chk.AssetType, Keys: slices.Sorted(slices.Values(chk.RequiredKeys))})
			}
		} else if sc, ok := ciemScopeFor(id); ok {
			for _, t := range sc.types {
				typeSet[t] = true
			}
		}
	}
	for _, k := range ciemEvidenceKeys {
		keySet[k] = true
	}
	return EvidenceSpec{
		Types:     sortedKeys(typeSet),
		Keys:      sortedKeys(keySet),
		ValueKeys: sortedKeys(valueSet),
		Probes:    probes,
	}
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// checkProvider is the cloud a check reads; false for an unknown check ID.
func (s *Service) checkProvider(id string) (asset.Provider, bool) {
	if chk, ok := s.registry.ByID(id); ok {
		return chk.Provider, true
	}
	if sc, ok := ciemScopeFor(id); ok {
		return sc.provider, true
	}
	return "", false
}

func (s *Service) checkEvaluated(id string, samples []asset.Asset) bool {
	if _, ok := s.registry.ByID(id); ok {
		return s.classify(id, samples) == evEvaluated
	}
	sc, ok := ciemScopeFor(id)
	if !ok {
		return false
	}
	seen := false
	for _, a := range samples {
		if a.Provider != sc.provider || !slices.Contains(sc.types, a.Type) {
			continue
		}
		if !ciem.Graded(a) {
			return false
		}
		seen = true
	}
	return seen
}

// Coverage is an alias for Compute that satisfies the chat.ComplianceReader interface.
func (s *Service) Coverage(ctx context.Context) (Coverage, error) {
	return s.Compute(ctx)
}
