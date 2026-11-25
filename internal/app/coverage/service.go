package coverage

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/graphschema"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// liveSource is the measurement port. Service defines it: the
// repository satisfies it, and a nil one means offline.
type liveSource interface {
	Facts(ctx context.Context) (LiveFacts, error)
}

// Service derives the coverage report. Everything it produces comes from the
// checks registry, the graphschema edge registry, an AST scan of the tree, or
// live ClickHouse counts — never from a value typed into this file.
type Service struct {
	registry *checks.Registry
	live     liveSource
	// srcDir is the tree DeclaredSources walks.
	srcDir string
	now    func() time.Time
}

// NewService returns a Service. live may be nil, which produces an offline
// report: the registry-derived half, with the live sections marked as needing a
// connection. CI has no ClickHouse connection, so offline is a first-class
// mode, not a failure.
func NewService(registry *checks.Registry, live liveSource, srcDir string) *Service {
	return &Service{registry: registry, live: live, srcDir: srcDir, now: func() time.Time { return time.Now().UTC() }}
}

// Build produces the report.
func (s *Service) Build(ctx context.Context) (Report, error) {
	r := Report{GeneratedAt: s.now(), FreshAssets: map[string]uint64{}}

	declared, err := DeclaredSources(s.srcDir)
	if err != nil {
		return Report{}, fmt.Errorf("Build: %w", err)
	}

	var facts LiveFacts
	if s.live != nil {
		facts, err = s.live.Facts(ctx)
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Msg("coverage: live measurement failed, degrading to offline")
			r.LiveErr = err.Error()
		} else {
			r.Live = true
			r.FailedSteps = facts.Failed
			if len(facts.QueryErrors) > 0 {
				r.LiveErr = fmt.Sprintf("%d of the measurements failed: %v", len(facts.QueryErrors), facts.QueryErrors)
			}
		}
	} else {
		r.LiveErr = ErrNoLiveData.Error()
	}

	idx := newIndex(s.registry, facts, r.Live)
	r.Checks = idx.checkFacts()
	r.Edges = idx.edgeFacts()
	r.UnreadKeys, r.UnreadKeyTotal = idx.unreadKeys()
	r.EmptyAssetTypes = idx.emptyAssetTypes()
	r.Sources = idx.sourceFacts(declared)
	if r.Live {
		r.Categories = idx.categoryFacts()
		r.Stages = idx.stageFacts()
		r.Advisory, r.AdvisoryGaps = idx.advisoryFacts(r.GeneratedAt)
		for _, a := range facts.Assets {
			r.FreshAssets[a.Provider] += a.Count
		}
	}
	return r, nil
}

// index holds every cross-reference the derivations need, built once.
type index struct {
	registry  *checks.Registry
	allChecks []checks.Check
	facts     LiveFacts
	live      bool

	// freshByProviderType and freshByType are deduped fresh asset counts.
	freshByProviderType map[[2]string]uint64
	freshByType         map[string]uint64
	// typeProvider is the provider that owns an asset type (the one with the
	// most fresh rows, so a type name reused across clouds resolves to where it
	// actually lives).
	typeProvider map[string]string
	// keyAssets[provider][type][key] is how many fresh assets carry the key.
	keyAssets map[[2]string]map[string]uint64
	// readKeys[provider][type] is every key a check applicable there reads.
	readKeys map[[2]string]map[string][]string
	// keyReaders is every check reading a key, anywhere.
	keyReaders map[string][]string
	// scoringSrc is the set of types the BFS can reach directly: sources of a
	// fresh internet seed, or destinations of a fresh reach edge.
	scoringSrc map[string]bool
	// inheritDst are types that take a hop count as the DESTINATION of a fresh
	// Inherit edge (a package inside a reached image), and inheritReverseSrc as
	// the SOURCE of a fresh InheritReverse edge (a repo deploying to a reached
	// workload). Both are hop-RECEIVING sides; see indexEdges.
	inheritDst        map[string]bool
	inheritReverseSrc map[string]bool
	// edgeSrcDistinct[edge][srcType] and edgeDstDistinct[edge][dstType].
	edgeSrcDistinct map[string]map[string]uint64
	edgeDstDistinct map[string]map[string]uint64
	metaValues      map[[3]string]uint64 // [type, key, value] → fresh assets; see inventory.go
	// resourcesByCategory[source][type] are the resource types carrying open findings.
	resourcesByCategory map[[2]string][]ResourceTypeCount
	// producers[source][type] are the REGISTERED checks that emitted this
	// category's open findings, and foreignProducers the check_ids it carries
	// that the registry does not know (nuclei templates, supply-chain advisory
	// IDs). Keeping the second set is what lets a category say WHY the evidence
	// axis does not apply to it instead of silently skipping the rule.
	producers        map[[2]string][]string
	foreignProducers map[[2]string][]string
	// checkList and checkFactByID are the derived CheckFacts, built once in
	// newIndex because deriveAxis depends on them.
	checkList     []CheckFact
	checkFactByID map[string]CheckFact
}

func newIndex(registry *checks.Registry, facts LiveFacts, live bool) *index {
	i := &index{
		registry:            registry,
		allChecks:           registry.All(),
		facts:               facts,
		live:                live,
		freshByProviderType: map[[2]string]uint64{},
		freshByType:         map[string]uint64{},
		typeProvider:        map[string]string{},
		keyAssets:           map[[2]string]map[string]uint64{},
		readKeys:            map[[2]string]map[string][]string{},
		keyReaders:          map[string][]string{},
		scoringSrc:          map[string]bool{},
		inheritDst:          map[string]bool{},
		inheritReverseSrc:   map[string]bool{},
		edgeSrcDistinct:     map[string]map[string]uint64{},
		edgeDstDistinct:     map[string]map[string]uint64{},
		resourcesByCategory: map[[2]string][]ResourceTypeCount{},
		producers:           map[[2]string][]string{},
		foreignProducers:    map[[2]string][]string{},
		checkFactByID:       map[string]CheckFact{},
	}
	best := map[string]uint64{}
	for _, a := range facts.Assets {
		i.freshByProviderType[[2]string{a.Provider, a.AssetType}] += a.Count
		i.freshByType[a.AssetType] += a.Count
		if a.Count > best[a.AssetType] {
			best[a.AssetType] = a.Count
			i.typeProvider[a.AssetType] = a.Provider
		}
	}
	for _, k := range facts.Keys {
		pt := [2]string{k.Provider, k.AssetType}
		if i.keyAssets[pt] == nil {
			i.keyAssets[pt] = map[string]uint64{}
		}
		i.keyAssets[pt][k.Key] += k.Assets
	}
	i.indexRegistry()
	i.indexEdges()
	i.indexMetaValues()
	// Check facts are built here, not lazily in checkFacts(): deriveAxis reads
	// them for the evidence rule, and an index whose caller had to remember to
	// populate it first is an index that silently answers "covered".
	i.buildCheckFacts()
	for _, rc := range facts.Resources {
		key := [2]string{rc.Source, rc.Type}
		i.resourcesByCategory[key] = append(i.resourcesByCategory[key], rc)
	}
	i.indexProducers()
	return i
}

// indexProducers splits each category's emitting check_ids into those the
// registry knows and those it does not. A check_id absent from the registry is
// normal — nuclei carries template IDs, supply_chain carries advisory IDs —
// so it is recorded rather than treated as an error or dropped on the floor.
func (i *index) indexProducers() {
	for _, cc := range i.facts.CategoryChecks {
		key := [2]string{cc.Source, cc.Type}
		if _, ok := i.registry.ByID(cc.CheckID); ok {
			i.producers[key] = appendUnique(i.producers[key], cc.CheckID)
			continue
		}
		i.foreignProducers[key] = appendUnique(i.foreignProducers[key], cc.CheckID)
	}
	for k := range i.producers {
		sort.Strings(i.producers[k])
	}
	for k := range i.foreignProducers {
		sort.Strings(i.foreignProducers[k])
	}
}

// indexRegistry maps required keys to the provider/type pairs that read them.
// A check with an empty AssetType applies to every type of its provider, so its
// keys are read everywhere that provider has assets.
func (i *index) indexRegistry() {
	for _, c := range i.allChecks {
		for _, k := range c.RequiredKeys {
			i.keyReaders[k] = appendUnique(i.keyReaders[k], c.ID)
		}
		provider := string(c.Provider)
		types := []string{c.AssetType}
		if c.AssetType == "" {
			types = i.typesOfProvider(provider)
		}
		for _, t := range types {
			pt := [2]string{provider, t}
			if i.readKeys[pt] == nil {
				i.readKeys[pt] = map[string][]string{}
			}
			for _, k := range c.RequiredKeys {
				i.readKeys[pt][k] = appendUnique(i.readKeys[pt][k], c.ID)
			}
		}
	}
}

func (i *index) typesOfProvider(provider string) []string {
	var out []string
	for pt := range i.freshByProviderType {
		if pt[0] == provider {
			out = append(out, pt[1])
		}
	}
	sort.Strings(out)
	return out
}

// indexEdges builds the per-edge-type endpoint volumes and, from them, the set
// of resource types that can RECEIVE an internet_hops value.
//
// Which side of an edge delivers a distance depends on the mechanism; testing
// the source side for all of them is wrong:
//
//	seed (exposed_to_internet)  the SRC is the entry point
//	Reach                       the DST is reached, from an already-reached src
//	Inherit                     the DST inherits (image → package)
//	InheritReverse              the SRC inherits (repo → workload)
//
// Testing the src of an Inherit edge said "container_image can be scored"
// because it is the source of runs_package, which is true only by accident —
// what makes an image scorable is being the DESTINATION of runs_image. On the
// same logic a package, which is never the source of anything, could never be
// judged scorable at all.
func (i *index) indexEdges() {
	reach := graphschema.ReachEdgeTypes()
	inherit := graphschema.InheritEdgeTypes()
	inheritReverse := graphschema.InheritReverseEdgeTypes()
	seed := map[string]bool{}
	for _, t := range ScoringSeedEdgeTypes {
		seed[t] = true
	}
	for _, e := range i.facts.EdgesBySrc {
		if i.edgeSrcDistinct[e.EdgeType] == nil {
			i.edgeSrcDistinct[e.EdgeType] = map[string]uint64{}
		}
		i.edgeSrcDistinct[e.EdgeType][e.EndpointType] += e.Distinct
		if e.Distinct == 0 {
			continue
		}
		if seed[e.EdgeType] {
			i.scoringSrc[e.EndpointType] = true
		}
		if inheritReverse[e.EdgeType] {
			i.inheritReverseSrc[e.EndpointType] = true
		}
	}
	for _, e := range i.facts.EdgesByDst {
		if i.edgeDstDistinct[e.EdgeType] == nil {
			i.edgeDstDistinct[e.EdgeType] = map[string]uint64{}
		}
		i.edgeDstDistinct[e.EdgeType][e.EndpointType] += e.Distinct
		if e.Distinct == 0 {
			continue
		}
		if reach[e.EdgeType] {
			i.scoringSrc[e.EndpointType] = true
		}
		if inherit[e.EdgeType] {
			i.inheritDst[e.EndpointType] = true
		}
	}
}

// checkFacts returns the derived CheckFacts, ID-ordered.
func (i *index) checkFacts() []CheckFact { return i.checkList }

// buildCheckFacts derives one CheckFact per registered check, attaching the
// evidence measurement when live.
func (i *index) buildCheckFacts() {
	all := i.allChecks
	out := make([]CheckFact, 0, len(all))
	for _, c := range all {
		f := CheckFact{
			ID: c.ID, Title: c.Title, Provider: string(c.Provider), AssetType: c.AssetType,
			Type: c.Type, Severity: string(c.Severity),
			RequiredKeys: append([]string(nil), c.RequiredKeys...),
		}
		sort.Strings(f.RequiredKeys)
		if i.live {
			f.EvidenceKnown = true
			f.OpenFindings = i.facts.CheckOpen[c.ID]
			f.EvidenceKeys, f.SuppressorKeys = i.splitKeys(c)
			f.Applicable, f.WorstKey, f.WorstKeyPresent = i.evidence(string(c.Provider), c.AssetType, f.EvidenceKeys)
		}
		out = append(out, f)
		i.checkFactByID[f.ID] = f
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	i.checkList = out
}

// splitKeys classifies a check's required keys into evidence-bearing and
// suppressor keys, taking the union over every asset type the check applies to:
// a key that can hide a violation on any one of them is a real gap, and a
// provider-wide check must not be excused by the types where it cannot.
func (i *index) splitKeys(c checks.Check) (evidence, suppressor []string) {
	types := []string{c.AssetType}
	if c.AssetType == "" {
		// Classify against every type the provider actually has; falling back to
		// the unset type keeps the classification independent of whether the
		// estate happens to hold assets today.
		if of := i.typesOfProvider(string(c.Provider)); len(of) > 0 {
			types = of
		}
	}
	isEvidence := map[string]bool{}
	for _, t := range types {
		ev, _ := evidenceKeys(c, t)
		for _, k := range ev {
			isEvidence[k] = true
		}
	}
	for _, k := range c.RequiredKeys {
		if isEvidence[k] {
			evidence = appendUnique(evidence, k)
		} else {
			suppressor = appendUnique(suppressor, k)
		}
	}
	sort.Strings(evidence)
	sort.Strings(suppressor)
	return evidence, suppressor
}

// evidence returns how many fresh assets a check applies to and which of its
// evidence-bearing required keys is present on the fewest of them.
func (i *index) evidence(provider, assetType string, keys []string) (applicable uint64, worstKey string, worstPresent uint64) {
	types := []string{assetType}
	if assetType == "" {
		types = i.typesOfProvider(provider)
	}
	for _, t := range types {
		applicable += i.freshByProviderType[[2]string{provider, t}]
	}
	if len(keys) == 0 {
		return applicable, "", applicable
	}
	worstPresent = ^uint64(0)
	for _, k := range keys {
		var present uint64
		for _, t := range types {
			present += i.keyAssets[[2]string{provider, t}][k]
		}
		if present < worstPresent {
			worstPresent, worstKey = present, k
		}
	}
	return applicable, worstKey, worstPresent
}

// edgeFacts joins the graphschema registry with live fresh volumes. The graph
// axis is a property of this table.
func (i *index) edgeFacts() []EdgeFact {
	rels := map[string]graphschema.Rel{}
	for _, r := range graphschema.Rels {
		rels[r.Name] = r
	}
	out := make([]EdgeFact, 0, len(graphschema.EdgeTypes))
	for _, e := range graphschema.EdgeTypes {
		f := EdgeFact{
			Type: e.Type, Rel: e.Rel, Tier: string(e.Tier),
			Reach: e.Reach, Inherit: e.Inherit, Doc: e.Doc,
		}
		if rel, ok := rels[e.Rel]; ok {
			f.Loaded, f.Expand, f.DropReason = rel.Loaded, rel.Expand, rel.DropReason
		}
		if i.live {
			f.LiveKnown = true
			f.Rows = i.facts.EdgeTotals[e.Type]
			for _, n := range i.edgeSrcDistinct[e.Type] {
				f.DistinctSrc += n
			}
		}
		out = append(out, f)
	}
	return out
}

// unreadKeysCap bounds how many rows the check axis renders. The full count is
// reported alongside, so the cap hides volume, never the existence of a gap.
const unreadKeysCap = 40

// unreadKeys measures the check axis: keys the registry reads somewhere, that
// are present on assets nothing asserts on.
func (i *index) unreadKeys() ([]UnreadKey, int) {
	var out []UnreadKey
	for pt, keys := range i.keyAssets {
		for key, n := range keys {
			readers, assertable := i.keyReaders[key]
			if !assertable {
				continue // descriptive metadata, not something the platform asserts on
			}
			if len(i.readKeys[pt][key]) > 0 {
				continue // a check for this exact provider/type already reads it
			}
			out = append(out, UnreadKey{Provider: pt[0], AssetType: pt[1], Key: key, Assets: n, ReadBy: readers})
		}
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Assets != out[b].Assets {
			return out[a].Assets > out[b].Assets
		}
		return out[a].AssetType+out[a].Key < out[b].AssetType+out[b].Key
	})
	total := len(out)
	if len(out) > unreadKeysCap {
		out = out[:unreadKeysCap]
	}
	return out, total
}

// emptyAssetTypes are the asset types a registered check targets that hold no
// fresh assets at all — the collected axis at check granularity.
func (i *index) emptyAssetTypes() []string {
	if !i.live {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range i.allChecks {
		if c.AssetType == "" || seen[c.AssetType] {
			continue
		}
		seen[c.AssetType] = true
		if i.freshByProviderType[[2]string{string(c.Provider), c.AssetType}] == 0 {
			out = append(out, c.AssetType)
		}
	}
	sort.Strings(out)
	return out
}

func (i *index) sourceFacts(declared []string) []SourceFact {
	byName := map[string]SourceFact{}
	for _, s := range declared {
		byName[s] = SourceFact{Source: s, Declared: true}
	}
	for _, s := range i.facts.Sources {
		f := byName[s.Source]
		f.Source = s.Source
		f.Total, f.Open, f.LastDetected = s.Total, s.Open, s.LastDetected
		byName[s.Source] = f
	}
	out := make([]SourceFact, 0, len(byName))
	for _, f := range byName {
		out = append(out, f)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Open != out[b].Open {
			return out[a].Open > out[b].Open
		}
		return out[a].Source < out[b].Source
	})
	return out
}

func (i *index) stageFacts() []StageFact {
	counts := map[string]uint64{}
	facts := make([]StageFact, 0, len(LineageStages))
	for _, st := range LineageStages {
		f := StageFact{LineageStage: st, Count: i.stageCount(st)}
		counts[st.Name] = f.Count
		facts = append(facts, f)
	}
	for n := range facts {
		if of := facts[n].OfStage; of != "" {
			facts[n].OfCount = counts[of]
		}
	}
	return facts
}

func (i *index) stageCount(st LineageStage) uint64 {
	filter := map[string]bool{}
	for _, t := range st.Types {
		filter[t] = true
	}
	var total uint64
	switch st.Kind {
	case StageAssets:
		for _, t := range st.Types {
			total += i.freshByType[t]
		}
	case StageEdgeSrc:
		for endpoint, n := range i.edgeSrcDistinct[st.EdgeType] {
			if len(filter) == 0 || filter[endpoint] {
				total += n
			}
		}
	case StageEdgeDst:
		for endpoint, n := range i.edgeDstDistinct[st.EdgeType] {
			if len(filter) == 0 || filter[endpoint] {
				total += n
			}
		}
	case StageAssetMeta:
		total = i.metaStageCount(st)
	}
	return total
}

// resourceTypeSample bounds how many resource types a category names.
const resourceTypeSample = 4

func (i *index) categoryFacts() []CategoryFact {
	out := make([]CategoryFact, 0, len(i.facts.Bands))
	for _, b := range i.facts.Bands {
		c := CategoryFact{
			Source: b.Source, Type: b.Type,
			Open: b.Open, Blank: b.Blank, Routine: b.Routine, Page: b.Page, High: b.High,
		}
		rts := i.resourcesByCategory[[2]string{b.Source, b.Type}]
		sort.Slice(rts, func(a, z int) bool { return rts[a].Open > rts[z].Open })
		for n, rt := range rts {
			if n >= resourceTypeSample {
				break
			}
			c.ResourceTypes = append(c.ResourceTypes, rt.ResourceType)
		}
		c.Axis, c.Because, c.Target, c.NeedsDecision = i.deriveAxis(rts, c)
		out = append(out, c)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Open != out[b].Open {
			return out[a].Open > out[b].Open
		}
		return out[a].Source+out[a].Type < out[b].Source+out[b].Type
	})
	return out
}

// deriveAxis applies the four rules in Axes order and returns the first that
// fails, the measurement that made it fail, and the condition that would close
// it. No per-category judgement is applied: the same inputs always produce the
// same axis, which is what makes a change between two runs a real change.
func (i *index) deriveAxis(rts []ResourceTypeCount, c CategoryFact) (Axis, string, string, bool) {
	types := make([]string, 0, len(rts))
	for _, rt := range rts {
		types = append(types, rt.ResourceType)
	}
	if len(types) == 0 {
		return AxisCollected, "no open finding carries a resource type, so nothing can be joined to an asset",
			"the producer must stamp resource_type on its findings", false
	}

	if a, why, target := i.collectedRule(types); a != "" {
		return a, why, target, false
	}
	a, why, target, evidenceNote := i.evidenceRule(c.Source, c.Type)
	if a != "" {
		return a, why, target, false
	}
	// The check axis only applies to a category some registered check produces.
	//
	// checkRule works on resource TYPES, so for a category whose findings come
	// from a source the registry knows nothing about — an external scanner, the
	// OSV matcher, the CIEM engine — it reports whichever key on a shared type
	// happens to be unread and blames this category for it. That produced four
	// verdicts covering a large number of open findings, every one of them a
	// category error: `instance_id` on ec2_instance for aws_guardduty (a join key,
	// not a control), `version` on github/package for supply_chain (read by the
	// OSV matcher), `policies` on iam_role for ciem_privesc (read by the CIEM
	// engine), `public` on dns_record for nuclei. The findings themselves are
	// proof that something reads the data.
	//
	// Same defect the evidence rule was corrected for, one axis later: attributing
	// a resource-type-level observation to whichever category happens to list that
	// type. evidenceRule already computed the answer and returned it as a note; it
	// just was not allowed to stop the pipeline.
	//
	// The unread keys are still worth knowing about, so they are reported as a
	// standalone inventory (UnreadKeys) rather than as a verdict on a category
	// that did not earn it.
	//
	// Gated on producers rather than on evidenceNote being empty: a note is also
	// set when producers exist but all decide on structural fields alone, and
	// there the check axis is perfectly legitimate.
	if len(i.producers[[2]string{c.Source, c.Type}]) > 0 {
		if a, why, target := i.checkRule(types); a != "" {
			return a, why, target, false
		}
	}
	if a, why, target := i.graphRule(types); a != "" {
		return a, why, target, false
	}
	target = "nothing measurable is missing"
	decision := false
	// Every axis is closed, so what is left is one of two different things, and
	// naming the wrong one sends the reader to the wrong team. `routine` is the
	// classifier's verdict — weighed, no urgency evidence — so the only open
	// question about it is a prioritisation decision. A blank class is the absence
	// of a verdict: enrichment has not run on those rows, or failed open on
	// missing evidence (for example unknown repo visibility, a truncated
	// supply-chain walk, a package or code-scanning alert with no deployment
	// lineage, or no RBAC subject evidence). That is enrichment or evidence, not a
	// decision.
	switch {
	case c.Routine > 0:
		target = fmt.Sprintf("%d of %d open findings are classed `routine` (weighed, no urgency evidence) with every axis closed — whether any of that population should rank higher is a prioritisation decision, not more coverage", c.Routine, c.Open)
		decision = true
	case c.Blank > 0:
		target = fmt.Sprintf("%d of %d open findings carry no must_fix_class at all with every axis closed — enrichment has not reached them (the enrich sweep closes that) or failed open on missing evidence, not a product decision", c.Blank, c.Open)
	}
	if evidenceNote == "" {
		evidenceNote = "evidence present"
	}
	return AxisCovered, "assets collected, " + evidenceNote + ", checks assert on the resource types, and they carry scoring edges", target, decision
}

func (i *index) collectedRule(types []string) (Axis, string, string) {
	var empty []string
	for _, t := range types {
		if i.freshByType[t] == 0 {
			empty = append(empty, t)
		}
	}
	if len(empty) != len(types) {
		return "", "", ""
	}
	return AxisCollected,
		fmt.Sprintf("every resource type carrying these findings (%s) has zero fresh assets", join(empty, resourceTypeSample)),
		fmt.Sprintf("a collector must produce rows for %s; today it produces none, so no check, edge or score can apply", join(empty, resourceTypeSample))
}

// evidenceRule measures the evidence axis over the checks that ACTUALLY
// produced this category's open findings, joined by check_id. Scanning every
// check that merely shares a resource type is how six unrelated categories —
// terraform state, IaC misconfiguration, GHAS secrets, CI federation, code
// scanning and cspm exposure — were all told to go emit `branch_protection`:
// they carry `github_repo` among their resource types, and nothing else.
//
// The fourth return value is a note for the covered case: when the axis cannot
// apply at all, saying so is a truer answer than borrowing another concern's
// check.
func (i *index) evidenceRule(source, typ string) (Axis, string, string, string) {
	key := [2]string{source, typ}
	producers := i.producers[key]
	if len(producers) == 0 {
		return "", "", "", i.noProducerNote(key)
	}
	var worst CheckFact
	measurable := 0
	for _, id := range producers {
		f, ok := i.checkFactByID[id]
		if !ok || f.EvidenceBlind() || f.Applicable == 0 {
			continue
		}
		measurable++
		if f.EvidenceBound() >= 1.0 {
			continue // fully evidenced — never a candidate for "worst"
		}
		// Among checks with a REAL evidence gap, the one carrying the most open
		// findings in THIS category is a truer "Because" than the lowest raw
		// percentage: a check with a thin applicable-asset denominator can post a
		// worse percentage than one carrying orders of magnitude more open volume,
		// and citing the former as "the" explanation for the category is actively
		// misleading. For example, a check with a handful of open findings and
		// under 1% evidence must not be cited as the "Because" for a category
		// whose open volume sits in fully evidenced checks that are correctly
		// blank on must_fix_class (no positive exploitability evidence, not a
		// gap) — that citation points at a rounding error, not the explanation.
		if worst.ID == "" || f.OpenFindings > worst.OpenFindings ||
			(f.OpenFindings == worst.OpenFindings && f.EvidenceBound() < worst.EvidenceBound()) {
			worst = f
		}
	}
	if worst.ID == "" {
		if measurable == 0 {
			return "", "", "", fmt.Sprintf("every check producing these findings (%s) decides on structural fields or suppressor keys alone, so the evidence axis does not apply",
				join(producers, resourceTypeSample))
		}
		return "", "", "", ""
	}
	worstBound := worst.EvidenceBound()
	return AxisEvidence,
		fmt.Sprintf("`%s` produces these findings and reads `%s`, present on %d of %d fresh applicable assets (%.1f%%)",
			worst.ID, worst.WorstKey, worst.WorstKeyPresent, worst.Applicable, 100*worstBound),
		fmt.Sprintf("the collector must emit `%s` on the remaining %d assets `%s` applies to; until then that check's silence is missing data, not a clean result",
			worst.WorstKey, worst.Applicable-worst.WorstKeyPresent, worst.ID),
		""
}

// noProducerNote states why the evidence axis cannot apply to a category no
// registered check emits.
func (i *index) noProducerNote(key [2]string) string {
	if foreign := i.foreignProducers[key]; len(foreign) > 0 {
		return fmt.Sprintf("these findings carry %d check IDs the registry does not know (%s), so no `Check.RequiredKeys` describes them and the evidence axis does not apply",
			len(foreign), join(foreign, resourceTypeSample))
	}
	return "no open finding in this category carries a check_id, so it comes from a source with no registered check and the evidence axis does not apply"
}

func (i *index) checkRule(types []string) (Axis, string, string) {
	var best UnreadKey
	for _, t := range types {
		pt := [2]string{i.typeProvider[t], t}
		for key, n := range i.keyAssets[pt] {
			readers, assertable := i.keyReaders[key]
			if !assertable || len(i.readKeys[pt][key]) > 0 || n <= best.Assets {
				continue
			}
			best = UnreadKey{Provider: pt[0], AssetType: t, Key: key, Assets: n, ReadBy: readers}
		}
	}
	if best.Key == "" {
		return "", "", ""
	}
	return AxisCheck,
		fmt.Sprintf("`%s` is observed on %d fresh %s/%s assets and read by no check for that type (it is read by `%s` elsewhere)",
			best.Key, best.Assets, best.Provider, best.AssetType, best.ReadBy[0]),
		fmt.Sprintf("register a check for %s/%s that asserts on `%s` — the data has been collected all along",
			best.Provider, best.AssetType, best.Key)
}

// graphRule asks whether a resource type can receive an internet_hops value at
// all. That is NOT the same as being the source of a reach edge, and reading it
// that way under-reports coverage:
//
//   - a package is never the SOURCE of anything; it takes its hop count as the
//     DESTINATION of runs_package, which is the whole point of the Inherit set.
//   - a github_repo takes its hop count as the SOURCE of deploys_to, an
//     InheritReverse edge, and as the DESTINATION of defined_in.
//
// So the test is over all three mechanisms the BFS actually has, on the side
// each one delivers a distance to. A test over reach-edge sources alone would
// report packages and repos dark however their hop counts are wired.
func (i *index) graphRule(types []string) (Axis, string, string) {
	var dark []string
	for _, t := range types {
		if !i.scoringSrc[t] && !i.inheritDst[t] && !i.inheritReverseSrc[t] {
			dark = append(dark, t)
		}
	}
	if len(dark) != len(types) {
		return "", "", ""
	}
	return AxisGraph,
		fmt.Sprintf("%s is the source of no fresh reach-set, inherit or internet-seed edge, so the internet-hops BFS can never assign it a hop count", join(dark, resourceTypeSample)),
		fmt.Sprintf("an edge producer must emit a reach or seed edge from %s; scoring cannot demote or promote what the graph cannot reach", join(dark, resourceTypeSample))
}

func join(v []string, limit int) string {
	if len(v) > limit {
		return fmt.Sprintf("%s (+%d more)", commaJoin(v[:limit]), len(v)-limit)
	}
	return commaJoin(v)
}

func commaJoin(v []string) string {
	out := ""
	for n, s := range v {
		if n > 0 {
			out += ", "
		}
		out += "`" + s + "`"
	}
	return out
}

func appendUnique(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}
