package respond

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// maxPeers / maxPathHops bound the pack so the prompt stays small.
const (
	maxPeers     = 15
	maxPathHops  = 10
	maxRepos     = 10  // max depends_on repos for supply-chain path
	maxWorkloads = 20  // max deploysTo workloads for supply-chain path
	maxRoles     = 5   // max attached IAM roles for identity chain
	advisoryLen  = 400 // max advisory text length injected into prompt
)

// Asset age buckets: brand-new resources and ones that have stopped
// appearing in syncs are both worth the reasoner's attention; the middle is the
// boring steady state. Bucketed, never raw timestamps, so the fingerprint does
// not churn every sweep.
const (
	newAssetAge   = 7 * 24 * time.Hour
	staleAssetAge = 7 * 24 * time.Hour
)

// ContextPack is the connected-graph context the reasoner sees for one finding:
// not just the finding, but its blast radius, the other findings on
// its resource, the privilege paths out of it, and derived exposure — so the
// model can tell a real risk from a finding with no meaningful risk.
type ContextPack struct {
	Finding    finding.Finding
	Blast      BlastSummary
	Peers      []PeerSummary
	Exposure   ExposureFlags
	Provenance Provenance

	// Impact is the action-independent "safe to fix" context: what depends on the
	// resource (would break if it changed), whether it looks unused, and where a
	// fix should be applied. Fed to the reasoner so it can weigh remediation impact,
	// not just attack blast radius.
	Impact ImpactAssessment

	// Factors is the per-source score breakdown. Explains WHY
	// the score is what it is — base severity + blast + KEV floor + EPSS points etc.
	// Nil when the signals row has not been written yet (first enrich cycle).
	// Loaded by Decide before the reasoning fingerprint (FactorsKnown is part of
	// it); the Context read path does not load it.
	Factors []enrich.Factor
	// FactorsKnown is true only when the factors read succeeded. False (read
	// failed, or no reader wired) renders as "unknown" to the reasoner, never
	// as an empty breakdown.
	FactorsKnown bool

	// CVE is populated for findings whose CheckID is a CVE ID. Carries EPSS
	// exploitation probability, KEV status, the fix version (from OSV), and a
	// trimmed advisory summary. Nil for non-CVE findings.
	CVE *CVEContext

	// Identity is the execution-identity chain for workload assets: what IAM role
	// the workload runs as, what roles are attached, and what repos have federated
	// access to that role via OIDC. Nil for non-workload or when graph edges are
	// absent.
	Identity *IdentityLinks

	// SupplyChain is the blast path for supply_chain source findings: which repos
	// include this vulnerable package and which workloads those repos deploy to.
	// Nil for non-supply_chain findings.
	SupplyChain *SupplyChainPath
}

// Provenance is where a resource came from: which connector synced it,
// in which account/region, who owns it, and whether it's freshly appeared or
// going stale. Lets the reasoner weigh "owned prod resource, real risk" against
// "orphaned, no owner, isolated — no meaningful risk". Derived from the seed asset.
type Provenance struct {
	Connector   string // prov_connector_type stamped at sync (e.g. "aws")
	AccountID   string
	Region      string
	Owner       string // owner/team tag, if any
	Environment string // the owner's own environment tag value, if any (shown to the reasoner)
	AgeBucket   string // "new" | "established" | "stale" | "" (unknown)
	// Env is the classified environment (asset.ClassifyEnvironment), which is
	// what the safety band decides on. Kept beside the raw label rather than
	// replacing it so the reason fingerprint (prov:env) does not churn.
	Env asset.EnvClassification

	// Supply-chain lineage: the github repo that deploys to
	// this resource, via the deploys_to correlation edge, with the edge's match
	// confidence so the reasoner weighs a medium-confidence link as a hint.
	SourceRepo       string
	SourceConfidence string
}

// BlastSummary summarizes the blast-radius walk (counts + types, not raw assets,
// to bound tokens) plus the privilege-escalation edges out of the resource.
type BlastSummary struct {
	Count int
	// Known is false when the walk that produced Count failed (or nothing
	// walked at all) — the same known-ness blastRadiusFor already computes,
	// carried through so a caller can never mistake "unmeasured" for a
	// measured "0 reachable assets". See summarizeBlast.
	Known        bool
	ByType       map[string]int
	CanAssume    []string   // "src -> dst" can_assume / can_escalate edges, capped
	TopReachable []AssetRef // top-5 reachable assets by risk score (from Ladybug signal; empty on CH walk)
	Truncated    bool

	// GraphAssets and GraphEdges are the raw BFS result — populated only when
	// assembled for the finding-detail UI (findingctx). Nil in the reasoning path
	// (where tokens matter more than graph fidelity).
	GraphAssets []AssetRef
	GraphEdges  []EdgeRef
}

// EdgeRef is a lightweight directed edge for the blast-radius graph view.
type EdgeRef struct {
	SrcID    string
	DstID    string
	EdgeType string
}

// AssetRef is a lightweight reference to a reachable asset with its risk score.
// Populated from Ladybug's MaxScore signal column when the Ladybug blast provider is used.
type AssetRef struct {
	ID    string
	Name  string
	Type  string
	Score uint8
}

// PeerSummary is another finding on the same resource.
// Score and Title let the reasoner rank co-located risk.
type PeerSummary struct {
	Type      string
	CheckID   string
	ScoreBand string
	Score     uint8
	Title     string
}

// ExposureFlags are crisp signals derived (in code, not by the LLM) from the
// resource's peer findings — the toxic-combo axes the model keys on.
type ExposureFlags struct {
	InternetFacing bool
	Privileged     bool
	// PeersKnown is false when the peer-findings query these flags are
	// derived from failed — as opposed to succeeding and finding no exposure
	// peer. Without this, a failed query and a genuinely clean resource were
	// indistinguishable: InternetFacing stayed at its zero value either way,
	// and the belief adjudicator's corroboration gate (GroundingFacts.
	// ExposureConfirmed, sourced from this field) would silently agree a
	// demotion has no conflicting witness when the truth is it never
	// checked.
	PeersKnown bool
}

// CVEContext carries CVE-specific intel for findings whose CheckID is a CVE.
// EPSS is the live exploit probability from FIRST.org (in-memory, not stored).
// FixedVersion comes from the OSV-synced finding.Remediation field.
type CVEContext struct {
	CVEID        string
	EPSS         float64
	EPSSBand     string // "critical" / "high" / "moderate" / "low"
	KEV          bool   // CISA Known-Exploited
	FixedVersion string // from finding.Remediation (OSV-synced)
	Advisory     string // trimmed finding.Description (OSV advisory summary)
}

// IdentityLinks is the execution-identity chain for a workload: what IAM role it
// runs as (executes_as edge), attached roles (has_role), and repos that have
// federated OIDC access to that execution role.
type IdentityLinks struct {
	ExecutesAsID     string   // ARN/ID of the role this asset executes as
	AttachedRoleIDs  []string // IAM role IDs attached to the asset
	FederatedRepoIDs []string // repo IDs with federated_access to the execution role
}

// WorkloadSummary is a workload that a repo deploys to, derived from deploys_to edges.
type WorkloadSummary struct {
	ID   string
	Type string // from edge DstType
}

// SupplyChainPath shows the "this package → these repos → these workloads" blast
// path for supply_chain findings. Lets the reasoner distinguish "unused internal
// package" from "deployed to internet-facing prod service".
type SupplyChainPath struct {
	RepoIDs   []string          // repos that include this package (depends_on edges)
	Workloads []WorkloadSummary // workloads deployed from those repos (deploys_to edges)
}

// ── Interfaces ────────────────────────────────────────────────────────────────

// Peers lists the other findings on a resource. finding.Service implements it.
type Peers interface {
	List(ctx context.Context, f finding.Filter) ([]finding.Finding, error)
}

// Lineage looks up supply-chain edges pointing at a resource — e.g. the repo
// that deploys_to a workload. asset.Service implements it. Optional:
// a nil seam yields no source-repo provenance.
type Lineage interface {
	EdgesInto(ctx context.Context, dstID, edgeType string) ([]asset.Edge, error)
	// EdgesIntoTypes fetches inbound edges across several edge types in one query —
	// used to size dependents (what relies on this resource) without N round-trips.
	EdgesIntoTypes(ctx context.Context, dstID string, edgeTypes []string) ([]asset.Edge, error)
}

// OutEdger looks up outgoing edges from a source asset filtered by edge type.
// asset.Service implements it (EdgesOut/EdgesOutBatch). Used for identity chain
// and supply-chain blast path resolution. Optional: nil skips it entirely.
type OutEdger interface {
	EdgesOut(ctx context.Context, srcID, edgeType string) ([]asset.Edge, error)
	// EdgesOutBatch is the batched variant — replaces N EdgesOut calls with one query.
	EdgesOutBatch(ctx context.Context, srcIDs []string, edgeType string) ([]asset.Edge, error)
}

// FactorsReader reads the per-source score breakdown for a finding from the
// signals table. enrich.SignalCHRepo implements it. Optional: nil skips injection.
type FactorsReader interface {
	Factors(ctx context.Context, findingID string) ([]enrich.Factor, error)
}

// EPSSScorer looks up the EPSS exploitation probability for a CVE from the
// in-memory catalog. epss.Cache implements it. Optional: nil skips EPSS injection.
type EPSSScorer interface {
	Score(cve string) (float64, bool)
}

// ── Pack assembly ─────────────────────────────────────────────────────────────

// buildContextPack assembles the graph context for f, reusing the already-walked
// blast radius and one peer-findings read. Degrades gracefully: nil seams or read
// errors yield a finding-only pack rather than failing the decision.
// prefetchedPeers is optional: pass nil to have buildContextPack fetch them itself
// (the Decide path); pass a non-nil slice (even empty) to skip the fetch (the
// Context read path, where peers are fetched concurrently with the blast walk).
// prefetchedPeersKnown is the CALLER's own known-ness bit for prefetchedPeers —
// meaningful only when prefetchedPeers != nil. The caller's own query may have
// failed and been normalized to an empty-but-non-nil slice before reaching
// here (see Service.Context); without this parameter, buildContextPack has no
// way to tell that apart from a genuinely successful empty result, and would
// default to known=true either way — the exact gap a prior fix closed for
// buildContextPack's OWN fetch (the `peersKnown` local below) but left open
// for a caller-prefetched one.
// blastKnown is the caller's own known-ness bit for br (from blastRadiusFor) —
// threaded through so the pack, and everything downstream of it (the LLM
// prompt, the finding-detail UI), can distinguish "0 reachable assets" from
// "the walk failed" instead of only ever seeing br's zero value either way.
func (s *Service) buildContextPack(ctx context.Context, f finding.Finding, br asset.BlastRadius, blastKnown bool, prefetchedPeers []finding.Finding, prefetchedPeersKnown bool) ContextPack {
	pack := ContextPack{Finding: f, Blast: summarizeBlast(br, blastKnown)}

	// The seed asset (depth 0 of the blast radius) carries the provenance — it's
	// already fetched, so no extra read. Absent (no resource / failed walk) leaves
	// provenance empty, same graceful degrade as the peers path below.
	var seed asset.Asset
	var seedType string
	if len(br.Assets) > 0 {
		seed = br.Assets[0]
		seedType = seed.Type
		pack.Provenance = s.provenanceOf(seed)
		if isWorkload(seed.Type) {
			s.addSourceRepo(ctx, f, &pack.Provenance)
		} else if seed.Type == "package" {
			s.addPackageRepo(ctx, f, &pack.Provenance)
		}
	}

	// ── Peers ──────────────────────────────────────────────────────────────────
	// prefetchedPeers == nil means "fetch now" (Decide path); non-nil means the
	// caller already fetched them concurrently (Context read path).
	//
	// peersKnown distinguishes "the query failed" from "the query succeeded and
	// found nothing" — both look like an empty/nil peer slice, but only the
	// latter is real evidence that InternetFacing/Privileged are genuinely
	// false. Without this, a failed peer query silently agreed with "no
	// exposure peer" — the same zero-value-as-measurement class as the
	// blast-radius fix, and it feeds the belief adjudicator's corroboration
	// gate (ExposureFlags.PeersKnown -> GroundingFacts) the same way.
	// s.peers == nil / no ResourceID is a deliberate, permanent no-op (the
	// feature isn't wired, or there's nothing to query), not a failure — that
	// stays known=true, same as always.
	// Defaults to the caller's own known-ness when peers were prefetched
	// (prefetchedPeers != nil); only the fetch-it-ourselves branch below
	// computes its own.
	peersKnown := prefetchedPeersKnown
	getPeers := func() []finding.Finding {
		if prefetchedPeers != nil {
			return prefetchedPeers
		}
		peersKnown = true
		if s.peers == nil || f.ResourceID == "" {
			return nil
		}
		peers, err := s.peers.List(ctx, finding.Filter{ResourceID: f.ResourceID, Limit: 200})
		if err != nil {
			peersKnown = false
			return nil
		}
		return peers
	}
	if peers := getPeers(); len(peers) > 0 {
		// Collect all peers (excluding self), sort by score descending so the
		// highest-risk co-located findings land in the capped slice.
		all := make([]finding.Finding, 0, len(peers))
		for _, p := range peers {
			if p.ID != f.ID {
				all = append(all, p)
			}
		}
		sort.Slice(all, func(i, j int) bool { return all[i].Score > all[j].Score })
		for _, p := range all {
			if len(pack.Peers) < maxPeers {
				pack.Peers = append(pack.Peers, PeerSummary{
					Type:      p.Type,
					CheckID:   p.CheckID,
					ScoreBand: p.ScoreBand,
					Score:     p.Score,
					Title:     truncate(p.Title, 60),
				})
			}
			switch p.Type {
			case "exposure":
				pack.Exposure.InternetFacing = true
			case "ciem_privesc":
				pack.Exposure.Privileged = true
			}
		}
	}
	pack.Exposure.PeersKnown = peersKnown

	// ── Score factors ──────────────────────────────────────────────────────────
	// Factors is loaded by Decide (loadFactors), not here: only the reasoner
	// and its fingerprint use it.

	// ── CVE context (EPSS + KEV + OSV fix version + advisory) ─────────────────
	if strings.HasPrefix(f.CheckID, "CVE-") {
		cve := &CVEContext{
			CVEID:        f.CheckID,
			KEV:          f.KnownExploited,
			FixedVersion: f.Remediation,
			Advisory:     truncate(f.Description, advisoryLen),
		}
		if s.epss != nil {
			if score, ok := s.epss.Score(f.CheckID); ok {
				cve.EPSS = score
				cve.EPSSBand = epssBand(score)
			}
		}
		pack.CVE = cve
	}

	// ── Identity chain (workloads only) ────────────────────────────────────────
	// executes_as and has_role are already in br.Edges (first hop of the blast
	// walk) — no extra CH queries needed. federated_access is inbound (not in
	// the outgoing walk) and still needs a lineage lookup.
	if f.ResourceID != "" && isWorkload(seedType) {
		pack.Identity = s.buildIdentityLinks(ctx, f.ResourceID, br)
	}

	// ── Supply-chain blast path (supply_chain findings only) ───────────────────
	if s.outEdger != nil && f.Source == "supply_chain" && f.ResourceID != "" && s.lineage != nil {
		pack.SupplyChain = s.buildSupplyChainPath(ctx, f.ResourceID)
	}

	// ── Impact / safe-to-fix (structural; action folded in later) ──────────────
	// Depends on Provenance.SourceRepo (set above) and the inbound dependent edges.
	deps, depsKnown := s.dependentsOf(ctx, f.ResourceID)
	pack.Impact = assessImpact(pack, seed, deps, depsKnown)

	return pack
}

// dependentsOf returns the inbound edges that mean "something relies on this
// resource" (dns_points_to / executes_as / federated_access), and whether that
// set was actually read. A nil lineage seam, no resource to look up, or a read
// error is NOT "nothing depends on it": known=false keeps the impact
// assessment, the prompt and the safety band from reading it as safe to change.
func (s *Service) dependentsOf(ctx context.Context, resourceID string) (edges []asset.Edge, known bool) {
	if s.lineage == nil || resourceID == "" {
		return nil, false
	}
	edges, err := s.lineage.EdgesIntoTypes(ctx, resourceID, dependentEdgeTypes)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("resource_id", resourceID).
			Msg("respond: dependents read failed — impact reports dependents as unknown")
		return nil, false
	}
	return edges, true
}

// maxFederatedRepos caps federated repo IDs in the identity chain so the prompt
// doesn't inflate when a shared deployment role is trusted by many repos.
const maxFederatedRepos = 5

// buildIdentityLinks derives the execution-identity chain from the already-fetched
// blast radius edges — no extra CH queries for executes_as/has_role since those
// are first-hop outgoing edges already in br.Edges. federated_access is inbound
// (not in the outgoing walk) and still needs one lineage lookup. Best-effort.
func (s *Service) buildIdentityLinks(ctx context.Context, assetID string, br asset.BlastRadius) *IdentityLinks {
	links := &IdentityLinks{}

	// executes_as and has_role are first-hop outgoing edges from the seed asset —
	// already in br.Edges, so zero extra CH queries needed here.
	for _, e := range br.Edges {
		if e.SrcID != assetID {
			continue
		}
		switch e.EdgeType {
		case "executes_as":
			if links.ExecutesAsID == "" {
				links.ExecutesAsID = e.DstID
			}
		case "has_role":
			if len(links.AttachedRoleIDs) < maxRoles {
				links.AttachedRoleIDs = append(links.AttachedRoleIDs, e.DstID)
			}
		}
	}

	// Federated repos: inbound to the execution role, not in the outgoing blast.
	if links.ExecutesAsID != "" && s.lineage != nil {
		if fedEdges, err := s.lineage.EdgesInto(ctx, links.ExecutesAsID, "federated_access"); err == nil {
			for i, e := range fedEdges {
				if i >= maxFederatedRepos {
					break
				}
				links.FederatedRepoIDs = append(links.FederatedRepoIDs, e.SrcID)
			}
		}
	}

	if links.ExecutesAsID == "" && len(links.AttachedRoleIDs) == 0 {
		return nil
	}
	return links
}

// buildSupplyChainPath traces the blast path for a vulnerable package:
// package ← depends_on ← repos → deploys_to → workloads.
// Best-effort: errors return nil.
func (s *Service) buildSupplyChainPath(ctx context.Context, packageID string) *SupplyChainPath {
	// Which repos include this package?
	repoEdges, err := s.lineage.EdgesInto(ctx, packageID, "depends_on")
	if err != nil || len(repoEdges) == 0 {
		return nil
	}

	path := &SupplyChainPath{}
	seen := map[string]bool{}
	for _, e := range repoEdges {
		if len(path.RepoIDs) >= maxRepos {
			break
		}
		if !seen[e.SrcID] {
			seen[e.SrcID] = true
			path.RepoIDs = append(path.RepoIDs, e.SrcID)
		}
	}

	// Which workloads do those repos deploy to? One batched CH query replaces N.
	deployEdges, err := s.outEdger.EdgesOutBatch(ctx, path.RepoIDs, "deploys_to")
	if err == nil {
		for _, e := range deployEdges {
			if len(path.Workloads) >= maxWorkloads {
				break
			}
			if e.DstID == "" {
				continue
			}
			path.Workloads = append(path.Workloads, WorkloadSummary{ID: e.DstID, Type: e.DstType})
		}
	}

	return path
}

// ownerTag is the raw owner label, read through the shared tag tier of owner
// resolution (asset.TagOwner) so the reasoner and the finding's routed owner
// consult the same keys. Raw, not normalised: the value feeds the reason
// fingerprint, which must not churn.
func ownerTag(seed asset.Asset) string {
	v, _ := asset.TagOwner(seed, nil)
	return v
}

// provenanceOf derives the seed asset's origin. Connector comes from the
// prov_connector_type metadata stamped at sync; owner/environment
// reuse the tag reader; age is bucketed against the service clock.
func (s *Service) provenanceOf(seed asset.Asset) Provenance {
	return Provenance{
		Connector:   seed.Metadata["prov_connector_type"],
		AccountID:   seed.AccountID,
		Region:      seed.Region,
		Owner:       ownerTag(seed),
		Environment: envTag(seed),
		AgeBucket:   ageBucket(s.now(), seed),
		Env:         asset.ClassifyEnvironment(seed),
	}
}

// isWorkload reports whether an asset type is a compute workload — k8s workloads,
// Lambda functions, GCE instances, and ECS tasks all get ExecutesAs correlation
// edges and are worth an identity-chain lookup.
func isWorkload(assetType string) bool {
	switch assetType {
	case "k8s_pod", "k8s_deployment", "lambda_function", "gce_instance", "ecs_task":
		return true
	}
	return false
}

// addSourceRepo fills in the supply-chain source (the repo that deploys to this
// resource) from the deploys_to lineage edges, preferring a high-confidence
// match. Best-effort: a nil seam or read error leaves the source empty.
func (s *Service) addSourceRepo(ctx context.Context, f finding.Finding, p *Provenance) {
	if s.lineage == nil || f.ResourceID == "" {
		return
	}
	edges, err := s.lineage.EdgesInto(ctx, f.ResourceID, "deploys_to")
	if err != nil || len(edges) == 0 {
		return
	}
	best := edges[0]
	for _, e := range edges {
		if e.Properties["confidence"] == "high" {
			best = e
			break
		}
	}
	p.SourceRepo = best.SrcID
	p.SourceConfidence = best.Properties["confidence"]
}

// addPackageRepo fills in the source repo for a package finding by following
// depends_on edges inbound to the package — the GitHub SBOM collector writes
// repo→package depends_on edges so we can trace back to the owning repo(s).
func (s *Service) addPackageRepo(ctx context.Context, f finding.Finding, p *Provenance) {
	if s.lineage == nil || f.ResourceID == "" {
		return
	}
	edges, err := s.lineage.EdgesInto(ctx, f.ResourceID, "depends_on")
	if err != nil || len(edges) == 0 {
		return
	}
	p.SourceRepo = edges[0].SrcID
}

// ageBucket classifies a resource by its lifecycle timestamps. Stale (we've
// stopped seeing it) takes priority over new, since a vanishing resource is the
// more notable signal.
//
// Reads FirstDiscoveredAt, not DiscoveredAt: DiscoveredAt is re-stamped to
// `now` by every collector on every sweep, so it cannot be used to tell an
// established resource from a newly-discovered one. Falls back to
// DiscoveredAt only when FirstDiscoveredAt is unset (e.g. a caller that built
// an Asset by hand).
func ageBucket(now time.Time, a asset.Asset) string {
	discovered := a.FirstDiscoveredAt
	if discovered.IsZero() {
		discovered = a.DiscoveredAt
	}
	if discovered.IsZero() {
		return ""
	}
	if !a.LastSeen.IsZero() && now.Sub(a.LastSeen) > staleAssetAge {
		return "stale"
	}
	if now.Sub(discovered) < newAssetAge {
		return "new"
	}
	return "established"
}

// maxGraphNodes caps the asset list embedded in the finding-detail response.
// The graph renderer is capped at hardMaxNodes=2000 in explore; 300 is plenty
// for the finding detail view and keeps the response size reasonable.
const maxGraphNodes = 300

// reachableAssets drops the seed asset — always at index 0 of a blast-radius
// walk (asset.Service.BlastRadiusDir seeds result.Assets with it before the
// BFS runs) — so every consumer of "how many/which assets are reachable"
// agrees with enrich's breakdownFromAssets and mustFixBlastThreshold: the
// resource an action targets is not itself part of its blast radius.
//
// summarizeBlast's Count and respond.Decide's blastCount both go through it;
// a bare len(br.Assets) — seed included — would disagree with enrich's must-fix
// classification by exactly one on every walk. blastCount feeds
// reasoncache.Entry.BlastRadius, the reach a person reads before approving.
func reachableAssets(assets []asset.Asset) []asset.Asset {
	if len(assets) == 0 {
		return nil
	}
	return assets[1:]
}

func summarizeBlast(br asset.BlastRadius, known bool) BlastSummary {
	reachable := reachableAssets(br.Assets)
	s := BlastSummary{Count: len(reachable), Known: known, ByType: map[string]int{}, Truncated: br.Truncated}
	for _, a := range reachable {
		if a.Type != "" {
			s.ByType[a.Type]++
		}
	}
	for _, e := range br.Edges {
		if e.EdgeType == "can_assume" || e.EdgeType == "can_escalate" {
			if len(s.CanAssume) < maxPathHops {
				s.CanAssume = append(s.CanAssume, e.SrcID+" -> "+e.DstID)
			}
		}
	}
	// TopReachable: top-5 non-seed assets by RiskScore. Only populated when
	// the Ladybug blast provider is used (RiskScore comes from the MaxScore signal
	// column written during Ladybug sync). CH-sourced walks have RiskScore=0.
	s.TopReachable = topReachable(br.Assets, 5)

	// GraphAssets / GraphEdges: the raw BFS result for the finding-detail UI.
	// Capped at maxGraphNodes to keep response size reasonable.
	cap := len(br.Assets)
	if cap > maxGraphNodes {
		cap = maxGraphNodes
		s.Truncated = true
	}
	s.GraphAssets = make([]AssetRef, 0, cap)
	for _, a := range br.Assets[:cap] {
		s.GraphAssets = append(s.GraphAssets, AssetRef{ID: a.ID, Name: a.Name, Type: a.Type, Score: a.RiskScore})
	}
	for _, e := range br.Edges {
		s.GraphEdges = append(s.GraphEdges, EdgeRef{SrcID: e.SrcID, DstID: e.DstID, EdgeType: e.EdgeType})
	}
	return s
}

// topReachable returns the top-n assets (excluding the seed at index 0) sorted
// by RiskScore descending. Assets with RiskScore=0 are omitted to avoid noise
// on CH-sourced blast walks where Ladybug signals aren't available.
func topReachable(assets []asset.Asset, n int) []AssetRef {
	if len(assets) <= 1 {
		return nil
	}
	// Collect non-seed assets with a meaningful score.
	candidates := make([]asset.Asset, 0, len(assets)-1)
	for _, a := range assets[1:] {
		if a.RiskScore > 0 {
			candidates = append(candidates, a)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].RiskScore > candidates[j].RiskScore
	})
	if len(candidates) > n {
		candidates = candidates[:n]
	}
	refs := make([]AssetRef, len(candidates))
	for i, a := range candidates {
		refs[i] = AssetRef{ID: a.ID, Name: a.Name, Type: a.Type, Score: a.RiskScore}
	}
	return refs
}

// fingerprintExtra returns the pack-derived inputs that must drive re-reasoning
// when they change: exposure flags, the sorted peer signature, and the
// privilege-path signature. Folded into the change fingerprint.
func (p ContextPack) fingerprintExtra() []string {
	extra := []string{
		fmt.Sprintf("exp:internet=%t", p.Exposure.InternetFacing),
		fmt.Sprintf("exp:priv=%t", p.Exposure.Privileged),
		fmt.Sprintf("blast:truncated=%t", p.Blast.Truncated),
	}
	// An unmeasured blast walk, peer set, or score breakdown is a different
	// context from a measured empty one: a plan reasoned while any was unknown
	// must not be reused once it is measured (and vice versa). Only the unknown state adds
	// a part, so the fingerprint of a fully measured pack is unchanged.
	if !p.Blast.Known {
		extra = append(extra, "blast:unknown")
	}
	if !p.Exposure.PeersKnown {
		extra = append(extra, "peers:unknown")
	}
	if !p.FactorsKnown {
		extra = append(extra, "factors:unknown")
	}
	for _, peer := range p.Peers {
		extra = append(extra, "peer:"+peer.Type+":"+peer.CheckID+":"+peer.ScoreBand)
	}
	extra = append(extra, p.Blast.CanAssume...)
	// Provenance: a change in who owns it, its environment, or its lifecycle
	// stage is a real reason to re-reason; the bucketed age keeps it from
	// churning on every sweep.
	extra = append(extra,
		"prov:connector="+p.Provenance.Connector,
		"prov:owner="+p.Provenance.Owner,
		"prov:env="+p.Provenance.Environment,
		"prov:age="+p.Provenance.AgeBucket,
		"prov:repo="+p.Provenance.SourceRepo,
	)
	// Impact change (new/removed dependents, a resource going unused, a fix moving
	// from repo to console) is a real reason to re-reason: it can flip the plan
	// from "safe to remediate" to "verify first".
	extra = append(extra,
		impactDepsFingerprint(p.Impact),
		fmt.Sprintf("impact:unused=%t", p.Impact.Unused),
		"impact:fix="+p.Impact.FixLocation.Kind+":"+p.Impact.FixLocation.Repo,
	)
	// Identity chain change must re-reason (different execution principal = different blast shape).
	if p.Identity != nil {
		extra = append(extra, "identity:executes_as="+p.Identity.ExecutesAsID)
	}
	// Supply-chain path change must re-reason: use sorted repo IDs so a swap
	// (same count, different repos) correctly busts the fingerprint.
	if p.SupplyChain != nil && len(p.SupplyChain.RepoIDs) > 0 {
		sorted := append([]string(nil), p.SupplyChain.RepoIDs...)
		sort.Strings(sorted)
		extra = append(extra, "sc:repos="+strings.Join(sorted, ","))
	}
	sort.Strings(extra)
	return extra
}

// epssBand maps a raw EPSS probability to a human-readable band.
func epssBand(p float64) string {
	switch {
	case p >= 0.5:
		return "critical"
	case p >= 0.1:
		return "high"
	case p >= 0.01:
		return "moderate"
	default:
		return "low"
	}
}

// truncate shortens s to at most n runes (cutting at a space boundary if possible).
// Operates on runes, not bytes, so multi-byte UTF-8 sequences are never split.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	cut := string(runes[:n])
	if i := strings.LastIndexByte(cut, ' '); i > n/2 {
		cut = cut[:i]
	}
	return cut + "…"
}
