package findingctx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/respond"
	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

type response struct {
	ID             string    `json:"id"`
	Source         string    `json:"source"`
	Type           string    `json:"type"`
	Severity       string    `json:"severity"`
	Title          string    `json:"title"`
	Description    string    `json:"description,omitempty"`
	ResourceType   string    `json:"resource_type,omitempty"`
	ResourceID     string    `json:"resource_id,omitempty"`
	ResourceName   string    `json:"resource_name,omitempty"`
	Region         string    `json:"region,omitempty"`
	CheckID        string    `json:"check_id,omitempty"`
	Remediation    string    `json:"remediation,omitempty"`
	Score          uint8     `json:"score"`
	ScoreBand      string    `json:"score_band"`
	KnownExploited bool      `json:"known_exploited"`
	DetectedAt     time.Time `json:"detected_at"`

	// Enrichment verdicts. must_fix_class and safety_class are not omitempty:
	// "" is a real verdict on both, and must be read against enrichment_state
	// to tell a real answer from an absent one.
	EnrichmentState finding.EnrichmentState `json:"enrichment_state"`
	EnrichedAt      *time.Time              `json:"enriched_at,omitempty"`
	MustFixClass    string                  `json:"must_fix_class"`
	MustFixReason   string                  `json:"must_fix_reason,omitempty"`
	SafetyClass     string                  `json:"safety_class"`

	// Routing context (ADR 089), as stamped by enrich — the same values the
	// findings list filters on. owner_source/environment "" = not yet stamped.
	OwnerTeam       string `json:"owner_team,omitempty"`
	OwnerSource     string `json:"owner_source"`
	OwnerConfidence string `json:"owner_confidence,omitempty"`
	Environment     string `json:"environment"`

	// Suppression standing, so the panel's Suppress/Unsuppress toggle reflects
	// reality. suppression_known=false means the read failed: is_suppressed is
	// then unmeasured and the client must not offer a toggle built on it.
	SuppressionKnown     bool       `json:"suppression_known"`
	IsSuppressed         bool       `json:"is_suppressed"`
	ExceptionExpired     bool       `json:"exception_expired"`
	SuppressionExpiresAt *time.Time `json:"suppression_expires_at,omitempty"`
	SuppressionReason    string     `json:"suppression_reason,omitempty"`
	SuppressedBy         string     `json:"suppressed_by,omitempty"`

	// Narrative is the deterministic plain-English risk story (see narrative.go).
	Narrative string `json:"narrative,omitempty"`

	// Detection context — scanner-native fields (e.g. nuclei) that explain what
	// was found and where. Sourced from the finding's metadata map.
	MatchedURL string `json:"matched_url,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	References string `json:"references,omitempty"`

	Reasoning  *reasoningResp `json:"reasoning,omitempty"`
	Exposure   exposureResp   `json:"exposure"`
	Blast      blastResp      `json:"blast"`
	Provenance provenanceResp `json:"provenance"`
	Impact     impactResp     `json:"impact"`
	Factors    []factorResp   `json:"factors,omitempty"`
	Peers      []peerResp     `json:"peers,omitempty"`
}

type reasoningResp struct {
	ActionClass     string  `json:"action_class"`
	Summary         string  `json:"summary"`
	Rationale       string  `json:"rationale"`
	Outcome         string  `json:"outcome"`
	ConfidenceBand  string  `json:"confidence_band,omitempty"`
	ConfidenceScore float64 `json:"confidence_score"`
	EffectiveN      float64 `json:"effective_n"`
	SampleCount     int     `json:"sample_count"`
	BlastRadius     int     `json:"blast_radius"`
	// BlastRadiusKnown pairs with BlastRadius (not omitempty — false is the
	// load-bearing value): false means the decision's own blast-radius walk
	// failed, so BlastRadius is left at its zero value and the UI must render
	// "unmeasured" rather than a measured "0 reachable assets".
	BlastRadiusKnown bool      `json:"blast_radius_known"`
	CoVeConcerns     []string  `json:"cove_concerns,omitempty"`
	SafetyBand       string    `json:"safety_band,omitempty"`
	DecidedAt        time.Time `json:"decided_at"`
}

// impactResp is the "safe to fix" context: what depends on the resource, whether
// it looks unused, the evidence to check before acting, and where the fix lands.
type impactResp struct {
	Dependents int `json:"dependents"`
	// DependentsKnown is false when dependents could not be read in full:
	// dependents is then unmeasured, and must render as unknown, never as "none".
	DependentsKnown bool             `json:"dependents_known"`
	Unused          bool             `json:"unused"`
	Signals         []string         `json:"signals,omitempty"`
	FixLocation     *fixLocationResp `json:"fix_location,omitempty"`
}

type fixLocationResp struct {
	Kind       string `json:"kind"`
	Repo       string `json:"repo,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Account    string `json:"account,omitempty"`
	Region     string `json:"region,omitempty"`
	Hint       string `json:"hint,omitempty"`
}

type exposureResp struct {
	// InternetFacing is the DIRECT signal: this resource itself carries an
	// ExposedToInternet edge.
	InternetFacing bool `json:"internet_facing"`
	Privileged     bool `json:"privileged"`
	// InternetReachable is the TRANSITIVE signal: the enrich pipeline's
	// internet-hops BFS (internal/app/enrich/sources_reach.go) found this
	// finding reachable from an internet-exposed asset within the
	// attacker-movement depth it computes, even though it is not itself
	// directly internet-facing. Deliberately separate from InternetFacing —
	// the two answer different questions and a responder needs both, not a
	// single flattened bit, so must_fix_reason ("reachable from an
	// internet-exposed asset (2 hops)") never contradicts this block. Read
	// off the finding's already-persisted must_fix_class/must_fix_reason (no
	// extra graph read).
	InternetReachable bool `json:"internet_reachable"`
}

type blastResp struct {
	Count int `json:"count"`
	// Known pairs with Count (not omitempty — false is the load-bearing
	// value): false means the LIVE walk this response was built from failed,
	// so Count is left at its zero value and the UI must render "unmeasured"
	// rather than a measured "0 reachable assets".
	Known     bool           `json:"known"`
	ByType    map[string]int `json:"by_type,omitempty"`
	CanAssume []string       `json:"can_assume,omitempty"`
	Truncated bool           `json:"truncated"`
	// GraphAssets and GraphEdges carry the raw BFS result so the finding-detail
	// page can render the blast-radius graph without a second API call.
	GraphAssets []blastAssetResp `json:"graph_assets,omitempty"`
	GraphEdges  []blastEdgeResp  `json:"graph_edges,omitempty"`
}

type blastAssetResp struct {
	ID    string `json:"id"`
	Name  string `json:"name,omitempty"`
	Type  string `json:"type,omitempty"`
	Score uint8  `json:"max_score"`
}

type blastEdgeResp struct {
	SrcID    string `json:"src_id"`
	DstID    string `json:"dst_id"`
	EdgeType string `json:"edge_type"`
}

type provenanceResp struct {
	Connector        string `json:"connector,omitempty"`
	AccountID        string `json:"account_id,omitempty"`
	Region           string `json:"region,omitempty"`
	Owner            string `json:"owner,omitempty"`
	Environment      string `json:"environment,omitempty"`
	AgeBucket        string `json:"age_bucket,omitempty"`
	SourceRepo       string `json:"source_repo,omitempty"`
	SourceConfidence string `json:"source_confidence,omitempty"`
}

type factorResp struct {
	Source string `json:"source"`
	Points int    `json:"points"`
	Floor  int    `json:"floor,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type peerResp struct {
	Type      string `json:"type"`
	CheckID   string `json:"check_id"`
	ScoreBand string `json:"score_band,omitempty"`
}

// Get returns the full context for one finding. Route: GET /api/findings/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	fc, err := h.svc.Context(r.Context(), id)
	if errors.Is(err, finding.ErrNotFound) {
		errs.WriteHTTPError(w, errs.NotFound("finding not found"))
		return
	}
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Str("finding_id", id).Msg("get finding context failed")
		errs.WriteHTTPError(w, errs.Internal("failed to load finding"))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, toResponse(fc))
}

// enrichedTime maps the unset/sentinel enriched_at to nil so JSON omits it
// rather than serving a 1970 epoch that reads as a real enrichment. ClickHouse
// DateTime has no NULL, so a never-enriched row comes back as the epoch, not the
// Go zero time — the same convention finding.Resolved() uses.
func enrichedTime(t time.Time) *time.Time {
	if t.IsZero() || t.Year() <= 2000 {
		return nil
	}
	return &t
}

func toResponse(fc FindingContext) response {
	f := fc.Finding
	out := response{
		ID: f.ID, Source: f.Source, Type: f.Type, Severity: string(f.Severity),
		Title: f.Title, Description: f.Description, ResourceType: f.ResourceType,
		ResourceID: f.ResourceID, ResourceName: f.ResourceName, Region: f.Region,
		CheckID: f.CheckID, Remediation: f.Remediation, Score: f.Score,
		ScoreBand: f.ScoreBand, KnownExploited: f.KnownExploited, DetectedAt: f.DetectedAt,
		EnrichmentState: f.EnrichmentStateAt(time.Now()), EnrichedAt: enrichedTime(f.EnrichedAt),
		MustFixClass: f.MustFixClass, MustFixReason: f.MustFixReason, SafetyClass: f.SafetyClass,
		MatchedURL: f.Metadata["matched_url"], Evidence: f.Metadata["evidence"],
		References: f.Metadata["references"],
		Narrative:  fc.Narrative,
		OwnerTeam:  f.OwnerTeam, OwnerSource: f.OwnerSource, OwnerConfidence: f.OwnerConfidence,
		Environment:      f.Environment,
		SuppressionKnown: fc.SuppressionKnown,
		IsSuppressed:     fc.Suppression.Suppressed,
		ExceptionExpired: fc.Suppression.Expired,
		Exposure: exposureResp{
			InternetFacing: fc.Exposure.InternetFacing,
			Privileged:     fc.Exposure.Privileged,
			// Direct facing already implies reachable; only worth asserting the
			// transitive bit on its own when it is the reason must_fix_reason
			// carries reachability evidence that InternetFacing didn't capture.
			InternetReachable: fc.Exposure.InternetFacing || transitivelyReachable(f),
		},
		Blast: blastResp{
			Count:     fc.Blast.Count,
			Known:     fc.Blast.Known,
			ByType:    fc.Blast.ByType,
			CanAssume: fc.Blast.CanAssume,
			Truncated: fc.Blast.Truncated,
			GraphAssets: func() []blastAssetResp {
				if len(fc.Blast.GraphAssets) == 0 {
					return nil
				}
				out := make([]blastAssetResp, len(fc.Blast.GraphAssets))
				for i, a := range fc.Blast.GraphAssets {
					out[i] = blastAssetResp{ID: a.ID, Name: a.Name, Type: a.Type, Score: a.Score}
				}
				return out
			}(),
			GraphEdges: func() []blastEdgeResp {
				if len(fc.Blast.GraphEdges) == 0 {
					return nil
				}
				out := make([]blastEdgeResp, len(fc.Blast.GraphEdges))
				for i, e := range fc.Blast.GraphEdges {
					out[i] = blastEdgeResp{SrcID: e.SrcID, DstID: e.DstID, EdgeType: e.EdgeType}
				}
				return out
			}(),
		},
		Provenance: provenanceResp{
			Connector: fc.Provenance.Connector, AccountID: fc.Provenance.AccountID,
			Region: fc.Provenance.Region, Owner: fc.Provenance.Owner,
			Environment: fc.Provenance.Environment, AgeBucket: fc.Provenance.AgeBucket,
			SourceRepo: fc.Provenance.SourceRepo, SourceConfidence: fc.Provenance.SourceConfidence,
		},
		Impact: impactResp{
			Dependents:      fc.Impact.Dependents,
			DependentsKnown: fc.Impact.DependentsKnown,
			Unused:          fc.Impact.Unused,
			Signals:         fc.Impact.Signals,
			FixLocation:     fixLocationResponse(fc.Impact.FixLocation),
		},
	}
	if sup := fc.Suppression; sup.Suppressed || sup.Expired {
		out.SuppressionExpiresAt = enrichedTime(sup.Suppression.ExpiresAt)
		out.SuppressionReason = sup.Suppression.Reason
		out.SuppressedBy = sup.Suppression.SuppressedBy
	}
	if fc.Reasoning != nil {
		out.Reasoning = &reasoningResp{
			ActionClass: fc.Reasoning.ActionClass, Summary: fc.Reasoning.Summary,
			Rationale: fc.Reasoning.Rationale, Outcome: fc.Reasoning.Outcome,
			ConfidenceBand: fc.Reasoning.ConfidenceBand, ConfidenceScore: fc.Reasoning.ConfidenceScore,
			EffectiveN: fc.Reasoning.EffectiveN, SampleCount: fc.Reasoning.SampleCount,
			BlastRadius: fc.Reasoning.BlastRadius, BlastRadiusKnown: fc.Reasoning.BlastRadiusKnown,
			CoVeConcerns: fc.Reasoning.CoVeConcerns,
			SafetyBand:   fc.Reasoning.SafetyBand, DecidedAt: fc.Reasoning.DecidedAt,
		}
	}
	for _, ft := range fc.Factors {
		out.Factors = append(out.Factors, factorResp{Source: ft.Source, Points: ft.Points, Floor: ft.Floor, Detail: ft.Detail})
	}
	for _, p := range fc.Peers {
		out.Peers = append(out.Peers, peerResp{Type: p.Type, CheckID: p.CheckID, ScoreBand: p.ScoreBand})
	}
	return out
}

// fixLocationResponse maps the domain fix location to the wire shape, returning
// nil (omitted) when there is nothing to point at.
func fixLocationResponse(fl respond.FixLocation) *fixLocationResp {
	if fl.Kind == "" || fl.Kind == respond.FixUnknown {
		return nil
	}
	return &fixLocationResp{
		Kind: fl.Kind, Repo: fl.Repo, Confidence: fl.Confidence,
		Account: fl.Account, Region: fl.Region, Hint: fl.Hint,
	}
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("write response failed")
	}
}
