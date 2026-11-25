package asset

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// AssetRisk is a resource's finding rollup, the primary measure of an asset's
// risk; the stored Asset.RiskScore is only a pre-propagation base score.
type AssetRisk struct {
	Count    int
	MaxScore uint8
	Band     string
}

// RankedRisk pairs a resource id with its risk for the risk-sorted inventory.
type RankedRisk struct {
	ResourceID string
	AssetRisk
}

// RiskProvider supplies per-resource finding rollups. finding.Service implements
// it (adapted at wiring). Defined here with asset-local types so the asset domain
// stays decoupled from the finding package. nil disables risk display.
type RiskProvider interface {
	RiskByResource(ctx context.Context, ids []string) (map[string]AssetRisk, error)
	RiskiestResources(ctx context.Context, limit int) ([]RankedRisk, error)
}

type Handler struct {
	svc          *Service
	risk         RiskProvider
	ownerTagKeys []string // nil = DefaultOwnerTagKeys
}

func NewHandler(svc *Service, risk RiskProvider) *Handler { return &Handler{svc: svc, risk: risk} }

// WithOwnerTagKeys sets the owner tag keys (OwnerTagKeys) — the same list the
// enrich worker stamps finding owners with, so the asset page and its findings
// name the same owner.
func (h *Handler) WithOwnerTagKeys(keys []string) *Handler { h.ownerTagKeys = keys; return h }

type assetResponse struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Type         string            `json:"type"`
	Provider     string            `json:"provider"`
	Region       string            `json:"region"`
	AccountID    string            `json:"account_id,omitempty"`
	Endpoint     string            `json:"endpoint,omitempty"`
	PublicIP     string            `json:"public_ip,omitempty"`
	PrivateIP    string            `json:"private_ip,omitempty"`
	Domain       string            `json:"domain,omitempty"`
	RiskScore    uint8             `json:"risk_score"`
	FindingCount int               `json:"finding_count"`
	MaxScore     uint8             `json:"max_score"`
	RiskBand     string            `json:"risk_band,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	LastSeen     time.Time         `json:"last_seen"`
	// Environment is ClassifyEnvironment's verdict: prod|staging|dev|unknown,
	// never omitted — "unknown" is a real answer. EnvironmentSource names the
	// evidence ("tag:env", "account_id", "conflict:tag", …); empty when unknown.
	Environment       Environment `json:"environment"`
	EnvironmentSource string      `json:"environment_source"`
	// Owner is ResolveOwnership's verdict, served on the single-asset read only
	// (it costs graph reads). Absent when resolution failed — a failed lookup is
	// not "unowned", which is an explicit source of "none".
	Owner *ownerResponse `json:"owner,omitempty"`
}

type ownerResponse struct {
	Team       string      `json:"team"`
	Source     OwnerSource `json:"source"`
	Confidence string      `json:"confidence,omitempty"`
	Evidence   string      `json:"evidence,omitempty"`
}

type assetPage struct {
	Items      []assetResponse `json:"items"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

type assetSummaryResponse struct {
	Total      int            `json:"total"`
	ByProvider map[string]int `json:"by_provider"`
	ByType     map[string]int `json:"by_type"`
}

// List returns a filtered, paginated page of assets. Route:
// GET /api/assets?provider&type&region&account_id&q&cursor&limit&sort.
// sort=risk returns the assets carrying findings, worst-score first (the triage
// view) — otherwise the keyset-paginated inventory, each row enriched with its
// finding rollup so the danger of a row is visible without opening it.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("sort") == "risk" {
		// The risk view is a single ranked page over the whole estate — it is built
		// from RiskiestResources, not from the inventory query, so NONE of the
		// inventory filters reach it. Reject rather than silently drop them: a
		// filter that appears to apply but doesn't is worse than an error on a
		// security tool.
		if bad := unsupportedRiskParams(q); len(bad) > 0 {
			errs.WriteHTTPError(w, errs.InvalidInput(
				"sort=risk ranks the whole estate and ignores inventory filters; remove "+
					strings.Join(bad, ", ")+" or drop sort=risk"))
			return
		}
		h.listByRisk(w, r)
		return
	}

	f := Filter{
		Provider:  q.Get("provider"),
		Type:      q.Get("type"),
		Region:    q.Get("region"),
		AccountID: q.Get("account_id"),
		Search:    q.Get("q"),
		Cursor:    q.Get("cursor"),
		Exposed:   q.Get("exposed") == "true",
	}
	if raw := q.Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			f.Limit = n
		}
	}
	if raw := q.Get("min_score"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			f.MinScore = n
		}
	}

	assets, err := h.svc.List(r.Context(), f)
	if errors.Is(err, ErrBadCursor) {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid cursor"))
		return
	}
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("list assets failed")
		errs.WriteHTTPError(w, errs.Internal("failed to list assets"))
		return
	}

	risk := h.riskFor(r.Context(), idsOf(assets))
	page := assetPage{Items: make([]assetResponse, len(assets))}
	for i, a := range assets {
		page.Items[i] = toAssetResponse(a, risk[a.ID])
	}
	// A full page means there may be more — emit a resume cursor.
	limit := f.Limit
	if limit <= 0 || limit > assetPageLimit {
		limit = assetPageLimit
	}
	if len(assets) == limit {
		page.NextCursor = EncodeCursor(assets[len(assets)-1])
	}
	writeJSON(r.Context(), w, http.StatusOK, page)
}

// riskIgnoredParams are the query parameters the inventory list honours and the
// risk view cannot. Kept next to Filter's construction above so a new filter
// can't be added to one path and silently dropped by the other.
var riskIgnoredParams = []string{
	"provider", "type", "region", "account_id", "q", "exposed", "min_score", "cursor",
}

// unsupportedRiskParams returns which inventory filters were sent alongside
// sort=risk, in a stable order (the error message is user-facing). An empty or
// explicitly-false value is not a filter, so `exposed=false` passes.
func unsupportedRiskParams(q url.Values) []string {
	var bad []string
	for _, p := range riskIgnoredParams {
		v := q.Get(p)
		if v == "" || v == "false" || v == "0" {
			continue
		}
		bad = append(bad, p)
	}
	return bad
}

// listByRisk returns the assets that carry findings, worst-score first — the
// triage view. The risky set is a small fraction of the inventory,
// so it is a single ranked page, not keyset-paginated.
//
// The ranking comes from the finding store and the rows from ByIDs, so neither
// half passes through inventoryReadCond — this is the one UI-facing asset read
// whose liveness gate has to be applied in Go, via LiveIDs (which embeds the
// same EphemeralLivenessCond, so "live" means one thing everywhere). Without it
// the triage view is where dead pods reappear: a finding on a pod deleted weeks
// ago outranks live infrastructure, and every asset row still exists to back it.
func (h *Handler) listByRisk(w http.ResponseWriter, r *http.Request) {
	if h.risk == nil {
		writeJSON(r.Context(), w, http.StatusOK, assetPage{Items: []assetResponse{}})
		return
	}
	ranked, err := h.risk.RiskiestResources(r.Context(), assetPageLimit)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("riskiest resources failed")
		errs.WriteHTTPError(w, errs.Internal("failed to rank assets by risk"))
		return
	}
	ids := make([]string, len(ranked))
	for i, rr := range ranked {
		ids[i] = rr.ResourceID
	}
	assets, err := h.svc.ByIDs(r.Context(), ids)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("load risky assets failed")
		errs.WriteHTTPError(w, errs.Internal("failed to load risky assets"))
		return
	}
	byID := make(map[string]Asset, len(assets))
	for _, a := range assets {
		byID[a.ID] = a
	}
	// Drop corpses and IaC declarations, so this view answers the same question
	// about "what exists" as the inventory list does. A LiveIDs failure degrades
	// to the unfiltered ranking rather than 500ing: showing a stale row is bad,
	// hiding the triage queue outright is worse.
	if live, err := h.svc.LiveIDs(r.Context(), ids); err != nil {
		log.FromContext(r.Context()).Warn().Err(err).
			Msg("asset: risk view liveness filter failed; ranking may include deleted resources")
	} else {
		liveSet := make(map[string]struct{}, len(live))
		for _, id := range live {
			liveSet[id] = struct{}{}
		}
		for id, a := range byID {
			_, ok := liveSet[id]
			if !ok || isNonInventoryType(a.Type) {
				delete(byID, id)
			}
		}
	}
	// Emit in the ranked order; skip ids that have findings but no asset row
	// (e.g. a resource collected only as a finding target).
	page := assetPage{Items: make([]assetResponse, 0, len(ranked))}
	for _, rr := range ranked {
		a, ok := byID[rr.ResourceID]
		if !ok {
			continue
		}
		page.Items = append(page.Items, toAssetResponse(a, rr.AssetRisk))
	}
	writeJSON(r.Context(), w, http.StatusOK, page)
}

// riskFor returns the finding rollup per asset id, or an empty map when no risk
// provider is wired or the lookup fails (risk is decoration, never fatal to a list).
func (h *Handler) riskFor(ctx context.Context, ids []string) map[string]AssetRisk {
	if h.risk == nil || len(ids) == 0 {
		return map[string]AssetRisk{}
	}
	risk, err := h.risk.RiskByResource(ctx, ids)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("asset risk lookup failed; listing without risk")
		return map[string]AssetRisk{}
	}
	return risk
}

func idsOf(assets []Asset) []string {
	ids := make([]string, len(assets))
	for i, a := range assets {
		ids[i] = a.ID
	}
	return ids
}

// Summary returns the inventory breakdown for the filter UI. Route:
// GET /api/assets/summary.
func (h *Handler) Summary(w http.ResponseWriter, r *http.Request) {
	s, err := h.svc.Summary(r.Context())
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("asset summary failed")
		errs.WriteHTTPError(w, errs.Internal("failed to summarize assets"))
		return
	}
	// Summary and assetSummaryResponse share field layout; the conversion just
	// attaches the JSON tags.
	writeJSON(r.Context(), w, http.StatusOK, assetSummaryResponse(s))
}

// Get returns one asset by ID. Route: GET /api/assets/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, err := h.svc.Get(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		errs.WriteHTTPError(w, errs.NotFound("asset not found"))
		return
	}
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Str("asset_id", id).Msg("get asset failed")
		errs.WriteHTTPError(w, errs.Internal("failed to load asset"))
		return
	}
	resp := toAssetResponse(a, h.riskFor(r.Context(), []string{id})[id])
	if o, err := h.svc.ResolveOwner(r.Context(), a, h.ownerTagKeys); err != nil {
		log.FromContext(r.Context()).Warn().Err(err).Str("asset_id", id).Msg("owner resolution failed; owner omitted")
	} else {
		resp.Owner = &ownerResponse{Team: o.Team, Source: o.Source, Confidence: o.Confidence, Evidence: o.Evidence}
	}
	writeJSON(r.Context(), w, http.StatusOK, resp)
}

type changeResponse struct {
	Field     string `json:"field"`
	OldValue  string `json:"old_value"`
	NewValue  string `json:"new_value"`
	ChangedAt string `json:"changed_at"`
}

// Changes returns an asset's per-field change history (drift timeline).
// Route: GET /api/assets/{id}/changes.
func (h *Handler) Changes(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	changes, err := h.svc.ChangeLog(r.Context(), id, 100)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Str("asset_id", id).Msg("asset change log failed")
		errs.WriteHTTPError(w, errs.Internal("failed to load change history"))
		return
	}
	out := make([]changeResponse, len(changes))
	for i, c := range changes {
		out[i] = changeResponse{
			Field: c.Field, OldValue: c.OldValue, NewValue: c.NewValue,
			ChangedAt: c.ChangedAt.Format("2006-01-02T15:04:05Z"),
		}
	}
	writeJSON(r.Context(), w, http.StatusOK, map[string]any{"changes": out})
}

type blastRadiusResponse struct {
	SeedID    string          `json:"seed_id"`
	MaxDepth  int             `json:"max_depth"`
	Truncated bool            `json:"truncated"`
	Assets    []assetResponse `json:"assets"`
	Edges     []edgeResponse  `json:"edges"`
}

type edgeResponse struct {
	SrcID    string `json:"src_id"`
	DstID    string `json:"dst_id"`
	EdgeType string `json:"edge_type"`
}

// BlastRadius returns the assets reachable from an asset. Route:
// GET /api/assets/{id}/blast-radius?depth=N.
func (h *Handler) BlastRadius(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	depth := 0
	if raw := r.URL.Query().Get("depth"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			errs.WriteHTTPError(w, errs.InvalidInput("depth must be a non-negative integer"))
			return
		}
		depth = parsed
	}

	dir := ParseDirection(r.URL.Query().Get("direction"))
	br, err := h.svc.BlastRadiusDir(r.Context(), id, depth, dir)
	if errors.Is(err, ErrNotFound) {
		errs.WriteHTTPError(w, errs.NotFound("asset not found"))
		return
	}
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Str("asset_id", id).Msg("blast radius failed")
		errs.WriteHTTPError(w, errs.Internal("failed to compute blast radius"))
		return
	}

	resp := blastRadiusResponse{SeedID: br.SeedID, MaxDepth: br.MaxDepth, Truncated: br.Truncated}
	risk := h.riskFor(r.Context(), idsOf(br.Assets))
	for _, a := range br.Assets {
		resp.Assets = append(resp.Assets, toAssetResponse(a, risk[a.ID]))
	}
	for _, e := range br.Edges {
		resp.Edges = append(resp.Edges, edgeResponse{SrcID: e.SrcID, DstID: e.DstID, EdgeType: e.EdgeType})
	}
	writeJSON(r.Context(), w, http.StatusOK, resp)
}

func toAssetResponse(a Asset, risk AssetRisk) assetResponse {
	env := ClassifyEnvironment(a)
	return assetResponse{
		Environment: env.Env, EnvironmentSource: env.Source,
		ID: a.ID, Name: a.Name, Type: a.Type, Provider: string(a.Provider),
		Region: a.Region, AccountID: a.AccountID, Endpoint: a.Endpoint,
		PublicIP: a.PublicIP, PrivateIP: a.PrivateIP, Domain: a.Domain,
		RiskScore:    a.RiskScore,
		FindingCount: risk.Count, MaxScore: risk.MaxScore, RiskBand: risk.Band,
		Tags: a.Tags, Metadata: a.Metadata, LastSeen: a.LastSeen,
	}
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("write response failed")
	}
}
