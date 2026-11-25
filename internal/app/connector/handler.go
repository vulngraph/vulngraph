package connector

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Syncer enqueues an immediate sync for a connector, or an immediate
// organization discovery for an aws_org connector. Implemented by the jobs
// package; injected so the connector handler stays free of River.
type Syncer interface {
	EnqueueSync(ctx context.Context, connectorID string) error
	EnqueueOrgDiscovery(ctx context.Context) error
}

type Handler struct {
	svc    *Service
	syncer Syncer
}

func NewHandler(svc *Service, syncer Syncer) *Handler {
	return &Handler{svc: svc, syncer: syncer}
}

// connectorResponse never includes Config — credentials never leave the server.
type connectorResponse struct {
	ID            string     `json:"id"`
	Type          string     `json:"type"`
	Name          string     `json:"name"`
	Enabled       bool       `json:"enabled"`
	EventSource   string     `json:"event_source,omitempty"`
	SyncStatus    string     `json:"sync_status"`
	SyncError     string     `json:"sync_error,omitempty"`
	LastSyncedAt  *time.Time `json:"last_synced_at,omitempty"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	// Stale is true when an enabled connector has not SUCCEEDED within
	// DefaultStaleAfter — surfaces a collector that has silently stopped working
	// (distinct from sync_status=error, which flags one that is actively failing,
	// and measured against last success so a repeatedly-erroring connector is caught).
	Stale bool `json:"stale"`
	// PartiallyStale is true when an enabled connector has racked up
	// DefaultPartialStreakThreshold+ consecutive Partial syncs — a best-effort
	// collector (e.g. one AWS global service) has been skipping on every recent
	// run. Distinct from Stale: a Partial sync still succeeds overall
	// (sync_status stays "ok", last_success_at still advances), so Stale alone
	// cannot see it — this is the signal that catches a connector stuck
	// incomplete for weeks while reading as fully healthy.
	PartiallyStale bool   `json:"partially_stale"`
	Mode           string `json:"mode"` // "read_only" | "read_write"
	// DiskScanMode is the agentless disk-scan opt-in: "off" (the default),
	// "existing_snapshots" or "create_snapshots".
	DiskScanMode string `json:"disk_scan_mode"`
}

type createConnectorRequest struct {
	Type        string            `json:"type"`
	Name        string            `json:"name"`
	Config      map[string]string `json:"config"`
	EventSource string            `json:"event_source"`
}

// Create registers a connector. Admin-only (gated by the router).
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req createConnectorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("request body must be JSON"))
		return
	}

	c, err := h.svc.Create(r.Context(), Type(req.Type), req.Name, req.Config, req.EventSource)
	switch {
	case errors.Is(err, ErrInvalidType):
		errs.WriteHTTPError(w, errs.InvalidInput("invalid connector type"))
		return
	case errors.Is(err, ErrMissingName), errors.Is(err, ErrMissingConfig),
		errors.Is(err, ErrInvalidConfig), errors.Is(err, ErrManagedChild):
		errs.WriteHTTPError(w, errs.InvalidInput(err.Error()))
		return
	case errors.Is(err, ErrNameTaken):
		errs.WriteHTTPError(w, errs.Conflict("a connector of this type already uses that name"))
		return
	case err != nil:
		log.FromContext(r.Context()).Error().Err(err).Msg("create connector failed")
		errs.WriteHTTPError(w, errs.Internal("failed to create connector"))
		return
	}
	writeJSON(r.Context(), w, http.StatusCreated, toResponse(c))
}

// List returns connector metadata (no credentials).
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	cs, err := h.svc.List(r.Context(), false)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("list connectors failed")
		errs.WriteHTTPError(w, errs.Internal("failed to list connectors"))
		return
	}
	out := make([]connectorResponse, len(cs))
	for i, c := range cs {
		out[i] = toResponse(c)
	}
	writeJSON(r.Context(), w, http.StatusOK, out)
}

// TriggerSync enqueues an immediate sync for a connector. Admin-only.
func (h *Handler) TriggerSync(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := h.svc.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			errs.WriteHTTPError(w, errs.NotFound("connector not found"))
			return
		}
		log.FromContext(r.Context()).Error().Err(err).Msg("trigger sync: load connector failed")
		errs.WriteHTTPError(w, errs.Internal("failed to trigger sync"))
		return
	}
	// An aws_org connector's "sync" is discovery, which one singleton job runs
	// for every enabled org.
	enqueue := func() error { return h.syncer.EnqueueSync(r.Context(), id) }
	if c.Type == TypeAWSOrg {
		enqueue = func() error { return h.syncer.EnqueueOrgDiscovery(r.Context()) }
	}
	if err := enqueue(); err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("trigger sync: enqueue failed")
		errs.WriteHTTPError(w, errs.Internal("failed to trigger sync"))
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// purgeRequest requires the caller to echo the connector's own name back —
// admin role alone gates who can call this endpoint, not what they meant to
// call it on. Purge is strictly more destructive than Delete (which touches
// only the connectors table): it hard-deletes every asset ClickHouse holds for
// the account and resolves every finding on them. A name typo fails closed
// with ErrNameMismatch rather than purging the wrong account's data.
type purgeRequest struct {
	ConfirmName string `json:"confirm_name"`
}

type purgeResponse struct {
	AssetsDeleted    int `json:"assets_deleted"`
	FindingsResolved int `json:"findings_resolved"`
	EdgesDeleted     int `json:"edges_deleted"`
}

// Purge deletes a connector's target account/project from the graph
// entirely — every asset, every open finding on them, then the connector row.
// Admin-only, and gated a second time on the caller echoing the connector's
// own name in the body (see purgeRequest): for an action this destructive,
// the role gate alone is not enough to be confident THIS is the connector the
// caller meant.
func (h *Handler) Purge(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := h.svc.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			errs.WriteHTTPError(w, errs.NotFound("connector not found"))
			return
		}
		log.FromContext(r.Context()).Error().Err(err).Msg("purge: load connector failed")
		errs.WriteHTTPError(w, errs.Internal("failed to purge connector"))
		return
	}

	var body purgeRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid request body"))
		return
	}
	if body.ConfirmName != c.Name {
		errs.WriteHTTPError(w, errs.InvalidInput("confirm_name must exactly match the connector's name"))
		return
	}

	result, err := h.svc.PurgeAndDelete(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNoAccountIdentity) {
			errs.WriteHTTPError(w, errs.InvalidInput(err.Error()))
			return
		}
		log.FromContext(r.Context()).Error().Err(err).Str("connector_id", id).Msg("purge failed")
		errs.WriteHTTPError(w, errs.Internal("failed to purge connector"))
		return
	}
	log.FromContext(r.Context()).Warn().
		Str("connector_id", id).Str("name", c.Name).
		Int("assets_deleted", result.AssetsDeleted).Int("findings_resolved", result.FindingsResolved).
		Msg("connector purged")
	writeJSON(r.Context(), w, http.StatusOK, purgeResponse(result))
}

// Delete removes a connector. Admin-only (gated by the router).
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	err := h.svc.Delete(r.Context(), r.PathValue("id"))
	if errors.Is(err, ErrNotFound) {
		errs.WriteHTTPError(w, errs.NotFound("connector not found"))
		return
	}
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("delete connector failed")
		errs.WriteHTTPError(w, errs.Internal("failed to delete connector"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetMode upgrades or downgrades a connector between read_only and read_write.
// Admin-only (gated by the router). Body: {"mode":"read_write"} or {"mode":"read_only"}.
func (h *Handler) SetMode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid request body"))
		return
	}
	mode := Mode(body.Mode)
	if !mode.Valid() {
		errs.WriteHTTPError(w, errs.InvalidInput(`mode must be "read_only" or "read_write"`))
		return
	}
	if err := h.svc.SetMode(r.Context(), r.PathValue("id"), mode); err != nil {
		if errors.Is(err, ErrNotFound) {
			errs.WriteHTTPError(w, errs.NotFound("connector not found"))
			return
		}
		log.FromContext(r.Context()).Error().Err(err).Msg("SetMode failed")
		errs.WriteHTTPError(w, errs.Internal("failed to set mode"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func toResponse(c Connector) connectorResponse {
	return connectorResponse{
		ID: c.ID, Type: string(c.Type), Name: c.Name, Enabled: c.Enabled,
		EventSource: c.EventSource, SyncStatus: string(c.SyncStatus),
		SyncError: c.SyncError, LastSyncedAt: c.LastSyncedAt, LastSuccessAt: c.LastSuccessAt,
		Stale:          c.Stale(time.Now(), DefaultStaleAfter),
		PartiallyStale: c.PartiallyStale(DefaultPartialStreakThreshold),
		Mode:           string(c.Mode),
		DiskScanMode:   diskScanModeName(c.DiskScanMode),
	}
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("write response failed")
	}
}
