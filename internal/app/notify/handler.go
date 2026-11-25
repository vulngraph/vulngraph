package notify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/errs"
)

// Handler exposes alert-channel CRUD + test over HTTP.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		errs.WriteHTTPErrorCtx(ctx, w, "encode response", http.StatusInternalServerError)
	}
}

// channelResponse is the wire shape — never includes the bot token.
type channelResponse struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`
	Name       string   `json:"name"`
	Channel    string   `json:"channel"`
	Enabled    bool     `json:"enabled"`
	EventTypes []string `json:"event_types"`
	Severities []string `json:"severities"`
	MinScore   int      `json:"min_score"`
	// Owner/environment scope (ADR 089). Never omitted: an empty list is the
	// meaningful "unscoped" value.
	OwnerTeams      []string `json:"owner_teams"`
	Environments    []string `json:"environments"`
	RouteUnowned    bool     `json:"route_unowned"`
	LastDeliveredAt string   `json:"last_delivered_at,omitempty"`
	LastStatus      string   `json:"last_status,omitempty"`
	LastError       string   `json:"last_error,omitempty"`
	HasToken        bool     `json:"has_token"` // whether a secret is stored (token/URL itself never returned)
	// UnwiredEventTypes lists this channel's routed event types that have no
	// producer anywhere in the codebase yet (see domain.go's unwiredEventTypes) —
	// so an operator who routes a channel to, say, "connector" can tell it will
	// never fire instead of discovering it the hard way. An empty event_types
	// list routes every event type, unwired ones included. Omitted when every
	// routed event type has a live producer.
	UnwiredEventTypes []string `json:"unwired_event_types,omitempty"`
}

func toResponse(c Channel) channelResponse {
	var last string
	if c.LastDeliveredAt != nil {
		last = c.LastDeliveredAt.Format("2006-01-02T15:04:05Z")
	}
	return channelResponse{
		ID: c.ID, Type: string(c.Type), Name: c.Name, Channel: c.SlackChannel,
		Enabled: c.Enabled, EventTypes: eventStrings(c.EventTypes), Severities: c.Severities,
		MinScore: c.MinScore, OwnerTeams: nonNil(c.OwnerTeams), Environments: nonNil(c.Environments),
		RouteUnowned: c.RouteUnowned, LastDeliveredAt: last, LastStatus: c.LastStatus, LastError: c.LastError,
		HasToken: true, UnwiredEventTypes: eventStrings(UnwiredIn(c.EventTypes)),
	}
}

// channelRequest is the create/update body.
type channelRequest struct {
	Type       string   `json:"type"`
	Name       string   `json:"name"`
	Channel    string   `json:"channel"`
	BotToken   string   `json:"bot_token"`   // slack; optional on update (empty = keep existing)
	WebhookURL string   `json:"webhook_url"` // webhook; optional on update (empty = keep existing)
	Enabled    bool     `json:"enabled"`
	EventTypes []string `json:"event_types"`
	Severities []string `json:"severities"`
	MinScore   int      `json:"min_score"`
	// Owner teams are normalised on the way in (asset.NormalizeOwner) — the
	// same form findings store their owner in — so "@acme/Payments" scopes the
	// channel to the team findings call "payments".
	OwnerTeams   []string `json:"owner_teams"`
	Environments []string `json:"environments"`
	RouteUnowned bool     `json:"route_unowned"`
}

func (req channelRequest) toChannel() Channel {
	return Channel{
		Type:         ChannelType(req.Type),
		Name:         req.Name,
		SlackChannel: req.Channel,
		BotToken:     req.BotToken,
		WebhookURL:   req.WebhookURL,
		Enabled:      req.Enabled,
		EventTypes:   toEventTypes(req.EventTypes),
		Severities:   req.Severities,
		MinScore:     req.MinScore,
		OwnerTeams:   normalizeOwners(req.OwnerTeams),
		Environments: req.Environments,
		RouteUnowned: req.RouteUnowned,
	}
}

// validEnvironments is the classifier's closed set (asset.Environment).
var validEnvironments = map[string]bool{"prod": true, "staging": true, "dev": true, "unknown": true}

// validate rejects an environment scope naming a value no finding can carry —
// a typo there would silently mute the channel.
func (req channelRequest) validate() error {
	for _, e := range req.Environments {
		if !validEnvironments[e] {
			return ErrInvalidScope
		}
	}
	return nil
}

func normalizeOwners(in []string) []string {
	out := make([]string, 0, len(in))
	for _, o := range in {
		if n := asset.NormalizeOwner(o); n != "" && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// GET /api/alerts/channels
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	channels, err := h.svc.List(r.Context())
	if err != nil {
		errs.WriteHTTPError(w, errs.Internal("list channels failed"))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, toListResponse(channels))
}

// channelListResponse carries, besides the channels, every event type that has
// no producer yet, so the channel form can label those choices before any
// channel routes them.
type channelListResponse struct {
	Channels          []channelResponse `json:"channels"`
	UnwiredEventTypes []string          `json:"unwired_event_types"`
}

func toListResponse(channels []Channel) channelListResponse {
	out := make([]channelResponse, len(channels))
	for i, c := range channels {
		out[i] = toResponse(c)
	}
	return channelListResponse{Channels: out, UnwiredEventTypes: eventStrings(UnwiredIn(nil))}
}

// POST /api/alerts/channels
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req channelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid JSON"))
		return
	}
	if req.Type == "" {
		req.Type = string(TypeSlack)
	}
	if err := req.validate(); err != nil {
		h.writeErr(w, err)
		return
	}
	c, err := h.svc.Create(r.Context(), req.toChannel())
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(r.Context(), w, http.StatusCreated, toResponse(c))
}

// PUT /api/alerts/channels/{id}
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	var req channelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid JSON"))
		return
	}
	if err := req.validate(); err != nil {
		h.writeErr(w, err)
		return
	}
	c := req.toChannel()
	c.ID = r.PathValue("id")
	updated, err := h.svc.Update(r.Context(), c)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, toResponse(updated))
}

// DELETE /api/alerts/channels/{id}
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Delete(r.Context(), r.PathValue("id")); err != nil {
		h.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/alerts/channels/{id}/test
func (h *Handler) Test(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.SendTest(r.Context(), r.PathValue("id")); err != nil {
		if errors.Is(err, ErrNotFound) {
			errs.WriteHTTPError(w, errs.NotFound("channel not found"))
			return
		}
		// Delivery failures are the user's config problem (bad token, channel) —
		// surface the Slack error message so they can fix it.
		errs.WriteHTTPError(w, errs.InvalidInput(err.Error()))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		errs.WriteHTTPError(w, errs.NotFound("channel not found"))
	case errors.Is(err, ErrMissingConfig):
		errs.WriteHTTPError(w, errs.InvalidInput("slack channels need bot_token + channel; webhook channels need webhook_url"))
	case errors.Is(err, ErrInvalidURL):
		errs.WriteHTTPError(w, errs.InvalidInput("webhook_url must be an http or https URL on port 80 or 443"))
	case errors.Is(err, ErrInvalidScope):
		errs.WriteHTTPError(w, errs.InvalidInput("environments must be drawn from prod, staging, dev, unknown"))
	case errors.Is(err, ErrUnsupported):
		errs.WriteHTTPError(w, errs.InvalidInput("unsupported channel type"))
	default:
		errs.WriteHTTPError(w, errs.Internal("channel operation failed"))
	}
}
