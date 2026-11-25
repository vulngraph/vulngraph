package apikey

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Handler serves the /api/keys routes.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// apiKeyResponse is what the API returns for an existing key (no plaintext).
type apiKeyResponse struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     string     `json:"scopes"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

// createResponse extends apiKeyResponse with the one-time plaintext key.
type createResponse struct {
	apiKeyResponse
	Key string `json:"key"` // plaintext — shown once
}

type createRequest struct {
	Name      string     `json:"name"`
	Scopes    string     `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// List returns all API keys owned by the authenticated user.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	u, ok := auth.UserFromContext(r.Context())
	if !ok {
		errs.WriteHTTPError(w, errs.Forbidden("not authenticated"))
		return
	}
	keys, err := h.svc.List(r.Context(), u.ID)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("list api keys failed")
		errs.WriteHTTPError(w, errs.Internal("failed to list api keys"))
		return
	}
	out := make([]apiKeyResponse, len(keys))
	for i, k := range keys {
		out[i] = toResponse(k)
	}
	writeJSON(r.Context(), w, http.StatusOK, out)
}

// Create generates a new API key for the authenticated user and returns the
// plaintext key once. The caller must store it — it cannot be retrieved later.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	u, ok := sessionPrincipal(w, r)
	if !ok {
		return
	}

	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("request body must be valid JSON"))
		return
	}
	if req.Scopes == "" {
		req.Scopes = string(ScopeRead)
	}

	// Privilege clamp: a key's scope maps to a role (read→viewer, write→analyst,
	// admin→admin), so a caller must never mint a key that grants more access
	// than the caller's own role. Without this, a read-scoped key (or any
	// non-admin user) could create an admin key and escalate to cloud-mutating
	// tools. Invalid scopes map to viewer here and are rejected by svc.Create.
	if auth.APIKeyScopeToRole(req.Scopes).Privilege() > u.Role.Privilege() {
		errs.WriteHTTPError(w, errs.Forbidden("cannot create an API key with more privilege than your role"))
		return
	}

	if Scope(req.Scopes) == ScopeInventory && u.Role != auth.RoleAdmin {
		errs.WriteHTTPError(w, errs.Forbidden("only an admin can create an inventory API key"))
		return
	}

	key, plaintext, err := h.svc.Create(r.Context(), u.ID, req.Name, Scope(req.Scopes), req.ExpiresAt)
	switch {
	case errors.Is(err, ErrInvalidScope):
		errs.WriteHTTPError(w, errs.InvalidInput("scope must be one of: read, write, admin, inventory"))
		return
	case errors.Is(err, ErrNameRequired):
		errs.WriteHTTPError(w, errs.InvalidInput("name is required"))
		return
	case errors.Is(err, ErrBadExpiry):
		errs.WriteHTTPError(w, errs.InvalidInput(ErrBadExpiry.Error()))
		return
	case err != nil:
		log.FromContext(r.Context()).Error().Err(err).Msg("create api key failed")
		errs.WriteHTTPError(w, errs.Internal("failed to create api key"))
		return
	}

	writeJSON(r.Context(), w, http.StatusCreated, createResponse{
		apiKeyResponse: toResponse(key),
		Key:            plaintext,
	})
}

// Delete removes an API key owned by the authenticated user.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	u, ok := sessionPrincipal(w, r)
	if !ok {
		return
	}

	id := r.PathValue("id")
	if id == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("id is required"))
		return
	}

	err := h.svc.Delete(r.Context(), id, u.ID)
	switch {
	case errors.Is(err, ErrNotFound):
		errs.WriteHTTPError(w, errs.NotFound("api key not found"))
		return
	case err != nil:
		log.FromContext(r.Context()).Error().Err(err).Msg("delete api key failed")
		errs.WriteHTTPError(w, errs.Internal("failed to delete api key"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// sessionPrincipal returns the caller for a key-management write, refusing
// one that authenticated with an API key. The principal of a key request is
// the key's owner, so without this a leaked read-scoped key could mint fresh
// keys (re-arming itself past revocation of the original) and delete the
// owner's other keys, admin ones included. Managing keys takes a session.
func sessionPrincipal(w http.ResponseWriter, r *http.Request) (auth.User, bool) {
	u, ok := auth.UserFromContext(r.Context())
	if !ok {
		errs.WriteHTTPError(w, errs.Forbidden("not authenticated"))
		return auth.User{}, false
	}
	if _, viaKey := auth.APIKeyFromContext(r.Context()); viaKey {
		errs.WriteHTTPError(w, errs.Forbidden("API keys cannot create or delete API keys; sign in to manage keys"))
		return auth.User{}, false
	}
	return u, true
}

func toResponse(k APIKey) apiKeyResponse {
	return apiKeyResponse{
		ID:         k.ID,
		Name:       k.Name,
		Prefix:     k.Prefix,
		Scopes:     string(k.Scopes),
		LastUsedAt: k.LastUsedAt,
		ExpiresAt:  k.ExpiresAt,
		CreatedAt:  k.CreatedAt,
	}
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("write response failed")
	}
}
