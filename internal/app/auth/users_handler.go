package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

type updateUserRequest struct {
	Role     *string `json:"role"`
	Disabled *bool   `json:"disabled"`
}

// UpdateUser changes another user's role and/or disabled state (admin).
// Route: PATCH /api/users/{id}, body {"role"?: "...", "disabled"?: bool}.
func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	actor, targetID, ok := h.userAdminTarget(w, r)
	if !ok {
		return
	}
	var req updateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("request body must be JSON"))
		return
	}
	if req.Role == nil && req.Disabled == nil {
		errs.WriteHTTPError(w, errs.InvalidInput("set at least one of: role, disabled"))
		return
	}
	upd := UserUpdate{Disabled: req.Disabled}
	if req.Role != nil {
		role := Role(*req.Role)
		upd.Role = &role
	}
	user, err := h.svc.UpdateUser(r.Context(), actor.ID, targetID, upd)
	if err != nil {
		writeUserAdminError(w, r, err, "update user")
		return
	}
	log.FromContext(r.Context()).Info().Str("actor_id", actor.ID).Str("target_id", targetID).
		Any("role", req.Role).Any("disabled", req.Disabled).Msg("auth: user updated")
	writeJSON(r.Context(), w, http.StatusOK, toUserListItem(user))
}

// DeleteUser removes another user with their sessions and API keys (admin).
// Route: DELETE /api/users/{id}.
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	actor, targetID, ok := h.userAdminTarget(w, r)
	if !ok {
		return
	}
	if err := h.svc.DeleteUser(r.Context(), actor.ID, targetID); err != nil {
		writeUserAdminError(w, r, err, "delete user")
		return
	}
	log.FromContext(r.Context()).Info().Str("actor_id", actor.ID).Str("target_id", targetID).Msg("auth: user deleted")
	w.WriteHeader(http.StatusNoContent)
}

// RevokeUserSessions signs another user out of every session (admin).
// Route: POST /api/users/{id}/revoke-sessions.
func (h *Handler) RevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	actor, targetID, ok := h.userAdminTarget(w, r)
	if !ok {
		return
	}
	n, err := h.svc.RevokeSessions(r.Context(), actor.ID, targetID)
	if err != nil {
		writeUserAdminError(w, r, err, "revoke sessions")
		return
	}
	log.FromContext(r.Context()).Info().Str("actor_id", actor.ID).Str("target_id", targetID).
		Int64("sessions", n).Msg("auth: user sessions revoked")
	w.WriteHeader(http.StatusNoContent)
}

// userAdminTarget resolves the acting admin and the {id} path value. A
// malformed id is a 404 like any other unknown user (the column is a uuid).
func (h *Handler) userAdminTarget(w http.ResponseWriter, r *http.Request) (User, string, bool) {
	if h.rejectWhenBypassed(w) {
		return User{}, "", false
	}
	actor, ok := UserFromContext(r.Context())
	if !ok {
		errs.WriteHTTPErrorCtx(r.Context(), w, "not authenticated", http.StatusUnauthorized)
		return User{}, "", false
	}
	if rejectAPIKey(w, r) {
		return User{}, "", false
	}
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		errs.WriteHTTPError(w, errs.NotFound("user not found"))
		return User{}, "", false
	}
	return actor, id, true
}

func writeUserAdminError(w http.ResponseWriter, r *http.Request, err error, op string) {
	switch {
	case errors.Is(err, ErrNotFound):
		errs.WriteHTTPError(w, errs.NotFound("user not found"))
	case errors.Is(err, ErrSelfAction):
		errs.WriteHTTPError(w, errs.Forbidden("you cannot change your own account here"))
	case errors.Is(err, ErrLastAdmin):
		errs.WriteHTTPError(w, errs.Conflict("this is the last active admin"))
	case errors.Is(err, ErrInvalidRole):
		errs.WriteHTTPError(w, errs.InvalidInput("role must be one of: admin, analyst, viewer"))
	default:
		log.FromContext(r.Context()).Error().Err(err).Msg(op + " failed")
		errs.WriteHTTPError(w, errs.Internal(op+" failed"))
	}
}

// rejectAPIKey refuses user administration on an API key. A key's principal is
// its owner, so without this a leaked admin key could create or promote an
// account of its own and keep access after the key is revoked, or disable the
// admins who would revoke it. Managing users takes a session.
func rejectAPIKey(w http.ResponseWriter, r *http.Request) bool {
	if _, viaKey := APIKeyFromContext(r.Context()); !viaKey {
		return false
	}
	errs.WriteHTTPError(w, errs.Forbidden("API keys cannot manage user accounts; sign in to manage users"))
	return true
}
