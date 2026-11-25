package auth

import (
	"net/http"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// RequireSession refuses a request that authenticated with an API key, for
// the admin writes a key must never make: user and role management, API key
// management, connector mode changes, purges and deletes, the approval policy
// and queue verdicts. An admin key may be held by an agent, and each of these
// either widens what the platform can do (a read_write connector, a looser
// approval policy, a fresh admin account or key) or destroys what an auditor
// needs (a purged connector's assets and findings). The refusal is a 403 and
// an auth.api_key_refused audit row naming the key and the route, the
// counterpart of the executor's executor.refused. Wrap it inside RequireAuth.
func (h *Handler) RequireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, viaKey := APIKeyFromContext(r.Context())
		if !viaKey {
			next(w, r)
			return
		}
		log.FromContext(r.Context()).Warn().Str("api_key_id", key.ID).Str("user_id", key.UserID).Str("route", r.Pattern).
			Msg("SECURITY: API key refused on a session-only route")
		if h.svc != nil {
			h.svc.RecordAPIKeyRefused(r.Context(), key, r.Pattern)
		}
		errs.WriteHTTPError(w, errs.Forbidden("API keys cannot make this change; sign in to make it"))
	}
}
