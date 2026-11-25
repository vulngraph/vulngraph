package httpsrv

import (
	"net/http"
	"strings"

	"github.com/vulngraph/vulngraph/pkg/errs"
)

// apiFallbackPattern catches every /api/ request no specific route matched.
// Without it the SPA catch-all answers an unknown API path (or a known path
// with the wrong method) with index.html and a 200, which API clients then
// fail to parse as JSON.
const apiFallbackPattern = "/api/"

// probeMethods are the methods tried when deciding between 404 and 405.
var probeMethods = []string{
	http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
}

// apiFallback answers unmatched /api/ requests with RFC 9457 problems: 405
// (with Allow) when the path is registered under other methods, 404 otherwise.
func apiFallback(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var allowed []string
		for _, m := range probeMethods {
			probe := r.Clone(r.Context())
			probe.Method = m
			if _, pattern := mux.Handler(probe); pattern != "" && pattern != apiFallbackPattern {
				allowed = append(allowed, m)
			}
		}
		if len(allowed) > 0 {
			w.Header().Set("Allow", strings.Join(allowed, ", "))
			errs.WriteHTTPErrorCtx(r.Context(), w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		errs.WriteHTTPErrorCtx(r.Context(), w, "no such API endpoint", http.StatusNotFound)
	})
}
