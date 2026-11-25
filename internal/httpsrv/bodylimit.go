package httpsrv

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/pkginv"
	"github.com/vulngraph/vulngraph/pkg/errs"
)

// defaultMaxBodyBytes caps every request body unless the route is listed in
// routeBodyLimits. Every JSON endpoint decodes the whole body into memory, so
// without a cap one request can make the serve pod allocate arbitrarily.
const defaultMaxBodyBytes int64 = 1 << 20 // 1 MiB

// routeBodyLimits raises the cap for the few routes whose payloads are
// legitimately larger. Keyed by exact path (none of these take path params).
var routeBodyLimits = map[string]int64{
	// Bulk findings from an external scanner (OpenVAS/Qualys/Burp export).
	"/api/scans/import": 32 << 20,
	// Nuclei template YAML; real templates are KiBs, workflows with many
	// embedded requests can reach a few hundred KiB.
	"/api/scans/templates/validate": 4 << 20,
	"/api/scans/templates/test":     4 << 20,
	"/api/scans/templates/generate": 4 << 20,
	// The chat UI resends the whole conversation, tool results included.
	"/api/chat": 8 << 20,
	// A customer agent's package inventory (up to 10,000 packages).
	"/api/package-inventory": pkginv.MaxBodyBytes,
}

func bodyLimitFor(path string) int64 {
	if n, ok := routeBodyLimits[path]; ok {
		return n
	}
	if strings.HasPrefix(path, "/api/assets/") && strings.HasSuffix(path, "/package-inventory") {
		return pkginv.MaxBodyBytes
	}
	return defaultMaxBodyBytes
}

// withBodyLimit rejects a declared-oversize body with 413 before any handler
// runs, and wraps every body in http.MaxBytesReader so a body without (or
// lying about) Content-Length is cut off at the same limit: the handler's
// decode then fails instead of buffering without bound.
func withBodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := bodyLimitFor(r.URL.Path)
		if r.ContentLength > limit {
			errs.WriteHTTPErrorCtx(r.Context(), w,
				fmt.Sprintf("request body exceeds %d bytes", limit), http.StatusRequestEntityTooLarge)
			return
		}
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}
