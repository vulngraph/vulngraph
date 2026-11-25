package asset

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// DriftRepo is the narrow interface the handler needs.
type DriftRepo interface {
	DriftEvents(ctx context.Context, since time.Duration, limit int) ([]DriftEvent, error)
	PGDriftEvents(ctx context.Context, pool pgDriftPool, since time.Duration, limit int) ([]DriftEvent, error)
}

// DriftHandler serves GET /api/drift/events.
// When a pgDriftPool is provided it uses the richer Postgres-backed query that
// surfaces changed assets (IP/name drift) in addition to new assets. Without a
// pool it falls back to the ClickHouse-only query.
type DriftHandler struct {
	repo DriftRepo
	pool pgDriftPool // nil = ClickHouse-only fallback
}

// NewDriftHandlerWithPool constructs a DriftHandler that queries Postgres for
// new/changed assets and enriches them from ClickHouse.
func NewDriftHandlerWithPool(repo *CHRepo, pool pgDriftPool) *DriftHandler {
	return &DriftHandler{repo: repo, pool: pool}
}

// Events handles GET /api/drift/events?since=24h&limit=100
// Returns inventory changes (new assets, new exposures, changed assets) within the window.
func (h *DriftHandler) Events(w http.ResponseWriter, r *http.Request) {
	sinceStr := r.URL.Query().Get("since")
	if sinceStr == "" {
		sinceStr = "24h"
	}
	since, err := time.ParseDuration(sinceStr)
	if err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid since parameter — use a Go duration e.g. 24h or 168h (there is no d unit)"))
		return
	}
	if since > 30*24*time.Hour {
		since = 30 * 24 * time.Hour // cap at 30 days
	}
	limit := 200
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	var events []DriftEvent
	if h.pool != nil {
		events, err = h.repo.PGDriftEvents(r.Context(), h.pool, since, limit)
	} else {
		events, err = h.repo.DriftEvents(r.Context(), since, limit)
	}
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("drift events query failed")
		errs.WriteHTTPError(w, errs.Internal("drift query failed"))
		return
	}
	if events == nil {
		events = []DriftEvent{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"events": events})
}
