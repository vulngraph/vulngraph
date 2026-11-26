package mcp

// Drift analysis exposes read-only tools over advisory LLM verdicts.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/driftanalysis"
)

// maxDriftSince mirrors the REST bound: batches are pruned after 90 days.
const maxDriftSince = 90 * 24 * time.Hour

// DriftAnalysisReader reads drift analyses. *driftanalysis.Service implements it.
type DriftAnalysisReader interface {
	List(ctx context.Context, p driftanalysis.ListParams) (driftanalysis.Listing, error)
	Get(ctx context.Context, batchID string) (driftanalysis.Batch, error)
}

// WithDriftAnalysis registers read-only drift analysis tools.
func (h *Handler) WithDriftAnalysis(reader DriftAnalysisReader) *Handler {
	h.register(tool{
		Name: "list_drift_analyses",
		Description: "List advisory LLM analyses of inventory drift batches (one batch = the changes on one connector since the last batch), newest first. " +
			"Every field is LLM-derived and advisory. scan_recommendation is recommended, not_needed or unknown; unknown means not analysed, never 'no scan needed'. " +
			"enabled false means analysis is switched off, which is not a verdict.",
		InputSchema: objSchema(map[string]any{
			"since": strProp("lookback as a Go duration, e.g. 24h or 168h (no d unit; default 720h, max 2160h)"),
			"limit": intProp("max analyses to return (1-200, default 50)"),
		}),
		handler: func(ctx context.Context, args map[string]any) (any, error) {
			var p driftanalysis.ListParams
			if raw, _ := args["since"].(string); raw != "" {
				d, err := time.ParseDuration(raw)
				if err != nil || d <= 0 || d > maxDriftSince {
					return nil, fmt.Errorf("%w: since must be a positive Go duration up to 2160h", errInvalidParams)
				}
				p.Since = time.Now().Add(-d)
			}
			p.Limit = intArg(args, "limit", 0)
			if p.Limit < 0 || p.Limit > 200 {
				return nil, fmt.Errorf("%w: limit must be between 1 and 200", errInvalidParams)
			}
			l, err := reader.List(ctx, p)
			if err != nil {
				return nil, fmt.Errorf("list_drift_analyses: %w", err)
			}
			return driftanalysis.ToListResponse(l), nil
		},
	})
	h.register(tool{
		Name: "get_drift_analysis",
		Description: "One drift batch analysis by batch_id: summary, per-asset changes, exposure judgement, scan recommendation with reason and evidence. " +
			"LLM-derived and advisory; scan_recommendation unknown means not analysed, never 'no scan needed'.",
		InputSchema: objSchema(map[string]any{"batch_id": strProp("the batch id from list_drift_analyses")}, "batch_id"),
		handler: func(ctx context.Context, args map[string]any) (any, error) {
			id, _ := args["batch_id"].(string)
			if strings.TrimSpace(id) == "" {
				return nil, fmt.Errorf("%w: batch_id is required", errInvalidParams)
			}
			b, err := reader.Get(ctx, id)
			if errors.Is(err, driftanalysis.ErrNotFound) {
				return nil, fmt.Errorf("%w: no drift analysis with that batch_id", errInvalidParams)
			}
			if err != nil {
				return nil, fmt.Errorf("get_drift_analysis: %w", err)
			}
			return driftanalysis.ToResponse(b), nil
		},
	})
	return h
}
