package mcp

// Drift analysis: two read tools over the advisory LLM verdicts, and the one
// write tool an agent may use on them. A verdict is data the agent reads, never
// authority: start_profile_scan is admin-only and audited whatever the verdict
// says, and nothing in this file consults one.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/driftanalysis"
	"github.com/vulngraph/vulngraph/internal/app/executor"
	"github.com/vulngraph/vulngraph/internal/app/scan"
)

// auditActionScanStart is the audit_events action for a scan an agent started.
const auditActionScanStart = "mcp.scan_start"

// maxDriftSince mirrors the REST bound: batches are pruned after 90 days.
const maxDriftSince = 90 * 24 * time.Hour

// DriftAnalysisReader reads drift analyses. *driftanalysis.Service implements it.
type DriftAnalysisReader interface {
	List(ctx context.Context, p driftanalysis.ListParams) (driftanalysis.Listing, error)
	Get(ctx context.Context, batchID string) (driftanalysis.Batch, error)
}

// ScanStarter starts a scan profile exactly as POST /api/scan-profiles/{id}/trigger
// does: run row, in-transaction enqueue and the scan.profile_start audit row.
// *scan.ProfileService implements it.
type ScanStarter interface {
	StartProfileScan(ctx context.Context, profileID string) (string, error)
}

// needsAdminError is an errNeedsHuman with a message that names the real rule.
type needsAdminError struct{ msg string }

func (e needsAdminError) Error() string        { return e.msg }
func (e needsAdminError) Is(target error) bool { return target == errNeedsHuman }

var errScanNeedsAdmin = needsAdminError{"refused: starting a scan needs an admin; ask a person to start it in the UI"}

// WithDriftAnalysis registers the drift analysis tools. Called only when the
// analysis store is wired. The scan limiter (WithScanLimit) must be wired too,
// or start_profile_scan is refused.
func (h *Handler) WithDriftAnalysis(reader DriftAnalysisReader, starter ScanStarter) *Handler {
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
	h.register(tool{
		Name: "start_profile_scan",
		Description: "Start a scan run for a scan profile, the same as the Start button in the UI. Admin only and audited. " +
			"A drift analysis is advice, not authorization: this tool does not read it. " +
			"drift_batch_id optionally records which analysis prompted the scan in the audit row.",
		InputSchema: objSchema(map[string]any{
			"profile_id":     strProp("the scan profile id"),
			"drift_batch_id": strProp("optional: the drift analysis batch that prompted this scan, recorded for the audit trail"),
		}, "profile_id"),
		limit: limitScanStart,
		handler: func(ctx context.Context, args map[string]any) (any, error) {
			user, ok := auth.UserFromContext(ctx)
			if !ok || user.Role != auth.RoleAdmin {
				return nil, errScanNeedsAdmin
			}
			profileID, _ := args["profile_id"].(string)
			batchID, _ := args["drift_batch_id"].(string)
			if strings.TrimSpace(profileID) == "" {
				return nil, fmt.Errorf("%w: profile_id is required", errInvalidParams)
			}
			if batchID != "" {
				if _, err := reader.Get(ctx, batchID); errors.Is(err, driftanalysis.ErrNotFound) {
					return nil, fmt.Errorf("%w: no drift analysis with that drift_batch_id", errInvalidParams)
				} else if err != nil {
					return nil, fmt.Errorf("start_profile_scan: %w", err)
				}
			}
			if err := h.auditScanStart(ctx, user, profileID, batchID); err != nil {
				return nil, err
			}
			runID, err := starter.StartProfileScan(ctx, profileID)
			if errors.Is(err, scan.ErrProfileNotFound) {
				return nil, fmt.Errorf("%w: no scan profile with that profile_id", errInvalidParams)
			}
			if err != nil {
				return nil, fmt.Errorf("start_profile_scan: %w", err)
			}
			return map[string]any{"run_id": runID, "profile_id": profileID}, nil
		},
	})
	return h
}

// auditScanStart writes the mcp.scan_start row BEFORE the scan is queued. A
// start that cannot be audited is refused, the same rule liveGate applies.
func (h *Handler) auditScanStart(ctx context.Context, u auth.User, profileID, batchID string) error {
	if h.audit == nil {
		return nil
	}
	d := map[string]any{"tool": "start_profile_scan", "profile_id": profileID, "actor_user_id": u.ID}
	if batchID != "" {
		d["drift_batch_id"] = batchID
	}
	details, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("start_profile_scan: audit: %w", err)
	}
	actor := u.Email
	if actor == "" {
		actor = executor.AuditActorUnknown
	}
	if err := h.audit.RecordAudit(ctx, executor.AuditEvent{
		TS: time.Now().UTC(), Actor: actor, Action: auditActionScanStart,
		TargetType: scan.AuditTargetScanProfile, TargetID: profileID, Details: string(details),
	}); err != nil {
		return fmt.Errorf("start_profile_scan: audit write failed, scan refused: %w", err)
	}
	return nil
}
