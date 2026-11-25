package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/suppress"
)

// mcpSuppressMaxDays is suppress.AgentMaxExpiry in days: the caller is
// usually an LLM agent acting on an admin's token, so whatever it silences
// comes back in front of a person within a month.
const mcpSuppressMaxDays = int(suppress.AgentMaxExpiry / (24 * time.Hour))

// errNeedsHuman is returned when suppress_finding refuses a finding that only
// a person may silence (urgent, must-fix, critical, or not yet scored).
var errNeedsHuman = errors.New("refused: this finding can only be suppressed by a person in the UI")

// registerSuppressFinding registers the suppress_finding write tool. Admin-only
// — the MCP endpoint authenticates but does not gate on role, so the tool
// enforces it from the session.
func (h *Handler) registerSuppressFinding(findingCtx FindingContextReader, sup SuppressionWriter) {
	h.register(tool{
		Name: "suppress_finding",
		Description: fmt.Sprintf("Suppress a low-urgency finding with a reason so it stops entering the decision pipeline, until the expiry (1-%d days) lapses and it re-enters triage. "+
			"Refused for critical, must-fix, page/high-band or not-yet-scored findings: those need a person in the UI. Admin only.", mcpSuppressMaxDays),
		InputSchema: objSchema(map[string]any{
			"finding_id":      strProp("the finding id to suppress"),
			"reason":          strProp("why it is being suppressed"),
			"expires_in_days": intProp(fmt.Sprintf("days until the suppression lapses and the finding is triaged again (1-%d)", mcpSuppressMaxDays)),
		}, "finding_id", "reason", "expires_in_days"),
		handler: func(ctx context.Context, args map[string]any) (any, error) {
			user, ok := auth.UserFromContext(ctx)
			if !ok || user.Role != auth.RoleAdmin {
				return nil, errForbidden
			}
			id, _ := args["finding_id"].(string)
			reason, _ := args["reason"].(string)
			if strings.TrimSpace(id) == "" || strings.TrimSpace(reason) == "" {
				return nil, fmt.Errorf("%w: finding_id and reason are required", errInvalidParams)
			}
			// Required like the HTTP API's expires_at: an exception nobody chose
			// an end for is one nobody looks at again.
			days := intArg(args, "expires_in_days", 0)
			if days < 1 || days > mcpSuppressMaxDays {
				return nil, fmt.Errorf("%w: expires_in_days must be between 1 and %d", errInvalidParams, mcpSuppressMaxDays)
			}
			fc, err := findingCtx.Context(ctx, id)
			if err != nil {
				return nil, fmt.Errorf("suppress_finding: %w", err)
			}
			if why := enrich.AgentRefusal(fc.Finding); why != "" {
				return nil, fmt.Errorf("%w (%s)", errNeedsHuman, why)
			}
			by := user.Email
			if by == "" {
				by = user.ID
			}
			return sup.SuppressUntil(ctx, id, reason, "mcp:"+by, time.Now().Add(time.Duration(days)*24*time.Hour))
		},
	})
}
