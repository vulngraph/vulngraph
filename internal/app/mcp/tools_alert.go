package mcp

import (
	"context"
	"errors"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/alertctx"
)

// errInvalidParams marks a tool failure caused by the caller's arguments, so the
// client sees what to fix instead of the generic "tool execution failed".
var errInvalidParams = errors.New("invalid params")

// AlertContexter resolves alert identifiers to graph assets and assembles their
// context. alertctx.Service implements it.
type AlertContexter interface {
	Context(ctx context.Context, identifiers []string) (alertctx.Result, error)
}

// WithAlertContext registers get_alert_context. Called only when the stores
// behind it are wired, like the graph tools.
func (h *Handler) WithAlertContext(c AlertContexter) *Handler {
	h.register(tool{
		Name: "get_alert_context",
		Description: "Graph context for an alert. Give it the identifiers the alert carries (any mix of: asset id, " +
			"ARN incl. assumed-role session ARN, EC2 instance id, public or private IP, hostname/DNS name, email, " +
			"k8s namespace/name) and it resolves each to graph assets (with match_type and confidence), then returns per " +
			"asset: type/account/region/environment/owner, risk score, internet exposure, attacker-direction blast " +
			"radius (counts by type, top reachable assets), open findings (by severity, must-fix with reasons), " +
			"and for identities whether privilege escalation paths exist. Unresolved identifiers are listed " +
			"explicitly. Every section has known; known=false means NOT MEASURED, never 'no risk'. Output is bounded; " +
			"check truncated. Use this first when triaging a SIEM alert.",
		InputSchema: objSchema(map[string]any{
			"identifiers": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"maxItems":    alertctx.MaxIdentifiers,
				"description": "identifiers from the alert: IPs, ARNs, instance ids, hostnames, emails, namespace/name, asset ids",
			},
		}, "identifiers"),
		limit: limitAlertContext,
		handler: func(ctx context.Context, args map[string]any) (any, error) {
			ids, err := stringList(args, "identifiers")
			if err != nil {
				return nil, fmt.Errorf("get_alert_context: %w: %w", errInvalidParams, err)
			}
			res, err := c.Context(ctx, ids)
			switch {
			case errors.Is(err, alertctx.ErrNoIdentifiers), errors.Is(err, alertctx.ErrTooManyIDs):
				return nil, fmt.Errorf("get_alert_context: %w: %w", errInvalidParams, err)
			case err != nil:
				return nil, fmt.Errorf("get_alert_context: %w", err)
			}
			return alertctx.ToResponse(res), nil
		},
	})
	return h
}

// stringList reads a required array-of-strings argument.
func stringList(args map[string]any, key string) ([]string, error) {
	raw, ok := args[key].([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array of strings", key)
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s must contain only strings", key)
		}
		out = append(out, s)
	}
	return out, nil
}
