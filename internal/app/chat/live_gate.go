package chat

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/executor"
	"github.com/vulngraph/vulngraph/internal/llm"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// liveTools reach a real cloud account (or enumerate the connectors that do).
// They are offered only to users at or above the live role, and every call
// writes an audit row first — the same rules as the MCP seam's live tools.
var liveTools = map[string]bool{
	"list_connectors":       true,
	"live_aws_describe":     true,
	"get_cloudtrail_events": true,
}

// Bounds on a CloudTrail lookup, matching the MCP tool.
const (
	defaultTrailHours = 24
	maxTrailHours     = 72
	defaultTrailLimit = 50
	maxTrailLimit     = 200
)

// auditActionLiveRead is the audit_events action for a live cloud read from chat.
const auditActionLiveRead = "chat.live_read"

// maxAuditedInput caps how much model-written tool input lands in an audit row.
const maxAuditedInput = 2048

// Auditor appends to the shared audit trail. *executor.CHAuditRepo implements it.
type Auditor interface {
	RecordAudit(ctx context.Context, e executor.AuditEvent) error
}

// WithLiveRole sets the minimum role for the live cloud tools (admin by default).
func (s *Service) WithLiveRole(r auth.Role) *Service {
	s.liveRole = r
	return s
}

// WithAudit attaches the audit sink for live cloud reads.
func (s *Service) WithAudit(a Auditor) *Service {
	s.audit = a
	return s
}

// liveAllowed reports whether the request's user may use the live tools.
// An unset or unknown configured role fails closed to admin.
func (s *Service) liveAllowed(ctx context.Context) (auth.User, bool) {
	u, ok := auth.UserFromContext(ctx)
	if !ok || !u.Role.Valid() {
		return auth.User{}, false
	}
	need := s.liveRole
	if !need.Valid() {
		need = auth.RoleAdmin
	}
	return u, u.Role.Privilege() >= need.Privilege()
}

// toolsFor is toolDefs minus the live tools the user may not call, so the
// model is never offered a tool that would only be refused.
func (s *Service) toolsFor(ctx context.Context) []llm.Tool {
	all := s.toolDefs()
	if _, ok := s.liveAllowed(ctx); ok {
		return all
	}
	out := make([]llm.Tool, 0, len(all))
	for _, t := range all {
		if !liveTools[t.Name] {
			out = append(out, t)
		}
	}
	return out
}

// liveGate checks the role and writes the audit row BEFORE a live read. A
// read that cannot be audited is refused.
func (s *Service) liveGate(ctx context.Context, name, inputJSON string) error {
	u, ok := s.liveAllowed(ctx)
	if !ok {
		return fmt.Errorf("tool %q requires the %s role", name, s.requiredLiveRole())
	}
	if s.audit == nil {
		return nil
	}
	var in struct {
		ConnectorID string `json:"connector_id"`
	}
	_ = json.Unmarshal([]byte(inputJSON), &in)
	if len(inputJSON) > maxAuditedInput {
		inputJSON = inputJSON[:maxAuditedInput]
	}
	details, err := json.Marshal(map[string]any{"tool": name, "input": inputJSON, "actor_user_id": u.ID})
	if err != nil {
		return fmt.Errorf("%s: audit: %w", name, err)
	}
	actor := u.Email
	if actor == "" {
		actor = executor.AuditActorUnknown
	}
	if err := s.audit.RecordAudit(ctx, executor.AuditEvent{
		TS: time.Now().UTC(), Actor: actor, Action: auditActionLiveRead,
		TargetType: executor.AuditTargetConnector, TargetID: in.ConnectorID, Details: string(details),
	}); err != nil {
		log.FromContext(ctx).Error().Err(err).Str("tool", name).Msg("chat: live read audit failed, refused")
		return fmt.Errorf("%s: the audit trail is unavailable, so the live read was refused", name)
	}
	return nil
}

func (s *Service) requiredLiveRole() auth.Role {
	if s.liveRole.Valid() {
		return s.liveRole
	}
	return auth.RoleAdmin
}

// clamp bounds v to [lo, hi], using def when v was not given (<= 0).
func clamp(v, def, lo, hi int) int {
	if v <= 0 {
		v = def
	}
	return max(lo, min(v, hi))
}
