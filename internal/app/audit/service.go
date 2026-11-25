package audit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Writer persists one event. CHRepo implements it.
type Writer interface {
	Write(ctx context.Context, e Event) error
}

// Service attributes and writes admin-action rows.
type Service struct {
	repo          Writer
	now           func() time.Time
	fallbackActor string
}

func NewService(repo Writer) *Service {
	return &Service{repo: repo, now: time.Now, fallbackActor: ActorUnknown}
}

// WithFallbackActor names the actor of rows written with no authenticated
// principal on the context (ActorCLI for the `graph user` commands).
func (s *Service) WithFallbackActor(actor string) *Service {
	s.fallbackActor = actor
	return s
}

// Record writes the row for an admin action that has already taken effect.
// The actor is the authenticated user on ctx. details must carry no secret.
//
// A write failure does not undo the action or fail the caller, whose change
// is committed; it is logged at error level as AUDIT WRITE FAILED, the line
// to alert on.
func (s *Service) Record(ctx context.Context, action, targetType, targetID string, details map[string]any) {
	e := s.event(ctx, action, targetType, targetID, details)
	if err := s.repo.Write(ctx, e); err != nil {
		log.FromContext(ctx).Error().Err(err).
			Str("action", action).Str("actor", e.Actor).Str("target_type", targetType).Str("target_id", targetID).
			Msg("audit: AUDIT WRITE FAILED — an admin action has no audit row")
	}
}

func (s *Service) event(ctx context.Context, action, targetType, targetID string, details map[string]any) Event {
	out := make(map[string]any, len(details)+3)
	for k, v := range details {
		out[k] = v
	}
	actor := s.fallbackActor
	if u, ok := auth.UserFromContext(ctx); ok {
		out["actor_user_id"] = u.ID
		if u.Email != "" {
			actor = u.Email
		}
	}
	if k, ok := auth.APIKeyFromContext(ctx); ok {
		out["api_key_id"] = k.ID
	}
	if ip := auth.ClientIPFromContext(ctx); ip != "" {
		out["client_ip"] = ip
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		encoded = []byte(`{"error":"audit details could not be encoded"}`)
	}
	return Event{
		TS: s.now().UTC(), Actor: actor, Action: action,
		TargetType: targetType, TargetID: targetID, Details: string(encoded),
	}
}
