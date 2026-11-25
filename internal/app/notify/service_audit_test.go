package notify

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type auditRow struct {
	action, targetType, targetID string
	details                      map[string]any
}

type fakeAudit struct{ rows []auditRow }

func (f *fakeAudit) Record(_ context.Context, action, targetType, targetID string, details map[string]any) {
	f.rows = append(f.rows, auditRow{action, targetType, targetID, details})
}

// Channel changes are audited without the bot token or webhook URL: an
// update says whether the secret was replaced and where alerts now go.
func TestChannelCRUD_IsAuditedWithoutSecrets(t *testing.T) {
	repo := &fakeRepo{}
	a := &fakeAudit{}
	svc := (&Service{repo: repo, now: time.Now}).WithAudit(a)
	ctx := context.Background()

	const hookURL = "https://user:pw@hooks.example.com/services/T000/B000/not-a-real-token"
	_, err := svc.Create(ctx, Channel{ID: "ch-1", Type: TypeWebhook, Name: "soc", WebhookURL: hookURL, Enabled: true})
	require.NoError(t, err)
	_, err = svc.Create(ctx, Channel{ID: "ch-2", Type: TypeSlack, Name: "alerts", SlackChannel: "#sec", BotToken: "xoxb-not-a-real-token"})
	require.NoError(t, err)
	_, err = svc.Update(ctx, Channel{ID: "ch-2", Type: TypeSlack, Name: "alerts", SlackChannel: "#sec"})
	require.NoError(t, err)
	_, err = svc.Update(ctx, Channel{ID: "ch-1", Type: TypeWebhook, Name: "soc", WebhookURL: "https://other.example.net/h"})
	require.NoError(t, err)
	_, err = svc.Update(ctx, Channel{ID: "ch-1", Type: TypeWebhook, Name: "soc"})
	require.NoError(t, err)
	repo.channels = []Channel{ // as List returns them: secrets omitted
		{ID: "ch-1", Type: TypeWebhook, Name: "soc", Enabled: true},
		{ID: "ch-2", Type: TypeSlack, Name: "alerts", SlackChannel: "#sec"},
	}
	require.NoError(t, svc.Delete(ctx, "ch-2"))
	require.NoError(t, svc.Delete(ctx, "ch-1"))

	require.Equal(t, []auditRow{
		{AuditActionChannelCreate, AuditTargetChannel, "ch-1", map[string]any{"type": "webhook", "name": "soc", "enabled": true, "webhook_host": "hooks.example.com"}},
		{AuditActionChannelCreate, AuditTargetChannel, "ch-2", map[string]any{"type": "slack", "name": "alerts", "enabled": false, "slack_channel": "#sec"}},
		{AuditActionChannelUpdate, AuditTargetChannel, "ch-2", map[string]any{"type": "slack", "name": "alerts", "enabled": false, "slack_channel": "#sec", "secret_replaced": false}},
		{AuditActionChannelUpdate, AuditTargetChannel, "ch-1", map[string]any{"type": "webhook", "name": "soc", "enabled": false, "webhook_host": "other.example.net", "secret_replaced": true}},
		{AuditActionChannelUpdate, AuditTargetChannel, "ch-1", map[string]any{"type": "webhook", "name": "soc", "enabled": false, "secret_replaced": false}},
		{AuditActionChannelDelete, AuditTargetChannel, "ch-2", map[string]any{"type": "slack", "name": "alerts", "enabled": false, "slack_channel": "#sec"}},
		{AuditActionChannelDelete, AuditTargetChannel, "ch-1", map[string]any{"type": "webhook", "name": "soc", "enabled": true}},
	}, a.rows)
	for _, r := range a.rows {
		for _, v := range r.details {
			if s, ok := v.(string); ok {
				require.NotContains(t, s, "token")
				require.NotContains(t, s, "user:pw", "no userinfo")
			}
		}
	}
}

func TestChannelCreate_RefusedWritesNoRow(t *testing.T) {
	a := &fakeAudit{}
	svc := (&Service{repo: &fakeRepo{}, now: time.Now}).WithAudit(a)
	_, err := svc.Create(context.Background(), Channel{Type: TypeSlack, Name: "x"})
	require.ErrorIs(t, err, ErrMissingConfig)
	require.Empty(t, a.rows)
}
