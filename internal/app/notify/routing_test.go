package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChannelAccepts_OwnerAndEnvironmentScope(t *testing.T) {
	payments := Notification{EventType: EventFinding, Severity: SeverityHigh, Owner: "payments", Environment: "prod"}
	unowned := Notification{EventType: EventFinding, Severity: SeverityHigh, Unowned: true, Environment: "unknown"}
	phishing := Notification{EventType: EventPhishing, Severity: SeverityHigh} // no owner/env dimension

	tests := []struct {
		name string
		ch   Channel
		n    Notification
		want bool
	}{
		{"unscoped channel takes owned findings", Channel{Enabled: true}, payments, true},
		{"unscoped channel takes unowned findings", Channel{Enabled: true}, unowned, true},
		{"unscoped channel takes ownerless events", Channel{Enabled: true}, phishing, true},

		{"team channel takes its team", Channel{Enabled: true, OwnerTeams: []string{"payments"}}, payments, true},
		{"team match is case-insensitive", Channel{Enabled: true, OwnerTeams: []string{"Payments"}}, payments, true},
		{"team channel rejects another team", Channel{Enabled: true, OwnerTeams: []string{"identity"}}, payments, false},
		{"team channel rejects unowned", Channel{Enabled: true, OwnerTeams: []string{"payments"}}, unowned, false},
		{"team channel rejects ownerless events", Channel{Enabled: true, OwnerTeams: []string{"payments"}}, phishing, false},

		{"unowned default takes unowned", Channel{Enabled: true, RouteUnowned: true}, unowned, true},
		{"unowned default alone rejects owned", Channel{Enabled: true, RouteUnowned: true}, payments, false},
		{"unowned default rejects ownerless events", Channel{Enabled: true, RouteUnowned: true}, phishing, false},
		{"team + unowned default takes both",
			Channel{Enabled: true, OwnerTeams: []string{"payments"}, RouteUnowned: true}, unowned, true},

		{"prod channel takes prod", Channel{Enabled: true, Environments: []string{"prod"}}, payments, true},
		{"prod channel rejects unknown", Channel{Enabled: true, Environments: []string{"prod"}}, unowned, false},
		{"unknown is listable", Channel{Enabled: true, Environments: []string{"prod", "unknown"}}, unowned, true},
		{"env channel rejects env-less events", Channel{Enabled: true, Environments: []string{"prod"}}, phishing, false},

		{"scopes AND together",
			Channel{Enabled: true, OwnerTeams: []string{"payments"}, Environments: []string{"staging"}}, payments, false},
		{"scopes AND with severity",
			Channel{Enabled: true, OwnerTeams: []string{"payments"}, Severities: []string{SeverityCritical}}, payments, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.ch.accepts(tt.n))
		})
	}
}

// An unowned finding reaches the configured default channel and no team's.
func TestDispatch_UnownedFindingRoutesToDefaultChannel(t *testing.T) {
	repo := &fakeRepo{channels: []Channel{
		{ID: "payments", Type: TypeSlack, Enabled: true, OwnerTeams: []string{"payments"}},
		{ID: "triage", Type: TypeSlack, Enabled: true, RouteUnowned: true},
		{ID: "prod-oncall", Type: TypeSlack, Enabled: true, Environments: []string{"prod"}},
	}}
	poster := &fakePoster{}
	svc := &Service{repo: repo, slack: poster, now: time.Now}

	svc.Dispatch(context.Background(), Notification{EventType: EventFinding, Severity: SeverityHigh, Unowned: true, Environment: "prod"})

	var ids []string
	for _, ch := range poster.sent {
		ids = append(ids, ch.ID)
	}
	assert.ElementsMatch(t, []string{"triage", "prod-oncall"}, ids)
}

func TestHandlerCreate_RoutingScope(t *testing.T) {
	repo := &captureRepo{}
	h := NewHandler(&Service{repo: repo, now: time.Now})

	body, _ := json.Marshal(map[string]any{
		"type": "webhook", "name": "payments", "webhook_url": "https://example.com/h", "enabled": true,
		"owner_teams": []string{"@acme/Payments", "payments", " "}, "environments": []string{"prod"},
		"route_unowned": true,
	})
	rec := httptest.NewRecorder()
	h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/alerts/channels", bytes.NewReader(body)))
	require.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, []string{"payments"}, repo.created.OwnerTeams, "normalised and de-duplicated")
	assert.Equal(t, []string{"prod"}, repo.created.Environments)
	assert.True(t, repo.created.RouteUnowned)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, []any{"payments"}, resp["owner_teams"])
	assert.Equal(t, true, resp["route_unowned"])

	body, _ = json.Marshal(map[string]any{
		"type": "webhook", "name": "x", "webhook_url": "https://example.com/h", "environments": []string{"production"},
	})
	rec = httptest.NewRecorder()
	h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/alerts/channels", bytes.NewReader(body)))
	require.Equal(t, http.StatusBadRequest, rec.Code, "an environment no finding carries would mute the channel")
}

func TestToResponse_ScopeNeverNull(t *testing.T) {
	b, err := json.Marshal(toResponse(Channel{ID: "c"}))
	require.NoError(t, err)
	assert.Contains(t, string(b), `"owner_teams":[]`)
	assert.Contains(t, string(b), `"environments":[]`)
	assert.Contains(t, string(b), `"route_unowned":false`)
}

// captureRepo echoes the created channel back, as the real repo's RETURNING does.
type captureRepo struct {
	fakeRepo
	created Channel
}

func (c *captureRepo) Create(_ context.Context, ch Channel) (Channel, error) {
	c.created = ch
	ch.ID = "new"
	return ch, nil
}

// A notification addressed to specific channels reaches only those, and each
// still applies its own rules (min_score is not bypassed by being chosen).
func TestChannelAccepts_ChannelIDs(t *testing.T) {
	n := Notification{EventType: EventQueryMatch, Severity: SeverityHigh, Score: 70, ChannelIDs: []string{"chosen"}}
	assert.True(t, Channel{ID: "chosen", Enabled: true}.accepts(n))
	assert.False(t, Channel{ID: "other", Enabled: true}.accepts(n))
	assert.False(t, Channel{ID: "chosen", Enabled: true, MinScore: 80}.accepts(n))
	n.ChannelIDs = nil
	assert.True(t, Channel{ID: "other", Enabled: true}.accepts(n), "no selection = normal routing")
}
