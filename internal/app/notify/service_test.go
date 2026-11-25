package notify

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChannelAccepts(t *testing.T) {
	base := Channel{Enabled: true}
	tests := []struct {
		name string
		ch   Channel
		n    Notification
		want bool
	}{
		{
			name: "disabled channel rejects",
			ch:   Channel{Enabled: false},
			n:    Notification{EventType: EventPhishing},
			want: false,
		},
		{
			name: "empty rules match everything",
			ch:   base,
			n:    Notification{EventType: EventFinding, Severity: SeverityLow, Score: 10},
			want: true,
		},
		{
			name: "event type filter matches",
			ch:   Channel{Enabled: true, EventTypes: []EventType{EventPhishing, EventDrift}},
			n:    Notification{EventType: EventPhishing},
			want: true,
		},
		{
			name: "event type filter excludes",
			ch:   Channel{Enabled: true, EventTypes: []EventType{EventPhishing}},
			n:    Notification{EventType: EventFinding},
			want: false,
		},
		{
			name: "severity filter excludes",
			ch:   Channel{Enabled: true, Severities: []string{SeverityCritical}},
			n:    Notification{EventType: EventFinding, Severity: SeverityHigh},
			want: false,
		},
		{
			name: "severity filter matches",
			ch:   Channel{Enabled: true, Severities: []string{SeverityCritical, SeverityHigh}},
			n:    Notification{EventType: EventFinding, Severity: SeverityHigh},
			want: true,
		},
		{
			// Regression guard: an unscored notification used to bypass any
			// explicit severity allow-list (the zero value read as "admit").
			// A channel that opted into a subset of severities must not
			// silently receive everything an un-severity'd producer sends.
			name: "empty severity on notification is excluded by a severity filter",
			ch:   Channel{Enabled: true, Severities: []string{SeverityCritical}},
			n:    Notification{EventType: EventDrift, Severity: ""},
			want: false,
		},
		{
			name: "empty severities on channel still matches an unscored notification",
			ch:   Channel{Enabled: true},
			n:    Notification{EventType: EventDrift, Severity: ""},
			want: true,
		},
		{
			name: "min score gate excludes",
			ch:   Channel{Enabled: true, MinScore: 70},
			n:    Notification{EventType: EventFinding, Score: 50},
			want: false,
		},
		{
			name: "min score gate passes at threshold",
			ch:   Channel{Enabled: true, MinScore: 70},
			n:    Notification{EventType: EventFinding, Score: 70},
			want: true,
		},
		{
			name: "all filters combined match",
			ch:   Channel{Enabled: true, EventTypes: []EventType{EventFinding}, Severities: []string{SeverityCritical}, MinScore: 80},
			n:    Notification{EventType: EventFinding, Severity: SeverityCritical, Score: 90},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.ch.accepts(tt.n))
		})
	}
}

// fakeRepo + fakePoster drive a Dispatch test without Postgres or Slack.
type fakeRepo struct {
	channels  []Channel
	unopened  []Channel // enabled channels whose secret did not open
	delivered []string  // channel IDs marked delivered
	statuses  []string
	errMsgs   []string
	created   []Channel
	updated   []Channel
	sealed    []SealedSecret
	// resealConflict makes ResealSecret report the row as changed mid-pass.
	resealConflict bool
}

func (f *fakeRepo) Create(_ context.Context, c Channel) (Channel, error) {
	f.created = append(f.created, c)
	return c, nil
}

func (f *fakeRepo) Update(_ context.Context, c Channel) (Channel, error) {
	f.updated = append(f.updated, c)
	return c, nil
}

func (f *fakeRepo) Delete(context.Context, string) error                   { return nil }
func (f *fakeRepo) List(context.Context) ([]Channel, error)                { return f.channels, nil }
func (f *fakeRepo) GetWithSecret(context.Context, string) (Channel, error) { return Channel{}, nil }
func (f *fakeRepo) EnabledWithSecret(context.Context) ([]Channel, []Channel, error) {
	return f.channels, f.unopened, nil
}
func (f *fakeRepo) MarkDelivered(_ context.Context, id, status, errMsg string) error {
	f.delivered = append(f.delivered, id)
	f.statuses = append(f.statuses, status)
	f.errMsgs = append(f.errMsgs, errMsg)
	return nil
}

func (f *fakeRepo) SealedSecrets(context.Context) ([]SealedSecret, error) {
	return append([]SealedSecret(nil), f.sealed...), nil
}

func (f *fakeRepo) ResealSecret(_ context.Context, id string, old, sealed []byte) (bool, error) {
	if f.resealConflict {
		return false, nil
	}
	for i := range f.sealed {
		if f.sealed[i].ChannelID == id && bytes.Equal(f.sealed[i].Ciphertext, old) {
			f.sealed[i].Ciphertext = sealed
			return true, nil
		}
	}
	return false, nil
}

type fakePoster struct {
	sent []Channel
	err  error
}

func (p *fakePoster) post(_ context.Context, ch Channel, _ Notification, _ time.Time) error {
	p.sent = append(p.sent, ch)
	return p.err
}

func TestDispatchRoutesToMatchingChannels(t *testing.T) {
	repo := &fakeRepo{channels: []Channel{
		{ID: "a", Type: TypeSlack, Enabled: true, EventTypes: []EventType{EventPhishing}},
		{ID: "b", Type: TypeSlack, Enabled: true, EventTypes: []EventType{EventFinding}},
		{ID: "c", Type: TypeSlack, Enabled: true}, // matches all
	}}
	poster := &fakePoster{}
	svc := &Service{repo: repo, slack: poster, now: time.Now}

	svc.Dispatch(context.Background(), Notification{EventType: EventPhishing, Severity: SeverityHigh})

	// Channels a (phishing) and c (all) match; b (finding-only) does not.
	require.Len(t, poster.sent, 2)
	ids := []string{poster.sent[0].ID, poster.sent[1].ID}
	assert.Contains(t, ids, "a")
	assert.Contains(t, ids, "c")
	assert.NotContains(t, ids, "b")

	// Both matched channels recorded an "ok" delivery.
	assert.Equal(t, []string{"ok", "ok"}, repo.statuses)
}

func TestDispatchRecordsFailure(t *testing.T) {
	repo := &fakeRepo{channels: []Channel{{ID: "a", Type: TypeSlack, Enabled: true}}}
	poster := &fakePoster{err: errors.New("channel_not_found")}
	svc := &Service{repo: repo, slack: poster, now: time.Now}

	// Dispatch never panics or returns even when delivery fails.
	svc.Dispatch(context.Background(), Notification{EventType: EventFinding})

	require.Equal(t, []string{"error"}, repo.statuses)
}

// Deliver counts only successful deliveries to accepting channels, so a caller
// that records "announced" can tell a failed send from a sent one.
func TestDeliverCountsSuccessfulChannels(t *testing.T) {
	repo := &fakeRepo{channels: []Channel{
		{ID: "a", Type: TypeSlack, Enabled: true},
		{ID: "b", Type: TypeSlack, Enabled: true, EventTypes: []EventType{EventPhishing}},
	}}
	ok := &Service{repo: repo, slack: &fakePoster{}, now: time.Now}
	n, err := ok.Deliver(context.Background(), Notification{EventType: EventFinding})
	require.NoError(t, err)
	require.Equal(t, 1, n, "b does not accept the event")

	failing := &Service{repo: repo, slack: &fakePoster{err: errors.New("channel_not_found")}, now: time.Now}
	n, err = failing.Deliver(context.Background(), Notification{EventType: EventFinding})
	require.NoError(t, err)
	require.Zero(t, n)
}

// DeliverCounted separates "routing chose nobody" from "every eligible send
// failed": only the second is worth retrying.
func TestDeliverCounted_EligibleVsDelivered(t *testing.T) {
	repo := &fakeRepo{channels: []Channel{
		{ID: "a", Type: TypeSlack, Enabled: true},
		{ID: "b", Type: TypeSlack, Enabled: true, EventTypes: []EventType{EventPhishing}},
	}}
	tests := []struct {
		name string
		svc  *Service
		n    Notification
		want DeliveryResult
	}{
		{name: "delivered", svc: &Service{repo: repo, slack: &fakePoster{}, now: time.Now},
			n: Notification{EventType: EventFinding}, want: DeliveryResult{Eligible: 1, Delivered: 1}},
		{name: "eligible but send failed", svc: &Service{repo: repo, slack: &fakePoster{err: errors.New("channel_not_found")}, now: time.Now},
			n: Notification{EventType: EventFinding}, want: DeliveryResult{Eligible: 1}},
		{name: "selected channel no longer enabled", svc: &Service{repo: repo, slack: &fakePoster{}, now: time.Now},
			n: Notification{EventType: EventFinding, ChannelIDs: []string{"deleted"}}, want: DeliveryResult{}},
		{name: "no channel configured", svc: &Service{repo: &fakeRepo{}, slack: &fakePoster{}, now: time.Now},
			n: Notification{EventType: EventFinding}, want: DeliveryResult{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.svc.DeliverCounted(context.Background(), tc.n)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestDispatchRoutesByType(t *testing.T) {
	repo := &fakeRepo{channels: []Channel{
		{ID: "slack-1", Type: TypeSlack, Enabled: true},
		{ID: "hook-1", Type: TypeWebhook, Enabled: true},
	}}
	slack := &fakePoster{}
	hook := &fakePoster{}
	svc := &Service{repo: repo, slack: slack, webhook: hook, now: time.Now}

	svc.Dispatch(context.Background(), Notification{EventType: EventFinding, Severity: SeverityHigh})

	require.Len(t, slack.sent, 1)
	require.Equal(t, "slack-1", slack.sent[0].ID)
	require.Len(t, hook.sent, 1)
	require.Equal(t, "hook-1", hook.sent[0].ID)
	assert.Equal(t, []string{"ok", "ok"}, repo.statuses)
}

// An owner no channel is scoped to (an IaC "repo:org/x" owner, a tagged team
// with no channel) reaches the route_unowned default instead of nobody; an
// owner that HAS a channel still goes only there.
func TestDispatch_OwnerWithNoChannelRoutesAsUnowned(t *testing.T) {
	channels := []Channel{
		{ID: "payments", Type: TypeSlack, Enabled: true, OwnerTeams: []string{"payments"}},
		{ID: "default", Type: TypeSlack, Enabled: true, RouteUnowned: true},
	}
	for owner, want := range map[string]string{"repo:org/infra": "default", "payments": "payments"} {
		t.Run(owner, func(t *testing.T) {
			poster := &fakePoster{}
			svc := &Service{repo: &fakeRepo{channels: channels}, slack: poster, now: time.Now}
			svc.Dispatch(context.Background(), Notification{EventType: EventFinding, Severity: SeverityHigh, Owner: owner})
			require.Len(t, poster.sent, 1)
			assert.Equal(t, want, poster.sent[0].ID)
		})
	}
}

// A notification no channel accepts is counted, not silently dropped.
func TestDispatch_ZeroRecipientsIsObserved(t *testing.T) {
	obs := &fakeDeliveryObserver{}
	svc := (&Service{
		repo:  &fakeRepo{channels: []Channel{{ID: "prod", Type: TypeSlack, Enabled: true, Environments: []string{"prod"}}}},
		slack: &fakePoster{}, now: time.Now,
	}).WithMetrics(obs)
	svc.Dispatch(context.Background(), Notification{EventType: EventFinding, Severity: SeverityHigh, Environment: "dev"})
	assert.Equal(t, []string{"//finding/" + StatusNoRecipient}, obs.calls)

	obs.calls = nil
	svc.Dispatch(context.Background(), Notification{EventType: EventFinding, Severity: SeverityHigh, Environment: "prod"})
	assert.Equal(t, []string{"prod/slack/finding/ok"}, obs.calls)
}

func TestEventTypeWired(t *testing.T) {
	// EventDrift and EventConnector are advertised in AllEventTypes but have no
	// Dispatch call site anywhere in the codebase yet — see domain.go's
	// unwiredEventTypes doc comment. This test pins the current set so adding a
	// producer (and forgetting to update the set) fails loudly instead of
	// leaving a stale "unwired" badge in the UI.
	for _, et := range AllEventTypes {
		want := et != EventDrift && et != EventConnector
		assert.Equal(t, want, et.Wired(), "EventType %q", et)
	}
}

func TestToResponseFlagsUnwiredEventTypes(t *testing.T) {
	c := Channel{
		ID:         "c1",
		EventTypes: []EventType{EventFinding, EventDrift, EventConnector},
	}
	resp := toResponse(c)
	assert.ElementsMatch(t, []string{"drift", "connector"}, resp.UnwiredEventTypes)
}

func TestToResponseFlagsUnwiredEventTypesForAllEventsChannel(t *testing.T) {
	// Empty event_types routes every event type, so the channel also expects
	// the two that never fire.
	resp := toResponse(Channel{ID: "c1"})
	assert.Equal(t, []string{"drift", "connector"}, resp.UnwiredEventTypes)
}

func TestToListResponseListsEveryUnwiredEventType(t *testing.T) {
	resp := toListResponse(nil)
	assert.Equal(t, []string{"drift", "connector"}, resp.UnwiredEventTypes)
	assert.NotNil(t, resp.Channels)
}

func TestToResponseOmitsUnwiredEventTypesWhenAllWired(t *testing.T) {
	c := Channel{ID: "c1", EventTypes: []EventType{EventFinding, EventPhishing}}
	resp := toResponse(c)
	assert.Empty(t, resp.UnwiredEventTypes)
}

// fakeDeliveryObserver records every ObserveNotifyDelivery call for assertion.
type fakeDeliveryObserver struct {
	calls []string // "channelID/channelType/eventType/status"
}

func (f *fakeDeliveryObserver) ObserveNotifyDelivery(channelID, channelType, eventType, status string) {
	f.calls = append(f.calls, channelID+"/"+channelType+"/"+eventType+"/"+status)
}

func TestDispatchObservesDeliveryMetrics(t *testing.T) {
	repo := &fakeRepo{channels: []Channel{
		{ID: "ok-chan", Type: TypeSlack, Enabled: true},
		{ID: "bad-chan", Type: TypeWebhook, Enabled: true},
	}}
	slack := &fakePoster{}
	hook := &fakePoster{err: errors.New("boom")}
	metrics := &fakeDeliveryObserver{}
	svc := &Service{repo: repo, slack: slack, webhook: hook, metrics: metrics, now: time.Now}

	svc.Dispatch(context.Background(), Notification{EventType: EventFinding, Severity: SeverityHigh})

	assert.ElementsMatch(t, []string{
		"ok-chan/slack/finding/ok",
		"bad-chan/webhook/finding/error",
	}, metrics.calls)
}

// A channel whose secret did not open is a recipient that failed, not an
// absent one: the alert is counted undelivered (so it is retried), and the
// failure lands on the channel's status and the delivery metric.
func TestDeliverCounted_UnopenedSecretIsAVisibleFailure(t *testing.T) {
	repo := &fakeRepo{
		channels: []Channel{{ID: "ok-chan", Type: TypeSlack, Enabled: true, EventTypes: []EventType{EventPhishing}}},
		unopened: []Channel{
			{ID: "sealed-chan", Type: TypeWebhook, Enabled: true},
			{ID: "other-event", Type: TypeWebhook, Enabled: true, EventTypes: []EventType{EventPhishing}},
		},
	}
	hook := &fakePoster{}
	metrics := &fakeDeliveryObserver{}
	svc := &Service{repo: repo, slack: &fakePoster{}, webhook: hook, metrics: metrics, now: time.Now}

	got, err := svc.DeliverCounted(context.Background(), Notification{EventType: EventFinding, Severity: SeverityHigh})
	require.NoError(t, err)
	assert.Equal(t, DeliveryResult{Eligible: 1}, got, "an unopened channel that accepts the event is eligible and undelivered")
	assert.Empty(t, hook.sent, "nothing is sent without its secret")
	assert.Equal(t, []string{"sealed-chan"}, repo.delivered)
	assert.Equal(t, []string{"error"}, repo.statuses)
	assert.Equal(t, []string{errSecretUnopened}, repo.errMsgs)
	assert.Equal(t, []string{"sealed-chan/webhook/finding/error"}, metrics.calls,
		"not the no_recipient count: a channel wanted this alert")
}

func TestDispatchWithNilMetricsDoesNotPanic(t *testing.T) {
	repo := &fakeRepo{channels: []Channel{{ID: "a", Type: TypeSlack, Enabled: true}}}
	svc := &Service{repo: repo, slack: &fakePoster{}, now: time.Now}
	assert.NotPanics(t, func() {
		svc.Dispatch(context.Background(), Notification{EventType: EventFinding})
	})
}

func TestCreateValidatesByType(t *testing.T) {
	svc := &Service{repo: &fakeRepo{}, now: time.Now}

	// Webhook needs a URL.
	_, err := svc.Create(context.Background(), Channel{Type: TypeWebhook, Name: "h"})
	require.ErrorIs(t, err, ErrMissingConfig)
	// Webhook with URL is accepted.
	_, err = svc.Create(context.Background(), Channel{Type: TypeWebhook, Name: "h", WebhookURL: "https://example.com/hook"})
	require.NoError(t, err)
	// Slack still needs token + channel.
	_, err = svc.Create(context.Background(), Channel{Type: TypeSlack, Name: "s", WebhookURL: "https://x"})
	require.ErrorIs(t, err, ErrMissingConfig)
	// Unknown type rejected.
	_, err = svc.Create(context.Background(), Channel{Type: "discord", Name: "d"})
	require.ErrorIs(t, err, ErrUnsupported)
}

// The no-recipient warning logs once per window and reports how many it held
// back; the metric (not under test here) counts every one.
func TestNoRecipientWarnIsRateLimited(t *testing.T) {
	s := &Service{}
	t0 := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	_, ok := s.noRecipientWarnDue(t0)
	require.True(t, ok, "the first one logs")
	for i := 1; i <= 3; i++ {
		_, ok = s.noRecipientWarnDue(t0.Add(time.Duration(i) * time.Minute))
		require.False(t, ok)
	}
	n, ok := s.noRecipientWarnDue(t0.Add(noRecipientWarnEvery + time.Second))
	require.True(t, ok)
	require.Equal(t, 3, n)
}

func TestHasEnabledChannels(t *testing.T) {
	ok, err := (&Service{repo: &fakeRepo{channels: []Channel{{ID: "off", Enabled: false}}}}).HasEnabledChannels(context.Background())
	require.NoError(t, err)
	require.False(t, ok)
	ok, err = (&Service{repo: &fakeRepo{channels: []Channel{{ID: "off"}, {ID: "on", Enabled: true}}}}).HasEnabledChannels(context.Background())
	require.NoError(t, err)
	require.True(t, ok)
}

// prefixCipher stands in for connector.Cipher with legible ciphertext: "cur:"
// rows are sealed under the current key, "old:" under a retired one, anything
// else cannot be opened. The AAD is written after the prefix and must match
// on open, as the real envelope requires.
type prefixCipher struct{}

func (prefixCipher) EncryptWithAAD(b, aad []byte) ([]byte, error) {
	return append(append(append([]byte("cur:"), aad...), '|'), b...), nil
}

func (prefixCipher) DecryptWithAAD(b, aad []byte) ([]byte, error) {
	for _, p := range []string{"cur:", "old:"} {
		bound := append(append([]byte(p), aad...), '|')
		if bytes.HasPrefix(b, bound) {
			return b[len(bound):], nil
		}
	}
	return nil, errors.New("no configured key opened the ciphertext")
}

func (prefixCipher) IsCurrentEnvelope(b []byte) bool { return bytes.HasPrefix(b, []byte("cur:")) }

func TestRewrapSecrets_ResealsRetiredRowsIdempotently(t *testing.T) {
	repo := &fakeRepo{sealed: []SealedSecret{
		{ChannelID: "a", Ciphertext: []byte(`old:` + string(channelAAD("a")) + `|{"bot_token":"xoxb-1"}`)},
		{ChannelID: "b", Ciphertext: []byte(`cur:` + string(channelAAD("b")) + `|{"webhook_url":"https://h"}`)},
	}}
	svc := &Service{repo: repo, now: time.Now}

	n, err := svc.RewrapSecrets(context.Background(), prefixCipher{})
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, `cur:`+string(channelAAD("a"))+`|{"bot_token":"xoxb-1"}`, string(repo.sealed[0].Ciphertext),
		"plaintext must survive exactly, still bound to its channel")
	assert.Equal(t, `cur:`+string(channelAAD("b"))+`|{"webhook_url":"https://h"}`, string(repo.sealed[1].Ciphertext))

	n, err = svc.RewrapSecrets(context.Background(), prefixCipher{})
	require.NoError(t, err)
	assert.Equal(t, 0, n, "a second run is a no-op")
}

func TestRewrapSecrets_LeavesUnopenableRowUntouched(t *testing.T) {
	garbage := []byte("sealed under a key that is not configured")
	repo := &fakeRepo{sealed: []SealedSecret{{ChannelID: "lost", Ciphertext: garbage}}}
	svc := &Service{repo: repo, now: time.Now}

	_, err := svc.RewrapSecrets(context.Background(), prefixCipher{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lost", "the error must name the row that needs attention")
	assert.Equal(t, garbage, repo.sealed[0].Ciphertext)
}

func TestRewrapSecrets_RowChangedMidPassIsNotCounted(t *testing.T) {
	repo := &fakeRepo{
		sealed:         []SealedSecret{{ChannelID: "a", Ciphertext: []byte("old:" + string(channelAAD("a")) + "|x")}},
		resealConflict: true,
	}
	svc := &Service{repo: repo, now: time.Now}

	n, err := svc.RewrapSecrets(context.Background(), prefixCipher{})
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.Equal(t, "old:"+string(channelAAD("a"))+"|x", string(repo.sealed[0].Ciphertext))
}

// A secret lifted from one channel row and written over another's must not
// open: that swap would route the second channel's alerts to the first one's
// Slack workspace or webhook.
func TestRewrapSecrets_RefusesASecretMovedFromAnotherChannel(t *testing.T) {
	moved := []byte(`old:` + string(channelAAD("attacker")) + `|{"webhook_url":"https://evil"}`)
	repo := &fakeRepo{sealed: []SealedSecret{{ChannelID: "victim", Ciphertext: moved}}}
	svc := &Service{repo: repo, now: time.Now}

	_, err := svc.RewrapSecrets(context.Background(), prefixCipher{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "victim")
	assert.Equal(t, moved, repo.sealed[0].Ciphertext, "an unopenable row is never rewritten")
}
