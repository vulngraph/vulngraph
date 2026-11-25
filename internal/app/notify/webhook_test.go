package notify

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/pkg/safenet"
)

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

// A failed delivery must not leak the secret webhook URL into last_error,
// which GET /api/alerts/channels returns to every viewer.
func TestDeliver_FailedWebhookDoesNotStoreURL(t *testing.T) {
	const secretURL = "https://hooks.example.com/services/T000/B000/s3cr3t-token"
	client := safenet.New(time.Second)
	client.Transport = failingTransport{}
	repo := &fakeRepo{channels: []Channel{{ID: "w", Type: TypeWebhook, Enabled: true, WebhookURL: secretURL}}}
	svc := &Service{repo: repo, webhook: &webhookClient{http: client}, now: time.Now}

	delivered, err := svc.Deliver(context.Background(), Notification{EventType: EventFinding, Title: "t"})
	require.NoError(t, err)
	require.Zero(t, delivered)
	require.Equal(t, []string{"error"}, repo.statuses)
	require.Contains(t, repo.errMsgs[0], "connection refused")
	require.NotContains(t, repo.errMsgs[0], "s3cr3t-token")
	require.NotContains(t, repo.errMsgs[0], "hooks.example.com")
}

// A stored URL that no longer parses fails at request build, and that
// *url.Error carries the whole URL; it must be scrubbed the same way.
func TestPost_UnparseableURLDoesNotLeakIt(t *testing.T) {
	const secretURL = "https://hooks.example.com/services/s3cr3t-token\n"
	c := &webhookClient{http: safenet.New(time.Second)}
	err := c.post(context.Background(), Channel{WebhookURL: secretURL}, Notification{EventType: EventFinding}, time.Now())
	require.Error(t, err)
	require.NotContains(t, err.Error(), "s3cr3t-token")
	require.NotContains(t, err.Error(), "hooks.example.com")
}

func TestWithoutURL(t *testing.T) {
	inner := errors.New("dial tcp: blocked")
	err := withoutURL(&url.Error{Op: "Post", URL: "https://x.example/secret", Err: inner})
	require.Equal(t, "Post: dial tcp: blocked", err.Error())
	require.ErrorIs(t, err, inner)

	plain := errors.New("plain")
	require.Equal(t, plain, withoutURL(plain))
}

func TestCreateValidatesWebhookURL(t *testing.T) {
	for _, tc := range []struct {
		url     string
		wantErr bool
	}{
		{"https://hooks.example.com/x", false},
		{"http://hooks.example.com:80/x", false},
		{"ftp://hooks.example.com/x", true},
		{"https://hooks.example.com:8443/x", true},
		{"https:///no-host", true},
		{"://bad", true},
	} {
		t.Run(tc.url, func(t *testing.T) {
			repo := &fakeRepo{}
			svc := &Service{repo: repo, now: time.Now}
			_, err := svc.Create(context.Background(), Channel{Type: TypeWebhook, WebhookURL: tc.url})
			if tc.wantErr {
				require.ErrorIs(t, err, ErrInvalidURL)
				require.Empty(t, repo.created, "an invalid URL must not be stored")
				return
			}
			require.NoError(t, err)
			require.Len(t, repo.created, 1)
		})
	}
}

func TestUpdateValidatesWebhookURL(t *testing.T) {
	repo := &fakeRepo{}
	svc := &Service{repo: repo, now: time.Now}

	_, err := svc.Update(context.Background(), Channel{ID: "w", WebhookURL: "https://hooks.example.com:22/x"})
	require.ErrorIs(t, err, ErrInvalidURL)
	require.Empty(t, repo.updated)

	_, err = svc.Update(context.Background(), Channel{ID: "w"})
	require.NoError(t, err, "an empty URL keeps the stored secret")
	_, err = svc.Update(context.Background(), Channel{ID: "w", WebhookURL: "https://hooks.example.com/x"})
	require.NoError(t, err)
	require.Len(t, repo.updated, 2)
}
