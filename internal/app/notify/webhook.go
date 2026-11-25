package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/vulngraph/vulngraph/pkg/safenet"
)

const webhookTimeout = 15 * time.Second

// webhookClient POSTs a JSON notification to a user-supplied URL. The URL is
// untrusted (an operator types it in), so it uses the SSRF-blocking safenet
// client — never NewInternal — to stop a webhook target from being pointed at
// the metadata service or an internal address.
type webhookClient struct {
	http *http.Client
}

func newWebhookClient() *webhookClient {
	return &webhookClient{http: safenet.New(webhookTimeout)}
}

// webhookPayload is the JSON body delivered to the endpoint. It is a stable,
// self-describing shape so receivers (a generic endpoint, a Lambda, a bridge to
// Jira/PagerDuty) can route on event_type/severity without parsing prose.
type webhookPayload struct {
	Event     string            `json:"event"`
	Severity  string            `json:"severity,omitempty"`
	Score     int               `json:"score,omitempty"`
	Title     string            `json:"title"`
	Message   string            `json:"message,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
	Link      string            `json:"link,omitempty"`
	Source    string            `json:"source"`
	Timestamp string            `json:"timestamp"`
}

func (c *webhookClient) post(ctx context.Context, ch Channel, n Notification, now time.Time) error {
	fields := make(map[string]string, len(n.Fields))
	for _, f := range n.Fields {
		fields[f.Label] = f.Value
	}
	payload := webhookPayload{
		Event: string(n.EventType), Severity: n.Severity, Score: n.Score,
		Title: n.Title, Message: n.Message, Fields: fields,
		Link: n.LinkURL, Source: "graph", Timestamp: now.UTC().Format(time.RFC3339),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ch.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook request: %w", withoutURL(err))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "graph-notify/1")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("webhook post: %w", withoutURL(err))
	}
	defer func() { _ = resp.Body.Close() }()

	// Accept any 2xx as success (endpoints vary: 200, 202, 204).
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook post: HTTP %d", resp.StatusCode)
	}
	return nil
}

// withoutURL strips the request URL from a transport error. *url.Error prints
// the full URL, and a webhook URL is a secret (it often embeds a token) while
// delivery errors are logged and stored in last_error, which any viewer reads.
func withoutURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}
