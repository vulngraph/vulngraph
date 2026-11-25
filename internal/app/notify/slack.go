package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/vulngraph/vulngraph/pkg/safenet"
)

const (
	slackPostURL = "https://slack.com/api/chat.postMessage"
	slackTimeout = 15 * time.Second
)

// slackClient posts messages to Slack via chat.postMessage using a bot token.
type slackClient struct {
	http *http.Client
}

func newSlackClient() *slackClient {
	return &slackClient{http: safenet.NewInternalEgress(slackTimeout)}
}

// slackMessage is the chat.postMessage request body.
type slackMessage struct {
	Channel     string            `json:"channel"`
	Text        string            `json:"text"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

type slackAttachment struct {
	Color  string       `json:"color,omitempty"`
	Title  string       `json:"title,omitempty"`
	Text   string       `json:"text,omitempty"`
	Fields []slackField `json:"fields,omitempty"`
	Footer string       `json:"footer,omitempty"`
	TS     int64        `json:"ts,omitempty"`
}

type slackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// slackResponse is the chat.postMessage reply. ok=false carries an error code.
type slackResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

// post sends a notification to a channel. now is injected so callers control
// the footer timestamp (and tests stay deterministic).
func (c *slackClient) post(ctx context.Context, ch Channel, n Notification, now time.Time) error {
	att := slackAttachment{
		Color:  severityColor(n.Severity),
		Title:  n.Title,
		Text:   n.Message,
		Footer: "Vulngraph · " + string(n.EventType),
		TS:     now.Unix(),
	}
	for _, f := range n.Fields {
		att.Fields = append(att.Fields, slackField{Title: f.Label, Value: f.Value, Short: f.Short})
	}
	if n.LinkURL != "" {
		label := n.LinkText
		if label == "" {
			label = "View in Vulngraph"
		}
		att.Fields = append(att.Fields, slackField{
			Title: "Link",
			Value: fmt.Sprintf("<%s|%s>", n.LinkURL, label),
			Short: false,
		})
	}

	msg := slackMessage{
		Channel:     ch.SlackChannel,
		Text:        severityEmoji(n.Severity) + " " + n.Title,
		Attachments: []slackAttachment{att},
	}

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("slack marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, slackPostURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+ch.BotToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("slack post: %w", withoutURL(err))
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack post: HTTP %d", resp.StatusCode)
	}
	var sr slackResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return fmt.Errorf("slack decode: %w", err)
	}
	if !sr.OK {
		// Common: invalid_auth, channel_not_found, not_in_channel.
		return fmt.Errorf("slack error: %s", sr.Error)
	}
	return nil
}

// severityColor maps a severity to a Slack attachment colour bar.
func severityColor(sev string) string {
	switch sev {
	case SeverityCritical:
		return "#dc2626" // red
	case SeverityHigh:
		return "#ea580c" // orange
	case SeverityMedium:
		return "#d97706" // amber
	case SeverityLow:
		return "#65a30d" // green
	default:
		return "#0d9488" // teal (info / unscored)
	}
}

// severityEmoji prefixes the notification text for at-a-glance triage.
func severityEmoji(sev string) string {
	switch sev {
	case SeverityCritical, SeverityHigh:
		return ":rotating_light:"
	case SeverityMedium:
		return ":warning:"
	default:
		return ":information_source:"
	}
}
