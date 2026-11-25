package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type captureTransport struct{ body []byte }

func (c *captureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	c.body = b
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
		Header:     http.Header{},
	}, nil
}

// The Slack attachment names the product: the footer and the default link
// label say Vulngraph.
func TestSlackPost_NamesVulngraph(t *testing.T) {
	tr := &captureTransport{}
	c := &slackClient{http: &http.Client{Transport: tr}}
	n := Notification{EventType: EventTest, Title: "t", LinkURL: "https://vg.example/findings/1"}

	require.NoError(t, c.post(context.Background(), Channel{SlackChannel: "#sec", BotToken: "x"}, n, time.Unix(0, 0)))

	var msg slackMessage
	require.NoError(t, json.Unmarshal(tr.body, &msg))
	require.Len(t, msg.Attachments, 1)
	att := msg.Attachments[0]
	require.Equal(t, "Vulngraph · "+string(EventTest), att.Footer)
	require.Len(t, att.Fields, 1)
	require.Equal(t, "<https://vg.example/findings/1|View in Vulngraph>", att.Fields[0].Value)
}
