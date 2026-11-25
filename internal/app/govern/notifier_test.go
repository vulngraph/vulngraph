package govern

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/pkg/webhooksig"
)

type captureTransport struct {
	req  *http.Request
	body []byte
}

func (c *captureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.req = r
	c.body, _ = io.ReadAll(r.Body)
	return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
}

func testApprovalNotifier(secret string) (*HTTPApprovalNotifier, *captureTransport) {
	ct := &captureTransport{}
	n := NewHTTPApprovalNotifier("https://hooks.example.com/approved", secret)
	n.client = &http.Client{Transport: ct}
	n.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	return n, ct
}

// A forged approval POST is a forged human approval to whatever the receiver
// automates, so the handoff is signed exactly like the decision webhook.
func TestApprovalWebhook_IsSignedOverTimestampAndBody(t *testing.T) {
	n, ct := testApprovalNotifier("whsec-approval")
	require.NoError(t, n.NotifyApproval(context.Background(), ApprovalPayload{Source: "graph", EventType: "decision_approved",
		ApprovedBy: "alice@example.com", ClusterKey: "c|remediate", ActionClass: "remediate"}))

	ts := ct.req.Header.Get(webhooksig.TimestampHeader)
	require.Equal(t, "1800000000", ts)
	require.Equal(t, webhooksig.Sign("whsec-approval", ts, ct.body), ct.req.Header.Get(webhooksig.SignatureHeader))
	require.NotEqual(t, webhooksig.Sign("whsec-approval", ts, append(ct.body, ' ')), ct.req.Header.Get(webhooksig.SignatureHeader),
		"a modified body does not verify")
}

func TestApprovalWebhook_UnsignedOnlyWithoutASecret(t *testing.T) {
	n, ct := testApprovalNotifier("")
	require.NoError(t, n.NotifyApproval(context.Background(), ApprovalPayload{Source: "graph"}))
	require.Empty(t, ct.req.Header.Get(webhooksig.SignatureHeader))
}
