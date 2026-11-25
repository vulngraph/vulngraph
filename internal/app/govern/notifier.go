package govern

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/vulngraph/vulngraph/pkg/safenet"
	"github.com/vulngraph/vulngraph/pkg/webhooksig"
)

const approvalWebhookTimeout = 15 * time.Second

// ApprovalNotifier is called when a governor approves a decision cluster.
// Wire it up via Service.WithApprovalNotifier to route approved decisions
// to Jira, Linear, Slack, or any other action system. Nil = disabled.
type ApprovalNotifier interface {
	NotifyApproval(ctx context.Context, payload ApprovalPayload) error
}

// ApprovalPayload is POSTed to the approval webhook. It carries everything
// a downstream system needs to create an actionable ticket or task.
type ApprovalPayload struct {
	Source    string `json:"source"`     // "graph"
	EventType string `json:"event_type"` // "decision_approved"

	// Who and when
	ApprovedBy string `json:"approved_by"`
	ApprovedAt string `json:"approved_at"` // RFC3339
	Note       string `json:"note,omitempty"`

	// What the cluster covers
	ClusterKey  string   `json:"cluster_key"`
	Title       string   `json:"title"`
	CheckID     string   `json:"check_id,omitempty"`
	ActionClass string   `json:"action_class"` // observe|remediate|modify|isolate|destroy
	Summary     string   `json:"summary"`      // agent's one-line plan
	FindingIDs  []string `json:"finding_ids"`
	Resources   int      `json:"resources"` // distinct resources affected
	Count       int      `json:"count"`     // total finding instances

	// Risk context — helps the receiver prioritise
	WorstScore  uint8  `json:"worst_score"`
	WorstBand   string `json:"worst_band,omitempty"`
	BlastRadius int    `json:"blast_radius"`
	// BlastRadiusKnown is false when at least one finding in this cluster had
	// a failed blast-radius walk — BlastRadius is a max across the cluster
	// (see Resolve), so it must never be read as "small" when the true state
	// is "partially unmeasured": a receiver may act on this payload, and the
	// queue card (handler.go) carries the same flag.
	BlastRadiusKnown bool     `json:"blast_radius_known"`
	ConfidenceBand   string   `json:"confidence_band,omitempty"`
	CoVeConcerns     []string `json:"cove_concerns,omitempty"`
	SampleTargets    []string `json:"sample_targets,omitempty"`
}

// HTTPApprovalNotifier POSTs approval payloads to a webhook URL. A receiver
// may open a ticket or run automation on "a person approved this" (one admin
// on a session, or a confirmed email link; the queue refuses API keys), so a
// forged POST is a forged approval: every request is signed with the same
// scheme as the decision webhook (pkg/webhooksig). The post is one approval
// for any action class: none of the executor's rules (a second admin, a
// grant, an intent row) stand behind it, and a receiver that changes
// infrastructure must apply its own (docs/security-hardening.md#approval-webhook).
type HTTPApprovalNotifier struct {
	url    string
	secret string // "" sends unsigned — only when explicitly allowed (cmd/graph)
	client *http.Client
	now    func() time.Time
}

// NewHTTPApprovalNotifier builds a notifier that POSTs to url, signing each
// request with secret (X-Graph-Timestamp, X-Graph-Signature).
func NewHTTPApprovalNotifier(url, secret string) *HTTPApprovalNotifier {
	return &HTTPApprovalNotifier{url: url, secret: secret, client: safenet.New(approvalWebhookTimeout), now: time.Now}
}

func (n *HTTPApprovalNotifier) NotifyApproval(ctx context.Context, payload ApprovalPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("NotifyApproval: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("NotifyApproval: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if n.secret != "" {
		webhooksig.SetHeaders(req.Header, n.secret, n.now(), body)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("NotifyApproval: POST: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("NotifyApproval: unexpected status %d", resp.StatusCode)
	}
	return nil
}
