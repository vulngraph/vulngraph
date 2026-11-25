package respond

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/pkg/promptfence"
	"github.com/vulngraph/vulngraph/pkg/safenet"
	"github.com/vulngraph/vulngraph/pkg/webhooksig"
)

const webhookTimeout = 15 * time.Second

// DecisionNotifier sends decisions to an external remediation service. Nil =
// disabled. Implement it to add Slack, PagerDuty, or any other notification
// target alongside the canonical remediation-service handoff.
type DecisionNotifier interface {
	Notify(ctx context.Context, f finding.Finding, d Decision, pack ContextPack) error
}

// Webhook signature headers. The scheme (pkg/webhooksig) is shared with the
// approval webhook; here it is keyed by DECISION_WEBHOOK_SECRET.
const (
	SignatureHeader = webhooksig.SignatureHeader
	TimestampHeader = webhooksig.TimestampHeader
)

// GraphDecisionPayload is the wire format POSTed to the decision webhook.
// Carries the pre-reasoned plan so the receiver skips triage entirely. It is a
// proposal awaiting a human, never an authorisation to act: Vulngraph executes no
// state-changing action without a human's yes (ADR 087), and a receiver must
// not treat this payload as one.
//
// Free-text fields that come from scanners, resource metadata or the LLM
// (title, description, summary, rationale, CoVe concerns, owner,
// environment, deployed_from) are wrapped in promptfence markers: a receiver
// that feeds them to its own LLM must treat them as data. Identifiers are
// left bare so receivers can route on them.
type GraphDecisionPayload struct {
	Source    string          `json:"source"`     // always "graph"
	EventType string          `json:"event_type"` // always "graph_decision"
	Action    string          `json:"action"`     // "parked_for_approval" | "escalated"
	Finding   FindingPayload  `json:"finding"`
	Decision  DecisionPayload `json:"decision"`
	Context   ContextPayload  `json:"context"`
}

// FindingPayload is the minimal finding identity a receiver needs.
type FindingPayload struct {
	ID           string `json:"id"`
	Source       string `json:"source"`
	Type         string `json:"type"`
	Severity     string `json:"severity"`
	Title        string `json:"title"`
	Description  string `json:"description,omitempty"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Region       string `json:"region,omitempty"`
	CheckID      string `json:"check_id,omitempty"`
	Score        uint8  `json:"score"`
	ScoreBand    string `json:"score_band"`
}

// DecisionPayload is the pre-reasoned action plan. The executor uses
// action_class to route without re-reasoning, and rationale as agent context.
type DecisionPayload struct {
	ActionClass string `json:"action_class"` // observe|remediate|modify|isolate|destroy
	Summary     string `json:"summary"`      // one-line human description
	Rationale   string `json:"rationale"`    // full graph-grounded reasoning
	BlastRadius int    `json:"blast_radius"` // reachable assets; meaningful only when blast_radius_known
	// BlastRadiusKnown is false when the blast walk failed: blast_radius is
	// then an unmeasured 0, not "touches nothing".
	BlastRadiusKnown bool     `json:"blast_radius_known"`
	ConfidenceBand   string   `json:"confidence_band"`         // low|medium|high
	CoVeConcerns     []string `json:"cove_concerns,omitempty"` // structural guardrail flags
	DecidedAt        string   `json:"decided_at"`              // RFC3339
}

// ContextPayload is the key graph signals the executor may use to prioritise
// or route the action (e.g. high blast + internet-facing = urgent).
type ContextPayload struct {
	InternetFacing bool   `json:"internet_facing"`
	Privileged     bool   `json:"privileged"`
	Owner          string `json:"owner,omitempty"`
	Environment    string `json:"environment,omitempty"`
	DeployedFrom   string `json:"deployed_from,omitempty"`
}

// HTTPDecisionNotifier POSTs decisions to a webhook URL. Observe-class decisions
// are silently dropped — "nothing to do" is not worth sending.
type HTTPDecisionNotifier struct {
	url    string
	secret string // signs each POST; "" sends unsigned (the caller warns)
	client *http.Client
	now    func() time.Time
}

// NewHTTPDecisionNotifier builds a notifier that POSTs to url using the
// shared safe HTTP client with a 15-second timeout. A non-empty secret signs
// every request (SignatureHeader, TimestampHeader).
func NewHTTPDecisionNotifier(url, secret string) *HTTPDecisionNotifier {
	return &HTTPDecisionNotifier{url: url, secret: secret, client: safenet.New(webhookTimeout), now: time.Now}
}

// SignWebhook returns the SignatureHeader value for body sent at timestamp.
// Exported so receivers written in Go (and tests) verify with the same code.
func SignWebhook(secret, timestamp string, body []byte) string {
	return webhooksig.Sign(secret, timestamp, body)
}

func fenceAll(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = promptfence.Fence(s)
	}
	return out
}

// fenceOpt fences s, leaving an empty value empty (omitempty fields stay omitted).
func fenceOpt(s string) string {
	if s == "" {
		return ""
	}
	return promptfence.Fence(s)
}

// Notify serialises and POSTs the decision payload. Best-effort: callers log
// errors but must not fail a decision because the webhook is down.
func (n *HTTPDecisionNotifier) Notify(ctx context.Context, f finding.Finding, d Decision, pack ContextPack) error {
	if !d.Notifiable() {
		return nil // a plain observe = no action needed; don't generate noise
	}

	payload := GraphDecisionPayload{
		Source:    "graph",
		EventType: "graph_decision",
		Action:    string(d.Outcome),
		Finding: FindingPayload{
			ID:           f.ID,
			Source:       f.Source,
			Type:         f.Type,
			Severity:     string(f.Severity),
			Title:        promptfence.Fence(f.Title),
			Description:  fenceOpt(f.Description),
			ResourceType: f.ResourceType,
			ResourceID:   f.ResourceID,
			Region:       f.Region,
			CheckID:      f.CheckID,
			Score:        f.Score,
			ScoreBand:    f.ScoreBand,
		},
		Decision: DecisionPayload{
			ActionClass:      string(d.Plan.ActionClass),
			Summary:          promptfence.Fence(d.Plan.Summary),
			Rationale:        promptfence.Fence(d.Plan.Rationale),
			BlastRadius:      d.BlastRadius,
			BlastRadiusKnown: d.BlastRadiusKnown,
			ConfidenceBand:   d.ConfidenceBand,
			CoVeConcerns:     fenceAll(d.CoVeConcerns),
			DecidedAt:        d.DecidedAt.UTC().Format(time.RFC3339),
		},
		Context: ContextPayload{
			InternetFacing: pack.Exposure.InternetFacing,
			Privileged:     pack.Exposure.Privileged,
			Owner:          fenceOpt(pack.Provenance.Owner),
			Environment:    fenceOpt(pack.Provenance.Environment),
			DeployedFrom:   fenceOpt(pack.Provenance.SourceRepo),
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("Notify: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("Notify: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if n.secret != "" {
		webhooksig.SetHeaders(req.Header, n.secret, n.now(), body)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("Notify: POST: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Notify: unexpected status %d", resp.StatusCode)
	}
	return nil
}
