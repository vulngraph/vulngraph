package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/govern"
	"github.com/vulngraph/vulngraph/internal/app/notify"
	"github.com/vulngraph/vulngraph/internal/app/respond"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// This file is the composition-root glue that connects the platform's existing
// single-notifier hooks (respond.DecisionNotifier, govern.ApprovalNotifier) to
// the multi-channel notify.Service, and fans out so Slack alerts coexist with
// the webhook/email notifiers.

// sevToNotify maps a finding severity onto a notify severity bucket.
func sevToNotify(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return notify.SeverityCritical
	case finding.SeverityHigh:
		return notify.SeverityHigh
	case finding.SeverityMedium:
		return notify.SeverityMedium
	case finding.SeverityLow:
		return notify.SeverityLow
	default:
		return notify.SeverityInfo
	}
}

// ── Decision → Slack ─────────────────────────────────────────────────────────

// slackDecisionNotifier adapts respond.DecisionNotifier onto notify.Service.
type slackDecisionNotifier struct{ notify dispatcher }

// dispatcher is the part of *notify.Service the adapters use.
type dispatcher interface {
	Dispatch(ctx context.Context, n notify.Notification)
}

func (n *slackDecisionNotifier) Notify(ctx context.Context, f finding.Finding, d respond.Decision, _ respond.ContextPack) error {
	if !d.Notifiable() {
		return nil // a plain observe = nothing to do; don't alert
	}
	blast := "unmeasured"
	if d.BlastRadiusKnown {
		blast = fmt.Sprintf("%d assets", d.BlastRadius)
	}
	n.notify.Dispatch(ctx, notify.Notification{
		EventType: notify.EventDecision,
		Severity:  sevToNotify(f.Severity),
		Score:     int(f.Score),
		Title:     fmt.Sprintf("Decision (%s): %s", d.Outcome, f.Title),
		Message:   d.Plan.Summary,
		Fields: []notify.Field{
			{Label: "Action", Value: string(d.Plan.ActionClass), Short: true},
			{Label: "Outcome", Value: string(d.Outcome), Short: true},
			{Label: "Confidence", Value: d.ConfidenceBand, Short: true},
			{Label: "Blast radius", Value: blast, Short: true},
			{Label: "Resource", Value: f.ResourceID, Short: false},
		},
		Owner:       findingOwner(f),
		Unowned:     f.Unowned(),
		Environment: f.Environment,
	})
	return nil
}

// findingOwner is the owner a decision alert routes on: the team enrich stamped
// on the finding, or "" when it is unowned or not yet resolved (both route to
// the unowned default channel — see finding.Finding.Unowned).
func findingOwner(f finding.Finding) string {
	if f.Unowned() {
		return ""
	}
	return f.OwnerTeam
}

// decisionWebhookNotifier builds the DECISION_WEBHOOK_URL notifier, or nil
// when it must not send. Without DECISION_WEBHOOK_SECRET the receiver cannot
// tell a decision from a forgery, and the payload (finding, decision, context)
// is what a forger would imitate to steer whatever acts on it — so an unsigned
// webhook is refused unless DECISION_WEBHOOK_ALLOW_UNSIGNED=true says the
// receiver authenticates some other way.
func decisionWebhookNotifier(ctx context.Context, getenv func(string) string) respond.DecisionNotifier {
	url := getenv("DECISION_WEBHOOK_URL")
	if url == "" {
		return nil
	}
	secret := getenv("DECISION_WEBHOOK_SECRET")
	if secret == "" {
		if getenv("DECISION_WEBHOOK_ALLOW_UNSIGNED") != "true" {
			log.FromContext(ctx).Error().Msg("SECURITY: DECISION_WEBHOOK_URL is set but DECISION_WEBHOOK_SECRET is not — decision " +
				"webhooks are DISABLED. Set DECISION_WEBHOOK_SECRET, or DECISION_WEBHOOK_ALLOW_UNSIGNED=true to send unsigned deliberately")
			return nil
		}
		log.FromContext(ctx).Warn().Msg("SECURITY: DECISION_WEBHOOK_ALLOW_UNSIGNED=true — decision webhooks are sent UNSIGNED " +
			"and the receiver cannot tell them from forgeries")
	}
	return respond.NewHTTPDecisionNotifier(url, secret)
}

// multiDecisionNotifier fans a decision out to several notifiers (webhook +
// Slack). An individual failure never blocks the others; each is logged and
// all are returned joined, so the caller sees that a handoff failed.
type multiDecisionNotifier []respond.DecisionNotifier

func (m multiDecisionNotifier) Notify(ctx context.Context, f finding.Finding, d respond.Decision, pack respond.ContextPack) error {
	var errsOut []error
	for i, n := range m {
		if err := n.Notify(ctx, f, d, pack); err != nil {
			log.FromContext(ctx).Error().Err(err).Int("notifier", i).Str("finding_id", f.ID).
				Msg("decision notifier failed")
			errsOut = append(errsOut, fmt.Errorf("multiDecisionNotifier[%d]: %w", i, err))
		}
	}
	return errors.Join(errsOut...)
}

// ── Approval → Slack ─────────────────────────────────────────────────────────

// slackApprovalNotifier adapts govern.ApprovalNotifier onto notify.Service.
type slackApprovalNotifier struct{ notify *notify.Service }

func (n *slackApprovalNotifier) NotifyApproval(ctx context.Context, p govern.ApprovalPayload) error {
	sev := notify.SeverityInfo
	switch p.WorstBand {
	case "page", "critical":
		sev = notify.SeverityCritical
	case "high":
		sev = notify.SeverityHigh
	}
	n.notify.Dispatch(ctx, notify.Notification{
		EventType: notify.EventApproval,
		Severity:  sev,
		Score:     int(p.WorstScore),
		Title:     "Decision approved: " + p.Title,
		Message:   fmt.Sprintf("%s approved by %s — %s", p.ActionClass, p.ApprovedBy, p.Summary),
		Fields: []notify.Field{
			{Label: "Action", Value: p.ActionClass, Short: true},
			{Label: "Approved by", Value: p.ApprovedBy, Short: true},
			{Label: "Resources", Value: fmt.Sprintf("%d", p.Resources), Short: true},
			{Label: "Findings", Value: fmt.Sprintf("%d", p.Count), Short: true},
		},
	})
	return nil
}

// multiApprovalNotifier fans an approval out to several notifiers. Every one
// runs; failures are returned joined (govern logs them with the cluster key).
type multiApprovalNotifier []govern.ApprovalNotifier

func (m multiApprovalNotifier) NotifyApproval(ctx context.Context, p govern.ApprovalPayload) error {
	var errsOut []error
	for i, n := range m {
		if err := n.NotifyApproval(ctx, p); err != nil {
			errsOut = append(errsOut, fmt.Errorf("multiApprovalNotifier[%d]: %w", i, err))
		}
	}
	return errors.Join(errsOut...)
}
