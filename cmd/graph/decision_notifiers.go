package main

import (
	"context"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/govern"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// decisionNotifiers fans a decision out to every configured channel: the
// decision webhook (DECISION_WEBHOOK_URL) and Slack alerts fire on every
// non-observe decision, and SMTP_HOST adds an approval-request email.
func decisionNotifiers(ctx context.Context, getenv func(string) string, notify dispatcher) (multiDecisionNotifier, error) {
	var notifiers multiDecisionNotifier
	if n := decisionWebhookNotifier(ctx, getenv); n != nil {
		notifiers = append(notifiers, n)
	}
	notifiers = append(notifiers, &slackDecisionNotifier{notify: notify})
	// SMTP_HOST: email an approval request (single-use approve/deny links bound
	// to the decision) whenever a decision is parked for approval. The serve
	// pod verifies the links with the same APPROVAL_TOKEN_SECRET.
	smtpHost := getenv("SMTP_HOST")
	if smtpHost == "" {
		return notifiers, nil
	}
	emailNotifier, err := govern.NewEmailApprovalNotifier(govern.EmailApprovalNotifierConfig{
		Host:    smtpHost,
		Port:    envInt(getenv, "SMTP_PORT", 587),
		From:    getenv("SMTP_FROM"),
		To:      getenv("SMTP_TO"),
		BaseURL: getenv("APPROVAL_BASE_URL"),
		Secret:  getenv("APPROVAL_TOKEN_SECRET"),
		// The links are bearer credentials: without TLS on the SMTP hop
		// anyone on the path can use them first.
		AllowPlaintext: getenv("SMTP_ALLOW_PLAINTEXT") == "true",
	})
	if err != nil {
		return nil, fmt.Errorf("SMTP_HOST is set: %w", err)
	}
	if getenv("SMTP_ALLOW_PLAINTEXT") == "true" {
		log.FromContext(ctx).Warn().Msg("SECURITY: SMTP_ALLOW_PLAINTEXT=true — approval emails go out unencrypted " +
			"when the SMTP server offers no STARTTLS, and their approve/deny links can be read and used on the way")
	}
	return append(notifiers, emailNotifier), nil
}
