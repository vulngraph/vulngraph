package jobs

import (
	"context"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/notify"
)

// AlertDispatcher routes outbound notifications to configured channels.
// *notify.Service satisfies it. Nil disables alerting at the call site.
type AlertDispatcher interface {
	Dispatch(ctx context.Context, n notify.Notification)
}

// newFindingNotification builds the alert for a finding whose urgency just
// transitioned (enrich_alert.go) from the enrich result: score.Value (0–100) is
// what a channel's min_score gates on, and score.Owner/Environment — the routing
// context enrich just persisted — are what owner/environment-scoped channels
// match (ADR 089). escalated marks a finding that alerted before at a lower
// urgency.
func newFindingNotification(f finding.Finding, score enrich.Score, escalated bool) notify.Notification {
	sev := notify.SeverityInfo
	switch f.Severity {
	case finding.SeverityCritical:
		sev = notify.SeverityCritical
	case finding.SeverityHigh:
		sev = notify.SeverityHigh
	case finding.SeverityMedium:
		sev = notify.SeverityMedium
	case finding.SeverityLow:
		sev = notify.SeverityLow
	}

	fields := []notify.Field{
		{Label: "Severity", Value: string(f.Severity), Short: true},
		{Label: "Score", Value: fmt.Sprintf("%d", score.Value), Short: true},
		{Label: "Resource", Value: f.ResourceID, Short: false},
	}
	if f.CheckID != "" {
		fields = append(fields, notify.Field{Label: "Check", Value: f.CheckID, Short: true})
	}
	owner := score.Owner.Team
	if !score.Owner.Resolved() || score.Owner.Unowned() {
		owner = ""
		fields = append(fields, notify.Field{Label: "Owner", Value: "unowned", Short: true})
	} else {
		fields = append(fields, notify.Field{Label: "Owner", Value: owner, Short: true})
	}
	// An environment that could not be classified (a failed seed read leaves
	// it "") routes as unknown: "" matched no env-scoped channel at all, so the
	// alert reached only unscoped ones — or nobody.
	env := score.Environment
	if env == "" {
		env = string(asset.EnvUnknown)
	}
	fields = append(fields, notify.Field{Label: "Environment", Value: env, Short: true})
	urgency := string(score.Band)
	if score.MustFixClass != "" {
		urgency += " / " + score.MustFixClass
	}
	fields = append(fields, notify.Field{Label: "Urgency", Value: urgency, Short: true})
	if f.KnownExploited {
		fields = append(fields, notify.Field{Label: "KEV", Value: "known-exploited :rotating_light:", Short: true})
	}
	verb := "New "
	if escalated {
		verb = "Escalated "
	}

	return notify.Notification{
		EventType: notify.EventFinding,
		Severity:  sev,
		Score:     int(score.Value),
		Title:     verb + string(f.Severity) + " finding: " + f.Title,
		Message:   f.Description,
		Fields:    fields,
		// Unresolved routes as unowned: an alert whose owner could not be
		// established must still reach the default channel, not nobody.
		Owner:       owner,
		Unowned:     owner == "",
		Environment: env,
	}
}
