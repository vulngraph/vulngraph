package github

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// closedAlertLookback bounds how far back each sweep reads closed GHAS alerts.
// GitHub lists every alert ever closed, so reading the whole history every sweep
// would cost pages in proportion to an org's lifetime. The listings are sorted
// by updated_at, newest first, and stop at the first alert last changed before
// the cutoff. A closure no sweep read inside the window (the connector did not
// sync for the whole window, or more than maxPages pages of alerts closed
// inside it) leaves its finding open until an admin resolves it by hand.
const closedAlertLookback = 30 * 24 * time.Hour

// closedCodeScanAlert is a code-scanning alert from a state=closed listing.
type closedCodeScanAlert struct {
	Number          int       `json:"number"`
	State           string    `json:"state"` // "fixed" or "dismissed"
	UpdatedAt       time.Time `json:"updated_at"`
	DismissedReason string    `json:"dismissed_reason"` // "false positive", "won't fix", "used in tests"
	Repository      alertRepo `json:"repository"`
}

func (a closedCodeScanAlert) updated() time.Time { return a.UpdatedAt }

// closedSecretAlert is a secret-scanning alert from a state=resolved listing.
type closedSecretAlert struct {
	Number     int       `json:"number"`
	State      string    `json:"state"` // "resolved"
	Resolution string    `json:"resolution"`
	UpdatedAt  time.Time `json:"updated_at"`
	Repository alertRepo `json:"repository"`
}

func (a closedSecretAlert) updated() time.Time { return a.UpdatedAt }

// codeScanClosure maps a closed code-scanning alert to a closure: fixed means
// GitHub's own analysis no longer reports it (the code was corrected);
// dismissed is a person's triage decision on GitHub. Any other state is not a
// closure GitHub defines, so it closes nothing.
func codeScanClosure(repoFullName string, a closedCodeScanAlert) (collect.FindingClosure, bool) {
	c := collect.FindingClosure{ID: codeScanFindingID(repoFullName, a.Number), Source: codeScanSource}
	switch a.State {
	case "fixed":
		c.Reason, c.Note = finding.ReasonFixed, "fixed on GitHub: code scanning no longer reports it"
	case "dismissed":
		c.Reason, c.Note = finding.ReasonManual, "dismissed on GitHub"+closureDetail(a.DismissedReason)
	default:
		return collect.FindingClosure{}, false
	}
	return c, true
}

// secretClosure maps a resolved secret-scanning alert to a closure. revoked is
// the remediation itself; false_positive, wont_fix and used_in_tests are a
// person's triage decision; pattern_deleted and pattern_edited are GitHub
// closing alerts of a custom pattern that changed — neither a fix nor a person
// judging the alert, as is any resolution GitHub adds later.
func secretClosure(repoFullName string, a closedSecretAlert) (collect.FindingClosure, bool) {
	if a.State != "resolved" {
		return collect.FindingClosure{}, false
	}
	c := collect.FindingClosure{ID: secretFindingID(repoFullName, a.Number), Source: secretSource}
	switch a.Resolution {
	case "revoked":
		c.Reason, c.Note = finding.ReasonFixed, "resolved on GitHub: revoked"
	case "false_positive", "wont_fix", "used_in_tests":
		c.Reason, c.Note = finding.ReasonManual, "resolved on GitHub"+closureDetail(a.Resolution)
	default:
		c.Reason, c.Note = finding.ReasonProviderClosed, "resolved on GitHub"+closureDetail(a.Resolution)
	}
	return c, true
}

// closureDetail renders GitHub's reason for a closure as a note suffix.
func closureDetail(reason string) string {
	if reason == "" {
		return ""
	}
	return ": " + strings.ReplaceAll(reason, "_", " ")
}

// listClosedAlerts reads one closed-alert listing (listURL carries the state
// and sort parameters), stopping at a short page, maxPages, or the first alert
// last changed before cutoff: the listing is sorted newest change first, so
// everything after it is older too. An alert with no updated_at is kept — its
// age is unknown, not old.
func listClosedAlerts[T interface{ updated() time.Time }](ctx context.Context, c *Collector, listURL, token string, cutoff time.Time) ([]T, error) {
	var out []T
	for page := 1; page <= maxPages; page++ {
		url := fmt.Sprintf("%s&per_page=%d&page=%d", listURL, perPage, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return out, fmt.Errorf("listClosedAlerts: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")

		var batch []T
		if err := c.doJSON(req, http.StatusOK, &batch); err != nil {
			return out, fmt.Errorf("listClosedAlerts: page %d: %w", page, err)
		}
		for _, a := range batch {
			if u := a.updated(); !u.IsZero() && u.Before(cutoff) {
				return out, nil
			}
			out = append(out, a)
		}
		if len(batch) < perPage {
			break
		}
	}
	return out, nil
}

// logClosedListErr logs a failed closed-alert listing. It costs only how soon a
// closure is seen — the open listing is unaffected, and the next sweep inside
// the lookback window reads the closure again — so only an unexpected error is
// a warning.
func logClosedListErr(ctx context.Context, err error, scope, kind string) {
	logger := log.FromContext(ctx)
	level := logger.Debug
	if classifyGHASErr(err) == skipOther {
		level = logger.Warn
	}
	level().Err(err).Str("scope", scope).Str("kind", kind).Msg("ghas: closed-alert listing failed (closures delayed)")
}

// orgClosedGHAS reads an org's recently closed alerts for each kind whose open
// listing answered, keeping only alerts on repos the open listing would also
// have read (the same scannable/secretable split).
func (c *Collector) orgClosedGHAS(ctx context.Context, baseURL, token, org string, doCS, doSS bool, scannable, secretable map[string]repo, cutoff time.Time) []collect.FindingClosure {
	var out []collect.FindingClosure
	if doCS {
		url := fmt.Sprintf("%s/orgs/%s/code-scanning/alerts?state=closed&sort=updated&direction=desc", baseURL, org)
		alerts, err := listClosedAlerts[closedCodeScanAlert](ctx, c, url, token, cutoff)
		if err != nil {
			logClosedListErr(ctx, err, org, codeScanSource)
		}
		for _, a := range alerts {
			if _, ok := scannable[a.Repository.FullName]; !ok {
				continue
			}
			if cl, ok := codeScanClosure(a.Repository.FullName, a); ok {
				out = append(out, cl)
			}
		}
	}
	if doSS {
		url := fmt.Sprintf("%s/orgs/%s/secret-scanning/alerts?state=resolved&sort=updated&direction=desc&hide_secret=true", baseURL, org)
		alerts, err := listClosedAlerts[closedSecretAlert](ctx, c, url, token, cutoff)
		if err != nil {
			logClosedListErr(ctx, err, org, secretSource)
		}
		for _, a := range alerts {
			if _, ok := secretable[a.Repository.FullName]; !ok {
				continue
			}
			if cl, ok := secretClosure(a.Repository.FullName, a); ok {
				out = append(out, cl)
			}
		}
	}
	return out
}

// repoClosedCodeScanning reads one repo's recently closed code-scanning alerts
// (the per-repo fallback path). The per-repo listing carries no repository
// object, so r names the repo.
func (c *Collector) repoClosedCodeScanning(ctx context.Context, baseURL, token string, r repo, cutoff time.Time) []collect.FindingClosure {
	url := fmt.Sprintf("%s/repos/%s/code-scanning/alerts?state=closed&sort=updated&direction=desc", baseURL, r.FullName)
	alerts, err := listClosedAlerts[closedCodeScanAlert](ctx, c, url, token, cutoff)
	if err != nil {
		logClosedListErr(ctx, err, r.FullName, codeScanSource)
	}
	var out []collect.FindingClosure
	for _, a := range alerts {
		if cl, ok := codeScanClosure(r.FullName, a); ok {
			out = append(out, cl)
		}
	}
	return out
}

// repoClosedSecretScanning is repoClosedCodeScanning for secret scanning.
func (c *Collector) repoClosedSecretScanning(ctx context.Context, baseURL, token string, r repo, cutoff time.Time) []collect.FindingClosure {
	url := fmt.Sprintf("%s/repos/%s/secret-scanning/alerts?state=resolved&sort=updated&direction=desc&hide_secret=true", baseURL, r.FullName)
	alerts, err := listClosedAlerts[closedSecretAlert](ctx, c, url, token, cutoff)
	if err != nil {
		logClosedListErr(ctx, err, r.FullName, secretSource)
	}
	var out []collect.FindingClosure
	for _, a := range alerts {
		if cl, ok := secretClosure(r.FullName, a); ok {
			out = append(out, cl)
		}
	}
	return out
}
