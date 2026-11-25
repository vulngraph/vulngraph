package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/pkg/log"
)

const ghasConcurrency = 8 // max parallel GHAS API calls (same as SBOM)

// errOrgAlertsUnsupported marks an org-level alert endpoint the installation
// cannot read: a 404 (older GHES doesn't serve it) or a non-rate-limited 403
// (the App holds repo-scoped secret_scanning_alerts:read but was never granted
// the org-level scope). Both mean "ask each repo instead", NOT "this org has
// no GHAS" — misclassifying either as unlicensed would write off every repo
// in the org from one call. A RATE-LIMITED 403 is deliberately excluded:
// falling back there would fan thousands of repo calls into an already-empty
// budget.
var errOrgAlertsUnsupported = errors.New("github: org-level alert endpoint not available")

// orgEndpointUnavailable reports whether a page-1 error means the org-level
// endpoint is unreadable for this token and the per-repo fallback should run.
func orgEndpointUnavailable(err error) bool {
	var ae *apiError
	if !errors.As(err, &ae) || ae.rateLimited {
		return false
	}
	return ae.status == http.StatusNotFound || ae.status == http.StatusForbidden
}

// ghasSkip classifies why a repo (or a whole org's repos) yielded no alerts.
type ghasSkip int

const (
	skipNone       ghasSkip = iota
	skipRateLimit           // budget exhausted, or the reset lies past the job deadline
	skipUnlicensed          // 404 (GHAS not enabled) or a genuine permission 403
	skipOther               // unexpected error — logged individually at debug
)

// classifyGHASErr buckets an alert-fetch error. A 403 arriving with the
// rate-limit budget at zero is starvation, NOT a licensing signal —
// misreading it hides exhausted sweeps behind "GHAS not licensed".
func classifyGHASErr(err error) ghasSkip {
	if err == nil {
		return skipNone
	}
	if errors.Is(err, errRateLimitWait) || errors.Is(err, context.DeadlineExceeded) {
		return skipRateLimit
	}
	var ae *apiError
	if errors.As(err, &ae) {
		if ae.rateLimited {
			return skipRateLimit
		}
		if ae.status == http.StatusNotFound || ae.status == http.StatusForbidden {
			return skipUnlicensed
		}
	}
	return skipOther
}

// isGHASSkippable reports whether an API error means GHAS is not enabled or
// the token lacks the required permission — expected on repos without GHAS.
// A rate-limited 403 is deliberately NOT skippable.
func isGHASSkippable(err error) bool {
	return classifyGHASErr(err) == skipUnlicensed
}

// worseSkip merges two skip reasons: rate-limit starvation dominates (it is
// actionable), then unlicensed, then other.
func worseSkip(a, b ghasSkip) ghasSkip {
	if a == skipRateLimit || b == skipRateLimit {
		return skipRateLimit
	}
	if a == skipUnlicensed || b == skipUnlicensed {
		return skipUnlicensed
	}
	if a == skipOther || b == skipOther {
		return skipOther
	}
	return skipNone
}

// ghasStats counts repos skipped during a sweep, by reason, so one summary
// log line can replace what would otherwise be per-repo debug spam.
type ghasStats struct {
	mu          sync.Mutex
	rateLimited int
	unlicensed  int
}

func (s *ghasStats) add(skip ghasSkip, repos int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch skip {
	case skipRateLimit:
		s.rateLimited += repos
	case skipUnlicensed:
		s.unlicensed += repos
	}
}

// collectGHAS fetches open code-scanning and secret-scanning alerts for the
// installation as findings, and the alerts GitHub recently closed as closures
// (ghas_closed.go). It prefers the org-level list endpoints — open and recently
// closed, per kind, so 4 paginated calls per org instead of 4 per repo, a few
// dozen calls where the per-repo walk cost thousands against a 5,000/hr
// budget — and falls back to per-repo listing where
// an org endpoint is unreadable for this token (see errOrgAlertsUnsupported).
// Best-effort throughout: skipped repos are counted and summarised in a single
// warn line.
func (c *Collector) collectGHAS(ctx context.Context, baseURL, token string, repos []repo) ([]finding.Finding, []collect.FindingClosure) {
	logger := log.FromContext(ctx)
	// Two repo sets, because archival means different things to the two alert
	// kinds. Archiving freezes commits, so a code-scanning alert on an archived
	// repo describes code that can no longer ship — but it does NOT revoke a
	// leaked credential, which stays valid until someone rotates it. Filtering
	// archived repos out of both sets would drop open secret alerts for
	// credentials that are still valid.
	scannable := make(map[string]repo, len(repos))  // non-archived: code scanning
	secretable := make(map[string]repo, len(repos)) // all repos: secret scanning
	orgRepos := make(map[string][]repo)
	var orgs []string
	for _, r := range repos {
		secretable[r.FullName] = r
		if !r.Archived {
			scannable[r.FullName] = r
		}
		org, _, _ := strings.Cut(r.FullName, "/")
		if _, seen := orgRepos[org]; !seen {
			orgs = append(orgs, org)
		}
		orgRepos[org] = append(orgRepos[org], r)
	}

	var st ghasStats
	var all []finding.Finding
	var closed []collect.FindingClosure
	cutoff := time.Now().Add(-closedAlertLookback)
	for _, org := range orgs {
		cs, csErr := c.orgCodeScanningFindings(ctx, baseURL, token, org, scannable)
		ss, ssErr := c.orgSecretScanningFindings(ctx, baseURL, token, org, secretable)
		all = append(all, cs...)
		all = append(all, ss...)
		// Closed alerts are read only where the open listing answered: an org
		// endpoint that just failed or rate-limited would fail the same way.
		closed = append(closed, c.orgClosedGHAS(ctx, baseURL, token, org, csErr == nil, ssErr == nil, scannable, secretable, cutoff)...)

		skip := skipNone
		for _, err := range []error{csErr, ssErr} {
			if err == nil || errors.Is(err, errOrgAlertsUnsupported) {
				continue
			}
			s := classifyGHASErr(err)
			if s == skipOther {
				logger.Warn().Err(err).Str("org", org).Msg("ghas: org alert fetch failed")
				continue
			}
			skip = worseSkip(skip, s)
		}
		if skip != skipNone {
			st.add(skip, len(orgRepos[org]))
		}

		fallbackCS := errors.Is(csErr, errOrgAlertsUnsupported)
		fallbackSS := errors.Is(ssErr, errOrgAlertsUnsupported)
		if fallbackCS || fallbackSS {
			fs, cl := c.collectGHASPerRepo(ctx, baseURL, token, orgRepos[org], fallbackCS, fallbackSS, cutoff, &st)
			all = append(all, fs...)
			closed = append(closed, cl...)
		}
	}

	if st.rateLimited > 0 || st.unlicensed > 0 {
		logger.Warn().
			Int("repos_skipped_rate_limit", st.rateLimited).
			Int("repos_ghas_unlicensed", st.unlicensed).
			Msg("ghas: repos skipped this sweep")
	}
	return all, closed
}

// collectGHASPerRepo is the fallback path for orgs whose GHES doesn't serve
// the org-level alert endpoints: fan out per repo with bounded concurrency,
// hitting only the endpoint(s) that needed the fallback. A repo's closed alerts
// are read only for a kind whose open listing answered for that repo: a repo
// without GHAS would 404 the closed listing too.
func (c *Collector) collectGHASPerRepo(ctx context.Context, baseURL, token string, repos []repo, doCS, doSS bool, cutoff time.Time, st *ghasStats) ([]finding.Finding, []collect.FindingClosure) {
	sem := make(chan struct{}, ghasConcurrency)
	var mu sync.Mutex
	var all []finding.Finding
	var closed []collect.FindingClosure
	var wg sync.WaitGroup

	for _, r := range repos {
		r := r
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A decode/nil panic in one repo's alert fetch must not crash the
			// worker pod mid-sync — degrade that repo, keep the rest.
			defer func() {
				if rec := recover(); rec != nil {
					log.FromContext(ctx).Error().Interface("panic", rec).Str("repo", r.FullName).Msg("ghas alert fetch panicked; skipped")
				}
			}()
			sem <- struct{}{}
			defer func() { <-sem }()

			var fs []finding.Finding
			var cl []collect.FindingClosure
			skip := skipNone
			// Archived repos are queried for secrets but not for code scanning —
			// same asymmetry as the org-level path (a leaked credential outlives
			// archival; unshippable code does not).
			if doCS && !r.Archived {
				cs, s := c.repoCodeScanningAlerts(ctx, baseURL, token, r)
				fs = append(fs, cs...)
				skip = worseSkip(skip, s)
				if s == skipNone {
					cl = append(cl, c.repoClosedCodeScanning(ctx, baseURL, token, r, cutoff)...)
				}
			}
			if doSS {
				ss, s := c.repoSecretScanningAlerts(ctx, baseURL, token, r)
				fs = append(fs, ss...)
				skip = worseSkip(skip, s)
				if s == skipNone {
					cl = append(cl, c.repoClosedSecretScanning(ctx, baseURL, token, r, cutoff)...)
				}
			}
			if skip == skipRateLimit || skip == skipUnlicensed {
				st.add(skip, 1)
			}
			if len(fs) > 0 || len(cl) > 0 {
				mu.Lock()
				all = append(all, fs...)
				closed = append(closed, cl...)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return all, closed
}

// alertRepo is the repository object embedded in org-level alerts; full_name
// keys back into the installation's repo set (which also filters archived
// repos and repos outside the installation).
type alertRepo struct {
	FullName string `json:"full_name"`
}

// ── Code scanning ─────────────────────────────────────────────────────────────

type codeScanAlert struct {
	Number    int       `json:"number"`
	CreatedAt time.Time `json:"created_at"`
	State     string    `json:"state"`
	Rule      struct {
		ID                    string `json:"id"`
		Name                  string `json:"name"`
		Description           string `json:"description"`
		Severity              string `json:"severity"`                // "note","warning","error"
		SecuritySeverityLevel string `json:"security_severity_level"` // "critical","high","medium","low"
	} `json:"rule"`
	Tool struct {
		Name string `json:"name"`
	} `json:"tool"`
	MostRecentInstance struct {
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Location struct {
			Path string `json:"path"`
		} `json:"location"`
	} `json:"most_recent_instance"`
}

type orgCodeScanAlert struct {
	codeScanAlert
	Repository alertRepo `json:"repository"`
}

// codeScanSource and secretSource are the finding sources GHAS alerts are
// recorded under.
const (
	codeScanSource = "ghas_code_scanning"
	secretSource   = "ghas_secrets"
)

// codeScanFindingID and secretFindingID derive a finding's ID from repo full
// name + alert number, so org-level and per-repo collection produce identical
// findings that upsert in place, and a closed alert names the finding its open
// alert was recorded under.
func codeScanFindingID(repoFullName string, number int) string {
	return fmt.Sprintf("%s:%s:%d", codeScanSource, repoFullName, number)
}

func secretFindingID(repoFullName string, number int) string {
	return fmt.Sprintf("%s:%s:%d", secretSource, repoFullName, number)
}

// codeScanFinding maps one code-scanning alert to a finding.
func codeScanFinding(r repo, a codeScanAlert, now time.Time) finding.Finding {
	return finding.Finding{
		ID:           codeScanFindingID(r.FullName, a.Number),
		Source:       codeScanSource,
		Type:         "code_vulnerability",
		Severity:     codeScanSeverity(a.Rule.SecuritySeverityLevel, a.Rule.Severity),
		Title:        a.Rule.Name,
		Description:  a.Rule.Description + descSuffix(a.MostRecentInstance.Message.Text, a.MostRecentInstance.Location.Path),
		ResourceType: "github_repo",
		ResourceID:   r.FullName,
		ResourceName: r.Name,
		Region:       "global",
		CheckID:      a.Rule.ID,
		DetectedAt:   coalesceTime(a.CreatedAt, now),
	}
}

func (c *Collector) orgCodeScanningFindings(ctx context.Context, baseURL, token, org string, active map[string]repo) ([]finding.Finding, error) {
	var out []finding.Finding
	now := time.Now()
	for page := 1; page <= maxPages; page++ {
		url := fmt.Sprintf("%s/orgs/%s/code-scanning/alerts?state=open&per_page=%d&page=%d", baseURL, org, perPage, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return out, fmt.Errorf("orgCodeScanningFindings: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")

		var batch []orgCodeScanAlert
		if err := c.doJSON(req, http.StatusOK, &batch); err != nil {
			if page == 1 && orgEndpointUnavailable(err) {
				return out, errOrgAlertsUnsupported
			}
			return out, fmt.Errorf("orgCodeScanningFindings: %s page %d: %w", org, page, err)
		}
		for _, a := range batch {
			if r, ok := active[a.Repository.FullName]; ok {
				out = append(out, codeScanFinding(r, a.codeScanAlert, now))
			}
		}
		if len(batch) < perPage {
			break
		}
	}
	return out, nil
}

func (c *Collector) repoCodeScanningAlerts(ctx context.Context, baseURL, token string, r repo) ([]finding.Finding, ghasSkip) {
	var alerts []codeScanAlert
	skip := skipNone
	for page := 1; page <= maxPages; page++ {
		url := fmt.Sprintf("%s/repos/%s/code-scanning/alerts?state=open&per_page=%d&page=%d",
			baseURL, r.FullName, perPage, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			break
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")

		var batch []codeScanAlert
		if err := c.doJSON(req, http.StatusOK, &batch); err != nil {
			skip = classifyGHASErr(err)
			if skip == skipOther {
				log.FromContext(ctx).Debug().Err(err).Str("repo", r.FullName).Msg("code-scanning: fetch failed")
			}
			break
		}
		alerts = append(alerts, batch...)
		if len(batch) < perPage {
			break
		}
	}

	now := time.Now()
	findings := make([]finding.Finding, 0, len(alerts))
	for _, a := range alerts {
		findings = append(findings, codeScanFinding(r, a, now))
	}
	return findings, skip
}

// ── Secret scanning ───────────────────────────────────────────────────────────

type secretAlert struct {
	Number                int       `json:"number"`
	CreatedAt             time.Time `json:"created_at"`
	State                 string    `json:"state"`
	SecretType            string    `json:"secret_type"`
	SecretTypeDisplayName string    `json:"secret_type_display_name"`
	// Validity is GitHub's check of the credential against its provider:
	// "active", "inactive" or "unknown", absent where validity checks are off
	// or the provider is not one GitHub can check.
	Validity string `json:"validity"`
}

type orgSecretAlert struct {
	secretAlert
	Repository alertRepo `json:"repository"`
}

// secretFinding maps one secret-scanning alert to a finding; same ID contract
// as codeScanFinding. GitHub's validity verdict is carried in Metadata only
// when it is one GitHub defines: anything else is recorded as absent, which
// the must-fix classifier reads as unknown.
func secretFinding(r repo, a secretAlert, now time.Time) finding.Finding {
	displayName := a.SecretTypeDisplayName
	if displayName == "" {
		displayName = a.SecretType
	}
	var meta map[string]string
	switch v := strings.ToLower(a.Validity); v {
	case finding.SecretValidityActive, finding.SecretValidityInactive, finding.SecretValidityUnknown:
		meta = map[string]string{finding.SecretValidityKey: v}
	}
	return finding.Finding{
		ID:           secretFindingID(r.FullName, a.Number),
		Source:       secretSource,
		Type:         "exposure",
		Severity:     finding.SeverityHigh,
		Title:        "Exposed secret: " + displayName,
		Description:  fmt.Sprintf("Secret of type %q detected in repository %s. Rotate immediately.", displayName, r.FullName),
		ResourceType: "github_repo",
		ResourceID:   r.FullName,
		ResourceName: r.Name,
		Region:       "global",
		CheckID:      a.SecretType,
		DetectedAt:   coalesceTime(a.CreatedAt, now),
		Metadata:     meta,
	}
}

func (c *Collector) orgSecretScanningFindings(ctx context.Context, baseURL, token, org string, active map[string]repo) ([]finding.Finding, error) {
	var out []finding.Finding
	now := time.Now()
	for page := 1; page <= maxPages; page++ {
		url := fmt.Sprintf("%s/orgs/%s/secret-scanning/alerts?state=open&hide_secret=true&per_page=%d&page=%d", baseURL, org, perPage, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return out, fmt.Errorf("orgSecretScanningFindings: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")

		var batch []orgSecretAlert
		if err := c.doJSON(req, http.StatusOK, &batch); err != nil {
			if page == 1 && orgEndpointUnavailable(err) {
				return out, errOrgAlertsUnsupported
			}
			return out, fmt.Errorf("orgSecretScanningFindings: %s page %d: %w", org, page, err)
		}
		for _, a := range batch {
			if r, ok := active[a.Repository.FullName]; ok {
				out = append(out, secretFinding(r, a.secretAlert, now))
			}
		}
		if len(batch) < perPage {
			break
		}
	}
	return out, nil
}

func (c *Collector) repoSecretScanningAlerts(ctx context.Context, baseURL, token string, r repo) ([]finding.Finding, ghasSkip) {
	var alerts []secretAlert
	skip := skipNone
	for page := 1; page <= maxPages; page++ {
		url := fmt.Sprintf("%s/repos/%s/secret-scanning/alerts?state=open&hide_secret=true&per_page=%d&page=%d",
			baseURL, r.FullName, perPage, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			break
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")

		var batch []secretAlert
		if err := c.doJSON(req, http.StatusOK, &batch); err != nil {
			skip = classifyGHASErr(err)
			if skip == skipOther {
				log.FromContext(ctx).Debug().Err(err).Str("repo", r.FullName).Msg("secret-scanning: fetch failed")
			}
			break
		}
		alerts = append(alerts, batch...)
		if len(batch) < perPage {
			break
		}
	}

	now := time.Now()
	findings := make([]finding.Finding, 0, len(alerts))
	for _, a := range alerts {
		findings = append(findings, secretFinding(r, a, now))
	}
	return findings, skip
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// codeScanSeverity maps GitHub's security_severity_level (preferred) or
// rule severity to a finding.Severity. Falls back to Medium when unknown.
func codeScanSeverity(secLevel, ruleSev string) finding.Severity {
	switch strings.ToLower(secLevel) {
	case "critical":
		return finding.SeverityCritical
	case "high":
		return finding.SeverityHigh
	case "medium":
		return finding.SeverityMedium
	case "low":
		return finding.SeverityLow
	}
	// Fall back to rule severity ("error"/"warning"/"note")
	switch strings.ToLower(ruleSev) {
	case "error":
		return finding.SeverityHigh
	case "warning":
		return finding.SeverityMedium
	case "note":
		return finding.SeverityLow
	}
	return finding.SeverityMedium
}

// descSuffix appends message text and file path to the description when present.
func descSuffix(msg, path string) string {
	if msg == "" && path == "" {
		return ""
	}
	var b strings.Builder
	if msg != "" {
		b.WriteString("\n\nInstance: ")
		b.WriteString(msg)
	}
	if path != "" {
		b.WriteString(" (")
		b.WriteString(path)
		b.WriteByte(')')
	}
	return b.String()
}

// coalesceTime returns t if non-zero, else fallback.
func coalesceTime(t, fallback time.Time) time.Time {
	if !t.IsZero() {
		return t
	}
	return fallback
}
