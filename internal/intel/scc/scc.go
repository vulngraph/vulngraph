// Package scc pulls active THREAT-class findings from GCP Security Command
// Center — cloud-native threat detections (malware-on-disk, DDoS, anomalous
// IAM) the platform cannot self-generate. Only the THREAT findingClass is
// fetched: the MISCONFIGURATION bulk duplicates our own CSPM checks and is
// deliberately excluded. SCC is org-scoped, so this is a single org-level query
// (a periodic feed, like KEV/OSV), not a per-project collection.
package scc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/api/option"
	securitycenter "google.golang.org/api/securitycenter/v1"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// threatFilter selects active threat detections only.
const threatFilter = `state="ACTIVE" AND findingClass="THREAT"`

// Fetcher reads SCC findings for one organization. quotaProject is the project
// the API calls bill to (must have the Security Command Center API enabled);
// empty uses ADC's default quota project.
type Fetcher struct {
	orgID        string
	quotaProject string
	now          func() time.Time
}

func NewFetcher(orgID, quotaProject string) *Fetcher {
	return &Fetcher{orgID: orgID, quotaProject: quotaProject, now: time.Now}
}

// Scope names the listing Fetch reads — the organization — so the findings it
// produced can be told apart from another organization's.
func (f *Fetcher) Scope() string { return "gcp_scc:organizations/" + f.orgID }

// Fetch lists active THREAT findings across all SCC sources for the org and maps
// them to platform findings (source "gcp_scc").
func (f *Fetcher) Fetch(ctx context.Context) ([]finding.Finding, error) {
	opts := []option.ClientOption{}
	if f.quotaProject != "" {
		opts = append(opts, option.WithQuotaProject(f.quotaProject))
	}
	svc, err := securitycenter.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("scc Fetch: %w", err)
	}

	now := f.now()
	parent := "organizations/" + f.orgID + "/sources/-"
	var out []finding.Finding
	err = svc.Organizations.Sources.Findings.List(parent).Filter(threatFilter).
		Pages(ctx, func(page *securitycenter.ListFindingsResponse) error {
			for _, r := range page.ListFindingsResults {
				if r.Finding != nil {
					out = append(out, mapSCCFinding(r.Finding, now))
				}
			}
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("scc Fetch: list: %w", err)
	}
	return out, nil
}

// mapSCCFinding maps an SCC finding to a platform finding. The ID derives from
// SCC's stable finding name so re-fetches upsert in place.
func mapSCCFinding(f *securitycenter.Finding, now time.Time) finding.Finding {
	resID, resType := parseSCCResource(f.ResourceName)
	return finding.Finding{
		ID:           dbutil.DeterministicID("gcp_scc", f.Name),
		Source:       "gcp_scc",
		Type:         "threat",
		Severity:     sccSeverity(f.Severity),
		Title:        f.Category,
		Description:  "GCP Security Command Center threat detection: " + f.Category,
		ResourceType: resType,
		ResourceID:   resID,
		CheckID:      f.Category,
		Remediation:  "Investigate the Security Command Center detection and contain the affected resource per your IR runbook.",
		DetectedAt:   now,
	}
}

// sccSeverity maps SCC's severity enum to the platform severity.
func sccSeverity(s string) finding.Severity {
	switch s {
	case "CRITICAL", "HIGH":
		return finding.SeverityHigh
	case "MEDIUM":
		return finding.SeverityMedium
	case "LOW":
		return finding.SeverityLow
	default:
		return finding.SeverityMedium
	}
}

// parseSCCResource turns an SCC resourceName into a platform resource id + type.
// Compute instances map to the gce_instance asset id (projectID/name) so the
// threat links into the graph; other shapes fall back to the raw name.
func parseSCCResource(resourceName string) (id, typ string) {
	if resourceName == "" {
		return "", ""
	}
	parts := strings.Split(resourceName, "/")
	idxOf := func(s string) int {
		for i, p := range parts {
			if p == s {
				return i
			}
		}
		return -1
	}
	pi, ii := idxOf("projects"), idxOf("instances")
	if pi >= 0 && pi+1 < len(parts) && ii >= 0 && ii+1 < len(parts) {
		return parts[pi+1] + "/" + parts[ii+1], "gce_instance"
	}
	return resourceName, ""
}
