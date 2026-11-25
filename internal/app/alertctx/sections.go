package alertctx

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"unicode"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/pkg/log"
)

const (
	failExposure = "exposure lookup failed"
	failBlast    = "blast radius walk failed"
	failFindings = "findings lookup failed"
)

// fill starts the independent sub-lookups for one asset. Each writes only its
// own sections of ac and degrades to "unavailable" on error or panic.
func (s *Service) fill(ctx context.Context, wg *sync.WaitGroup, sem chan struct{}, a asset.Asset, ac *AssetContext) {
	spawn(ctx, wg, sem, "exposure", func(reason string) { ac.Exposure = Exposure{Availability: Availability{Reason: reason}} }, func() string {
		exposed, err := s.assets.IsExposedEdge(ctx, a.ID)
		if err != nil {
			log.FromContext(ctx).Error().Err(err).Str("asset_id", a.ID).Msg("alertctx: exposure lookup failed")
			return failExposure
		}
		ac.Exposure = Exposure{Availability: Availability{Known: true}, ExposedToInternet: exposed}
		return ""
	})
	spawn(ctx, wg, sem, "blast", func(reason string) { ac.Blast = Blast{Availability: Availability{Reason: reason}} }, func() string {
		br, err := s.blast.BlastRadius(ctx, a.ID, blastDepth)
		if err != nil {
			log.FromContext(ctx).Error().Err(err).Str("asset_id", a.ID).Msg("alertctx: blast radius failed")
			return failBlast
		}
		ac.Blast = summarizeBlast(a.ID, br)
		return ""
	})
	onFindingsFail := func(reason string) {
		ac.Findings = Findings{Availability: Availability{Reason: reason}}
		if isIdentity(a.Type) {
			ac.Privileges = &Privileges{Availability: Availability{Reason: reason}}
		}
	}
	spawn(ctx, wg, sem, "findings", onFindingsFail, func() string {
		list, truncated, err := s.assetFindings(ctx, a)
		if err != nil {
			log.FromContext(ctx).Error().Err(err).Str("asset_id", a.ID).Msg("alertctx: findings lookup failed")
			return failFindings
		}
		ac.Findings = summarizeFindings(list, truncated)
		if isIdentity(a.Type) {
			p := summarizePrivileges(a, list, truncated)
			ac.Privileges = &p
		}
		return ""
	})
}

// spawn runs fn under the semaphore. fn returns a failure reason or "". A
// panic or a cancelled context is reported through onFail like any other
// failure.
func spawn(ctx context.Context, wg *sync.WaitGroup, sem chan struct{}, name string, onFail func(string), fn func() string) {
	wg.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.FromContext(ctx).Error().Any("panic", r).Str("section", name).Msg("alertctx: section panicked")
				onFail(name + " lookup failed unexpectedly")
			}
			wg.Done()
		}()
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		case <-ctx.Done():
			onFail("request cancelled before the " + name + " lookup ran")
			return
		}
		if reason := fn(); reason != "" {
			onFail(reason)
		}
	}()
}

// nameKeyedSource: aws_guardduty iam_user findings carry the principal's NAME
// as resource id while the asset id is its ARN, so an id-only lookup misses an
// active GuardDuty detection on a user.
const nameKeyedSource = "aws_guardduty"

// assetFindings lists open findings for the asset by id, plus name-keyed
// GuardDuty findings for IAM principals. truncated is true when the fetch limit
// was reached.
func (s *Service) assetFindings(ctx context.Context, a asset.Asset) ([]finding.Finding, bool, error) {
	list, err := s.findings.List(ctx, finding.Filter{ResourceID: a.ID, SortByScore: true, Limit: findingsFetchLimit})
	if err != nil {
		return nil, false, fmt.Errorf("findings by id: %w", err)
	}
	truncated := len(list) >= findingsFetchLimit
	if (a.Type == "iam_user" || a.Type == "iam_role") && a.Name != "" && a.Name != a.ID {
		named, err := s.findings.List(ctx, finding.Filter{ResourceID: a.Name, Source: nameKeyedSource, SortByScore: true, Limit: findingsFetchLimit})
		if err != nil {
			return nil, false, fmt.Errorf("findings by name: %w", err)
		}
		have := make(map[string]bool, len(list))
		for _, f := range list {
			have[f.ID] = true
		}
		for _, f := range named {
			if !have[f.ID] && f.ResourceType == "iam_user" {
				list = append(list, f)
			}
		}
		truncated = truncated || len(named) >= findingsFetchLimit
	}
	return list, truncated, nil
}

func summarizeBlast(seedID string, br asset.BlastRadius) Blast {
	b := Blast{Availability: Availability{Known: true}, ByType: map[string]int{}, Truncated: br.Truncated}
	var reach []asset.Asset
	for _, a := range br.Assets {
		if a.ID == seedID {
			continue
		}
		b.Count++
		b.ByType[a.Type]++
		reach = append(reach, a)
	}
	if len(b.ByType) > MaxTypes {
		types := make([]string, 0, len(b.ByType))
		for t := range b.ByType {
			types = append(types, t)
		}
		sort.Slice(types, func(i, j int) bool {
			if b.ByType[types[i]] != b.ByType[types[j]] {
				return b.ByType[types[i]] > b.ByType[types[j]]
			}
			return types[i] < types[j]
		})
		kept := map[string]int{}
		for _, t := range types[:MaxTypes] {
			kept[t] = b.ByType[t]
		}
		b.ByType, b.Truncated = kept, true
	}
	sort.Slice(reach, func(i, j int) bool {
		if reach[i].RiskScore != reach[j].RiskScore {
			return reach[i].RiskScore > reach[j].RiskScore
		}
		return reach[i].ID < reach[j].ID
	})
	if len(reach) > MaxTop {
		reach = reach[:MaxTop]
	}
	for _, a := range reach {
		b.TopReachable = append(b.TopReachable, ReachableAsset{ID: a.ID, Name: clean(a.Name), Type: a.Type, RiskScore: a.RiskScore})
	}
	return b
}

func summarizeFindings(list []finding.Finding, truncated bool) Findings {
	f := Findings{Availability: Availability{Known: true}, Total: len(list), BySeverity: map[string]int{}, Truncated: truncated}
	sorted := append([]finding.Finding(nil), list...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Score > sorted[j].Score })
	for _, x := range sorted {
		f.BySeverity[string(x.Severity)]++
		if x.MustFixClass == "must_fix" && len(f.MustFix) < MaxTop {
			f.MustFix = append(f.MustFix, findingRef(x))
		}
	}
	for _, x := range sorted[:min(MaxTop, len(sorted))] {
		f.Top = append(f.Top, findingRef(x))
	}
	return f
}

func findingRef(f finding.Finding) FindingRef {
	return FindingRef{
		ID: f.ID, Title: clean(f.Title), Severity: string(f.Severity), Score: f.Score,
		CheckID: clean(f.CheckID), MustFixClass: f.MustFixClass, MustFixReason: clean(f.MustFixReason),
	}
}

const privescFindingType = "ciem_privesc"

// summarizePrivileges reads escalation from CIEM findings. Having no privesc
// finding proves nothing unless CIEM actually evaluated the identity — its
// privilege_tier stamp over a read permission set is that witness
// (ciem.Graded: absent for a type or provider CIEM does not read, "unknown"
// when the permission set was not read, and a collector-flagged admin whose
// permissions were never read is not an evaluation either). A
// truncated finding list with no privesc finding seen stays unknown too.
func summarizePrivileges(a asset.Asset, list []finding.Finding, truncated bool) Privileges {
	var techniques []string
	for _, f := range list {
		if f.Type == privescFindingType {
			techniques = append(techniques, clean(f.CheckID))
		}
	}
	if len(techniques) == 0 {
		if truncated {
			return Privileges{Availability: Availability{Reason: "finding list truncated; escalation findings may be missing"}}
		}
		if !ciem.Graded(a) {
			return Privileges{Availability: Availability{Reason: "privilege escalation not evaluated for this identity (permissions unread or not covered by CIEM)"}}
		}
	}
	techniques = dedupe(techniques)
	sort.Strings(techniques)
	if len(techniques) > MaxTop*2 {
		techniques = techniques[:MaxTop*2]
	}
	return Privileges{Availability: Availability{Known: true}, CanEscalate: len(techniques) > 0, Techniques: techniques}
}

func isIdentity(assetType string) bool {
	switch assetType {
	case "iam_role", "iam_user", "iam_group", "gcp_service_account",
		"azure_service_principal", "azure_managed_identity", "human_identity", "k8s_service_account":
		return true
	}
	return false
}

func summarize(a asset.Asset) AssetSummary {
	return AssetSummary{
		ID: a.ID, Name: clean(a.Name), Type: a.Type, Provider: string(a.Provider),
		AccountID: a.AccountID, Region: a.Region,
		Environment: clean(tagOf(a, "environment", "env", "Environment", "Env")),
		Owner:       clean(tagOf(a, "owner", "Owner", "team", "Team", "app.kubernetes.io/part-of")),
		PublicIP:    a.PublicIP, PrivateIP: a.PrivateIP, Domain: clean(a.Domain),
		RiskScore: a.RiskScore, RiskScoreSource: RiskSourceStored, LastSeen: a.LastSeen,
	}
}

// tagOf returns the first non-empty tag or metadata value among keys.
func tagOf(a asset.Asset, keys ...string) string {
	for _, k := range keys {
		if v := a.Tags[k]; v != "" {
			return v
		}
		if v := a.Metadata[k]; v != "" {
			return v
		}
	}
	return ""
}

// clean makes cloud-originated text safe to embed in a one-line summary and
// bounds its size: control characters (newlines included) become spaces.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > maxFieldLen {
		return string(r[:maxFieldLen]) + "..."
	}
	return s
}
