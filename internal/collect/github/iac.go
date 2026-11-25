package github

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/scanner/iac"
	"github.com/vulngraph/vulngraph/pkg/log"
)

const (
	iacConcurrency  = 8   // max parallel repos scanned (matches GHAS/SBOM)
	iacMaxFiles     = 300 // per-repo ceiling on .tf files fetched — bounds a huge monorepo
	iacMaxFileBytes = 1 << 20
)

// collectIaC scans each non-archived repo's Terraform for misconfigurations and
// returns findings keyed to the repo (shift-left signal). Best-effort per repo:
// a repo with no .tf, no read permission, or a fetch error is silently skipped —
// only the scan of that repo degrades, never the whole sync.
//
// Findings are attached to the github_repo asset, not the deployed cloud
// resource: reliably linking a .tf resource to its live asset needs tfstate or
// a tagging convention (a source_code_defines edge), which doesn't exist yet —
// there's no general join key between a Terraform resource name and its live
// asset.
//
// fetchTerraformFiles also skips files under conventional test/example/fixture
// paths (isTestFixturePath): without it, deliberately vulnerable scanner-test
// fixtures are indistinguishable in severity from real misconfigurations.
func (c *Collector) collectIaC(ctx context.Context, baseURL, token string, repos []repo) []finding.Finding {
	sem := make(chan struct{}, iacConcurrency)
	var mu sync.Mutex
	var all []finding.Finding
	var wg sync.WaitGroup

	for _, r := range repos {
		if r.Archived || r.DefaultBranch == "" {
			continue
		}
		r := r
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					log.FromContext(ctx).Error().Interface("panic", rec).Str("repo", r.FullName).Msg("iac scan panicked; skipped")
				}
			}()
			sem <- struct{}{}
			defer func() { <-sem }()

			files := c.fetchTerraformFiles(ctx, baseURL, token, r)
			if len(files) == 0 {
				return
			}
			issues, parseErrs := iac.Scan(files)
			for name, perr := range parseErrs {
				log.FromContext(ctx).Debug().Err(perr).Str("repo", r.FullName).Str("file", name).Msg("iac: terraform parse failed")
			}
			if len(issues) == 0 {
				return
			}
			now := time.Now()
			fs := make([]finding.Finding, 0, len(issues))
			for _, is := range issues {
				fs = append(fs, finding.Finding{
					ID:           fmt.Sprintf("iac:%s:%s:%s", r.FullName, is.Resource, is.RuleID),
					Source:       "iac",
					Type:         "misconfiguration",
					Severity:     iacSeverity(is.Severity),
					Title:        is.Title,
					Description:  fmt.Sprintf("%s\n\nResource: %s (%s)", is.Detail, is.Resource, is.File),
					ResourceType: "github_repo",
					ResourceID:   r.FullName,
					ResourceName: r.Name,
					Region:       "global",
					CheckID:      is.RuleID,
					Remediation:  is.Fix,
					DetectedAt:   now,
					Metadata:     map[string]string{"iac_resource": is.Resource, "iac_file": is.File},
				})
			}
			mu.Lock()
			all = append(all, fs...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return all
}

// treeEntry is one node in a git tree listing.
type treeResponse struct {
	Tree []struct {
		Path string `json:"path"`
		Type string `json:"type"`
	} `json:"tree"`
	Truncated bool `json:"truncated"`
}

// repoTree lists a repo's default-branch tree recursively. Shared because every
// per-repo file ingest here needs it; callers decide what to do about tree.Truncated, which is why it is
// returned rather than logged in here.
func (c *Collector) repoTree(ctx context.Context, baseURL, token string, r repo) (treeResponse, bool) {
	url := fmt.Sprintf("%s/repos/%s/git/trees/%s?recursive=1", baseURL, r.FullName, r.DefaultBranch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return treeResponse{}, false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	var tree treeResponse
	if err := c.doJSON(req, http.StatusOK, &tree); err != nil {
		if !isGHASSkippable(err) {
			log.FromContext(ctx).Debug().Err(err).Str("repo", r.FullName).Msg("github: tree fetch failed")
		}
		return treeResponse{}, false
	}
	return tree, true
}

// fetchTerraformFiles lists the repo's default-branch tree and fetches the
// content of every *.tf file (capped). Returns filename → content.
func (c *Collector) fetchTerraformFiles(ctx context.Context, baseURL, token string, r repo) map[string]string {
	tree, ok := c.repoTree(ctx, baseURL, token, r)
	if !ok {
		return nil
	}
	if tree.Truncated {
		log.FromContext(ctx).Warn().Str("repo", r.FullName).Msg("iac: repo tree truncated by GitHub — some .tf files not scanned")
	}

	files := map[string]string{}
	for _, e := range tree.Tree {
		if len(files) >= iacMaxFiles {
			log.FromContext(ctx).Warn().Str("repo", r.FullName).Int("cap", iacMaxFiles).Msg("iac: .tf file cap hit — remaining files not scanned")
			break
		}
		if e.Type != "blob" || !strings.HasSuffix(e.Path, ".tf") {
			continue
		}
		if isTestFixturePath(e.Path) {
			continue
		}
		if content, ok := c.fetchFileContent(ctx, baseURL, token, r, e.Path); ok {
			files[e.Path] = content
		}
	}
	return files
}

// testFixturePathSegments are path components that mark a Terraform file as
// scanner/example fixture content rather than deployment config actually meant
// to be applied — e.g. a scanner-test repo's test/test_project/main.tf that
// defines aws_s3_bucket.vulnerable_bucket and aws_security_group.vulnerable_sg
// on purpose, to exercise a scanner. Matched as whole path
// segments (split on "/"), never substring, so a legitimately-named directory
// like "latest/" or "contest-entries/" is never caught.
var testFixturePathSegments = map[string]struct{}{
	"test":       {},
	"tests":      {},
	"testdata":   {},
	"example":    {},
	"examples":   {},
	"fixture":    {},
	"fixtures":   {},
	".terraform": {}, // downloaded module cache, never authored source
}

// isTestFixturePath reports whether path (repo-relative, forward-slash
// separated) has any directory component identifying it as scanner-fixture or
// example content rather than real deployment Terraform. Conservative and
// path-segment-exact by design: a false negative (missing a fixture path) just
// means one extra low-value finding; a false positive (skipping a real
// production file) hides a real misconfiguration, which is the worse failure
// mode.
func isTestFixturePath(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if _, ok := testFixturePathSegments[strings.ToLower(seg)]; ok {
			return true
		}
	}
	return false
}

type contentResponse struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
	Size     int    `json:"size"`
}

func (c *Collector) fetchFileContent(ctx context.Context, baseURL, token string, r repo, path string) (string, bool) {
	url := fmt.Sprintf("%s/repos/%s/contents/%s?ref=%s", baseURL, r.FullName, path, r.DefaultBranch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	var cr contentResponse
	if err := c.doJSON(req, http.StatusOK, &cr); err != nil {
		return "", false
	}
	if cr.Size > iacMaxFileBytes || cr.Encoding != "base64" {
		return "", false
	}
	// GitHub base64 content is newline-wrapped.
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(cr.Content, "\n", ""))
	if err != nil {
		return "", false
	}
	return string(decoded), true
}

func iacSeverity(s string) finding.Severity {
	switch s {
	case iac.SeverityCritical:
		return finding.SeverityCritical
	case iac.SeverityHigh:
		return finding.SeverityHigh
	case iac.SeverityMedium:
		return finding.SeverityMedium
	default:
		return finding.SeverityLow
	}
}
