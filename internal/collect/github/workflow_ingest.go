package github

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect/iac"
	"github.com/vulngraph/vulngraph/pkg/log"
)

const (
	workflowConcurrency = 8  // parallel repos scanned (matches collectK8sManifests/collectIaC)
	workflowMaxFiles    = 50 // per-repo ceiling on workflow files fetched — bounds one sync's worst case
)

// collectWorkflows scans each non-archived repo's .github/workflows/ for
// cloud-identity intents declared in GitHub Actions steps and projects them
// into declared_ci_access assets. Best-effort per repo: no default
// branch, no workflows, no read permission, or a fetch error just skips that
// repo — this is supplementary signal and must never sink the whole GitHub
// sync (never sets Partial). Emits assets only; no edges (the join to a live
// iam_role/gcp_service_account happens in the ci_access correlate rule).
func (c *Collector) collectWorkflows(ctx context.Context, baseURL, token string, repos []repo) []asset.Asset {
	sem := make(chan struct{}, workflowConcurrency)
	var mu sync.Mutex
	var all []asset.Asset
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
					log.FromContext(ctx).Error().Interface("panic", rec).Str("repo", r.FullName).Msg("workflow scan panicked; skipped")
				}
			}()
			sem <- struct{}{}
			defer func() { <-sem }()

			paths := c.workflowTree(ctx, baseURL, token, r)
			if len(paths) == 0 {
				return
			}
			var decls []iac.DeclaredCIAccess
			for _, p := range paths {
				content, ok := c.workflowFile(ctx, baseURL, token, r, p)
				if !ok {
					continue
				}
				decls = append(decls, iac.ParseWorkflow(p, []byte(content))...)
			}
			if len(decls) == 0 {
				return
			}
			assets := iac.ProjectDeclaredCIAccess(decls, r.FullName, time.Now())
			mu.Lock()
			all = append(all, assets...)
			mu.Unlock()
			log.FromContext(ctx).Info().Int("assets", len(assets)).Str("repo", r.FullName).Msg("workflow ingest: projected declared CI access")
		}()
	}
	wg.Wait()
	return all
}

// listWorkflowPaths lists the repo's default-branch tree and returns
// .github/workflows/*.{yml,yaml} paths (capped). Mirrors listManifestPaths'
// tree walk.
func (c *Collector) listWorkflowPaths(ctx context.Context, baseURL, token string, r repo) []string {
	url := fmt.Sprintf("%s/repos/%s/git/trees/%s?recursive=1", baseURL, r.FullName, r.DefaultBranch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	var tree treeResponse
	if err := c.doJSON(req, http.StatusOK, &tree); err != nil {
		if !isGHASSkippable(err) {
			log.FromContext(ctx).Debug().Err(err).Str("repo", r.FullName).Msg("workflow: tree fetch failed")
		}
		return nil
	}
	if tree.Truncated {
		log.FromContext(ctx).Warn().Str("repo", r.FullName).Msg("workflow: repo tree truncated by GitHub — some workflows not scanned")
	}

	var paths []string
	for _, e := range tree.Tree {
		if len(paths) >= workflowMaxFiles {
			log.FromContext(ctx).Warn().Str("repo", r.FullName).Int("cap", workflowMaxFiles).Msg("workflow: file cap hit — remaining workflows not scanned")
			break
		}
		if e.Type != "blob" || !strings.HasPrefix(e.Path, ".github/workflows/") {
			continue
		}
		if !strings.HasSuffix(e.Path, ".yml") && !strings.HasSuffix(e.Path, ".yaml") {
			continue
		}
		paths = append(paths, e.Path)
	}
	return paths
}
