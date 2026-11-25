package github

import (
	"context"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect/iac"
	"github.com/vulngraph/vulngraph/pkg/log"
)

const (
	harvestConcurrency = 8   // parallel repos (matches the other IaC ingests)
	harvestMaxFiles    = 400 // per-repo ceiling on files fetched
)

// harvestExtensions are the file types swept for cloud identifiers. Broad on
// purpose: it does not matter which tool wrote the file — IAM policy JSON,
// Terraform, CDK, Helm/k8s YAML, and deploy-glue shell scripts all name
// identities the same way.
var harvestExtensions = map[string]bool{
	".tf": true, ".tfvars": true, ".json": true, ".yaml": true, ".yml": true,
	".ts": true, ".js": true, ".py": true, ".sh": true, ".tpl": true,
	".hcl": true, ".env": true, ".md": true,
}

// harvestSkipDirs are path segments whose contents are vendored or generated —
// scanning them costs API calls and yields identifiers the repo does not own.
var harvestSkipDirs = map[string]bool{
	"node_modules": true, "vendor": true, ".terraform": true, "dist": true,
	"build": true, ".git": true,
}

// collectRepoHarvest sweeps EVERY non-archived repo for the concrete
// identifiers written in its files and projects them as declared_* assets:
// cloud identities (declared_cloud_identity, joined to live identities by the
// declared_identity_ownership rule) and private-registry container image paths
// (declared_image_build, joined to live container_image assets by the
// ImageOwnership rule).
//
// Both extractors run over ONE tree listing and ONE set of file fetches, so the
// image sweep costs no additional GitHub API call — that is the whole reason it
// lives here rather than in its own pass.
//
// There is deliberately NO configuration: the sweep covers every repo, org and
// tool, so a new one is picked up the moment it appears rather than needing to
// be named somewhere.
//
// Best-effort per repo, like every other ingest here: a tree or content fetch
// failure skips that repo and never sets Partial.
func (c *Collector) collectRepoHarvest(ctx context.Context, baseURL, token string, repos []repo) []asset.Asset {
	logger := log.FromContext(ctx)

	sem := make(chan struct{}, harvestConcurrency)
	var mu sync.Mutex
	var all []asset.Asset
	var reposWithHits, filesScanned, imageAssets int
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
					logger.Error().Interface("panic", rec).Str("repo", r.FullName).Msg("repo harvest panicked; skipped")
				}
			}()
			sem <- struct{}{}
			defer func() { <-sem }()

			files := c.harvestFiles(ctx, baseURL, token, r)
			if len(files) == 0 {
				return
			}
			now := time.Now()
			var repoAssets []asset.Asset

			// imageFirstPath keeps the alphabetically first file naming each
			// image so the evidence path is stable across syncs (map iteration
			// order is not).
			imageFirstPath := map[string]string{}
			for p, content := range files {
				if ids := iac.HarvestIdentities([]byte(content)); len(ids) > 0 {
					repoAssets = append(repoAssets, iac.ProjectDeclaredIdentities(ids, r.FullName, p, now)...)
				}
				for _, img := range HarvestImageRefs([]byte(content)) {
					if prev, ok := imageFirstPath[img]; !ok || p < prev {
						imageFirstPath[img] = p
					}
				}
			}
			imgs := projectDeclaredImageBuilds(imageFirstPath, r.FullName, now)
			repoAssets = append(repoAssets, imgs...)

			mu.Lock()
			filesScanned += len(files)
			imageAssets += len(imgs)
			if len(repoAssets) > 0 {
				reposWithHits++
				all = append(all, repoAssets...)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	logger.Info().Int("assets", len(all)).Int("repos_with_hits", reposWithHits).
		Int("image_assets", imageAssets).
		Int("files_scanned", filesScanned).Int("repos", len(repos)).
		Msg("repo harvest: projected declared_cloud_identity + declared_image_build")
	return all
}

// fetchHarvestFiles lists a repo's tree once and returns the contents of as
// many candidate files as the cap allows.
func (c *Collector) fetchHarvestFiles(ctx context.Context, baseURL, token string, r repo) map[string]string {
	tree, ok := c.repoTree(ctx, baseURL, token, r)
	if !ok {
		return nil
	}
	logger := log.FromContext(ctx)
	if tree.Truncated {
		logger.Warn().Str("repo", r.FullName).Msg("repo harvest: repo tree truncated by GitHub — some files not swept")
	}

	files := map[string]string{}
	var capped int
	for _, e := range tree.Tree {
		if e.Type != "blob" || !harvestCandidate(e.Path) {
			continue
		}
		if len(files) >= harvestMaxFiles {
			capped++
			continue
		}
		if content, ok := c.fetchFileContent(ctx, baseURL, token, r, e.Path); ok {
			files[e.Path] = content
		}
	}
	if capped > 0 {
		logger.Warn().Str("repo", r.FullName).Int("cap", harvestMaxFiles).Int("skipped", capped).
			Msg("repo harvest: content-fetch cap hit — those files' identifiers not read")
	}
	return files
}

// harvestCandidate reports whether a repo path is worth fetching.
func harvestCandidate(p string) bool {
	if isTestFixturePath(p) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if harvestSkipDirs[seg] {
			return false
		}
	}
	return harvestExtensions[strings.ToLower(path.Ext(p))]
}
