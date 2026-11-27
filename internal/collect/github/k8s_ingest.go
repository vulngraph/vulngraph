package github

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect/iac"
	"github.com/vulngraph/vulngraph/pkg/log"
)

const (
	k8sManifestConcurrency = 8   // parallel repos scanned (matches collectIaC)
	k8sManifestMaxFiles    = 300 // per-repo ceiling on YAML files fetched
)

// collectK8sManifests scans each non-archived repo's plain Kubernetes manifests
// and returns declared_k8s_workload assets. Best-effort per
// repo: no default branch, no YAML, no read permission, or a fetch error just
// skips that repo — the K8sManifestOwnership correlate rule later joins these to
// live k8s assets. Emits assets only; no edges (the join needs live inventory).
func (c *Collector) collectK8sManifests(ctx context.Context, baseURL, token string, repos []repo) []asset.Asset {
	sem := make(chan struct{}, k8sManifestConcurrency)
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
					log.FromContext(ctx).Error().Interface("panic", rec).Str("repo", r.FullName).Msg("k8s manifest scan panicked; skipped")
				}
			}()
			sem <- struct{}{}
			defer func() { <-sem }()

			paths := c.manifestTree(ctx, baseURL, token, r)
			if len(paths) == 0 {
				return
			}
			files := make(map[string]string, len(paths))
			for _, p := range paths {
				if content, ok := c.manifestFile(ctx, baseURL, token, r, p); ok {
					files[p] = content
				}
			}
			decls := iac.ParseK8sManifests(files)
			if len(decls) == 0 {
				return
			}
			assets := iac.ProjectDeclaredK8s(decls, r.FullName, time.Now())
			mu.Lock()
			all = append(all, assets...)
			mu.Unlock()
			log.FromContext(ctx).Info().Int("assets", len(assets)).Str("repo", r.FullName).Msg("k8s manifest ingest: projected declared workloads")
		}()
	}
	wg.Wait()
	return all
}

// listManifestPaths lists the repo's default-branch tree and returns *.yaml /
// *.yml paths (capped, fixture paths skipped). Mirrors fetchTerraformFiles'
// tree walk (iac.go), sharing successful source reads within a repository.
func (c *Collector) listManifestPaths(ctx context.Context, baseURL, token string, r repo) []string {
	tree, ok := c.repoTree(ctx, baseURL, token, r)
	if !ok {
		return nil
	}
	if tree.Truncated {
		log.FromContext(ctx).Warn().Str("repo", r.FullName).Msg("k8s manifest: repo tree truncated by GitHub — some YAML not scanned")
	}

	var paths []string
	for _, e := range tree.Tree {
		if len(paths) >= k8sManifestMaxFiles {
			log.FromContext(ctx).Warn().Str("repo", r.FullName).Int("cap", k8sManifestMaxFiles).Msg("k8s manifest: file cap hit — remaining YAML not scanned")
			break
		}
		if e.Type != "blob" {
			continue
		}
		if !strings.HasSuffix(e.Path, ".yaml") && !strings.HasSuffix(e.Path, ".yml") {
			continue
		}
		if isTestFixturePath(e.Path) {
			continue
		}
		paths = append(paths, e.Path)
	}
	return paths
}
