package github

import (
	"context"
	"sync"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/pkg/log"
)

type repositorySources struct {
	Assets    []asset.Asset
	Findings  []finding.Finding
	Workflows workflowInventory
	Failed    bool
}

// Finish the source readers for each repository before releasing its raw read
// cache. Eight admitted repositories bound retained data independently of the
// total repository count. Existing readers keep their parsing/error semantics.
func (c *Collector) collectRepositorySources(ctx context.Context, baseURL, token string, repos []repo, prior map[string]map[string]string, apps appInventory, stateAccountID string) repositorySources {
	out := repositorySources{Workflows: workflowInventory{Metadata: map[string]map[string]string{}, Complete: true}}
	index := newAppScopeIndex(apps.Snapshot, repos)
	sem := make(chan struct{}, workflowConcurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, r := range repos {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			out.Workflows.Complete = false
			return out
		}
		wg.Add(1)
		go func(r repo) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					mu.Lock()
					out.Failed = true
					mu.Unlock()
					log.FromContext(ctx).Error().Interface("panic", rec).Msg("repository source scan failed")
				}
			}()
			repoCtx, cache := withRepositoryReadCache(ctx)
			defer cache.close()
			one := []repo{r}
			findings := c.collectIaC(repoCtx, baseURL, token, one)
			assets := c.collectK8sManifests(repoCtx, baseURL, token, one)
			workflows := c.collectWorkflowVisibilityIndexed(repoCtx, baseURL, token, one, prior, index)
			assets = append(assets, c.collectRepoHarvest(repoCtx, baseURL, token, one)...)
			stateAssets, stateFindings := c.collectTFState(repoCtx, baseURL, token, one, c.tfStateObj, c.tfStateBucketAcct, c.tfStateConn, stateAccountID)
			assets = append(assets, stateAssets...)
			findings = append(findings, stateFindings...)
			mu.Lock()
			defer mu.Unlock()
			out.Assets = append(out.Assets, assets...)
			out.Findings = append(out.Findings, findings...)
			out.Workflows.Assets = append(out.Workflows.Assets, workflows.Assets...)
			out.Workflows.Edges = append(out.Workflows.Edges, workflows.Edges...)
			out.Workflows.Findings = append(out.Workflows.Findings, workflows.Findings...)
			out.Workflows.Metadata[r.FullName] = workflows.Metadata[r.FullName]
			out.Workflows.Complete = out.Workflows.Complete && workflows.Complete
		}(r)
	}
	wg.Wait()
	log.FromContext(ctx).Info().Int("repos", len(repos)).Int("source_assets", len(out.Assets)).
		Int("workflow_assets", len(out.Workflows.Assets)).Msg("repository source ingest complete")
	return out
}
