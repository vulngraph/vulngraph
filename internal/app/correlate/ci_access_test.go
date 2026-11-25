package correlate

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func declaredCIAccessAsset(repo, provider, workflowPath string, meta map[string]string) asset.Asset {
	target := meta["target_arn"]
	if target == "" {
		target = meta["target_sa"]
	}
	m := map[string]string{
		"repo": repo, "provider": provider, "workflow_path": workflowPath,
	}
	for k, v := range meta {
		m[k] = v
	}
	return asset.Asset{
		ID:       "declared_ci_access:" + repo + ":" + workflowPath + ":" + target,
		Type:     "declared_ci_access",
		Metadata: m,
	}
}

func TestCIAccess_JoinsDeclaredToLiveRoleByARN(t *testing.T) {
	arn := "arn:aws:iam::210987654321:role/gh-deploy"
	g := NewGraph([]asset.Asset{
		{ID: arn, Type: "iam_role"},
		declaredCIAccessAsset("example-corp/api", "aws", ".github/workflows/d.yml", map[string]string{
			"target_arn": arn, "account_id": "210987654321",
		}),
		{ID: "example-corp/api", Type: "github_repo", Name: "api"},
	})

	edges := (&CIAccess{}).Correlate(g)
	if assert.Len(t, edges, 1) {
		e := edges[0]
		assert.Equal(t, EdgeFederatedAccess, e.EdgeType)
		assert.Equal(t, "example-corp/api", e.SrcID)
		assert.Equal(t, arn, e.DstID)
		assert.Equal(t, "gh_workflow", e.Properties["provenance"])
		assert.Equal(t, "high", e.Properties["confidence"])
		assert.Equal(t, ".github/workflows/d.yml", e.Properties["workflow_path"])
	}
}

func TestCIAccess_NoLiveRole_QueuesForVerify_NoEdge(t *testing.T) {
	arn := "arn:aws:iam::999999999999:role/mystery"
	g := NewGraph([]asset.Asset{
		declaredCIAccessAsset("r", "aws", ".github/workflows/d.yml", map[string]string{
			"target_arn": arn, "account_id": "999999999999",
		}),
		{ID: "r", Type: "github_repo"},
	})

	rule := &CIAccess{}
	edges := rule.Correlate(g)
	assert.Empty(t, edges, "no live role → no edge emitted inline")
	assert.Contains(t, rule.PendingLiveVerify(), PendingVerify{
		RepoID: "r", TargetARN: arn, AccountID: "999999999999",
		WorkflowPath: ".github/workflows/d.yml",
	})
}

func TestCIAccess_JoinsDeclaredToLiveGCPServiceAccount(t *testing.T) {
	sa := "deploy@my-project.iam.gserviceaccount.com"
	g := NewGraph([]asset.Asset{
		{ID: "serviceAccount:" + sa, Type: "gcp_service_account", Name: sa},
		declaredCIAccessAsset("example-corp/api", "gcp", ".github/workflows/d.yml", map[string]string{
			"target_sa": sa, "account_id": "my-project",
		}),
		{ID: "example-corp/api", Type: "github_repo", Name: "api"},
	})

	edges := (&CIAccess{}).Correlate(g)
	if assert.Len(t, edges, 1) {
		e := edges[0]
		assert.Equal(t, EdgeFederatedAccess, e.EdgeType)
		assert.Equal(t, "example-corp/api", e.SrcID)
		assert.Equal(t, "serviceAccount:"+sa, e.DstID)
		assert.Equal(t, "gcp_service_account", e.DstType)
		assert.Equal(t, "gh_workflow", e.Properties["provenance"])
		assert.Equal(t, "high", e.Properties["confidence"])
	}
}

func TestCIAccess_NoLiveGCPServiceAccount_NoEdgeNoPending(t *testing.T) {
	sa := "ghost@my-project.iam.gserviceaccount.com"
	g := NewGraph([]asset.Asset{
		declaredCIAccessAsset("r", "gcp", ".github/workflows/d.yml", map[string]string{
			"target_sa": sa, "account_id": "my-project",
		}),
		{ID: "r", Type: "github_repo"},
	})

	rule := &CIAccess{}
	edges := rule.Correlate(g)
	assert.Empty(t, edges, "no live SA → no edge emitted")
	assert.Empty(t, rule.PendingLiveVerify(), "GCP unmatched is not queued for live verify")
}

func TestCIAccess_MissingRepoIDNoEdgeNoPending(t *testing.T) {
	arn := "arn:aws:iam::111111111111:role/x"
	g := NewGraph([]asset.Asset{
		{ID: arn, Type: "iam_role"},
		{ID: "declared_ci_access:x", Type: "declared_ci_access", Metadata: map[string]string{
			"repo": "", "provider": "aws", "target_arn": arn, "account_id": "111111111111",
		}},
	})

	rule := &CIAccess{}
	edges := rule.Correlate(g)
	assert.Empty(t, edges, "repo==\"\" must skip, no edge")
	assert.Empty(t, rule.PendingLiveVerify())
}

func TestCIAccess_Correlate_ResetsPendingEachSweep(t *testing.T) {
	firstARN := "arn:aws:iam::999999999999:role/mystery-1"
	g1 := NewGraph([]asset.Asset{
		declaredCIAccessAsset("r", "aws", ".github/workflows/d.yml", map[string]string{
			"target_arn": firstARN, "account_id": "999999999999",
		}),
		{ID: "r", Type: "github_repo"},
	})

	rule := &CIAccess{}
	rule.Correlate(g1)
	require.Contains(t, rule.PendingLiveVerify(), PendingVerify{
		RepoID: "r", TargetARN: firstARN, AccountID: "999999999999",
		WorkflowPath: ".github/workflows/d.yml",
	})

	secondARN := "arn:aws:iam::888888888888:role/mystery-2"
	g2 := NewGraph([]asset.Asset{
		declaredCIAccessAsset("r2", "aws", ".github/workflows/e.yml", map[string]string{
			"target_arn": secondARN, "account_id": "888888888888",
		}),
		{ID: "r2", Type: "github_repo"},
	})

	rule.Correlate(g2)
	pending := rule.PendingLiveVerify()
	assert.Equal(t, []PendingVerify{{
		RepoID: "r2", TargetARN: secondARN, AccountID: "888888888888",
		WorkflowPath: ".github/workflows/e.yml",
	}}, pending,
		"second sweep must not accumulate the first sweep's pending targets")
}

func TestCIAccess_Name(t *testing.T) {
	require.Equal(t, "ci_access", (&CIAccess{}).Name())
}

// TestCIAccess_ConcurrentCorrelateAndPendingLiveVerify_NoRace asserts nothing
// itself: only `go test -race` turns a reverted mu guard on CIAccess.pending
// into a failure (CI's race-detector step runs this package); a plain run
// passes either way.
// It runs Correlate (the write side, called from correlate.Service's rule
// loop) against PendingLiveVerify (the read side, called from
// jobs/correlate.go's workFull) on one shared *CIAccess, the sharing
// cmd/graph/worker.go sets up. Production never calls the two concurrently
// (correlateWorkers=1 serializes correlate jobs); under -race this shows the
// type stays memory-safe if that is ever loosened.
func TestCIAccess_ConcurrentCorrelateAndPendingLiveVerify_NoRace(t *testing.T) {
	arn := "arn:aws:iam::999999999999:role/mystery"
	g := NewGraph([]asset.Asset{
		declaredCIAccessAsset("r", "aws", ".github/workflows/d.yml", map[string]string{
			"target_arn": arn, "account_id": "999999999999",
		}),
		{ID: "r", Type: "github_repo"},
	})

	rule := &CIAccess{}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			rule.Correlate(g)
		}()
		go func() {
			defer wg.Done()
			rule.PendingLiveVerify()
		}()
	}
	wg.Wait()
}
