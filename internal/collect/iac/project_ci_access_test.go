package iac

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestProjectDeclaredCIAccess_AWSCarriesAccountAndTarget(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	decls := []DeclaredCIAccess{{
		Provider: "aws", TargetARN: "arn:aws:iam::210987654321:role/gh-deploy",
		WorkflowPath: ".github/workflows/deploy.yml", Resolved: true,
	}}
	got := ProjectDeclaredCIAccess(decls, "example-corp/api", now)
	if assert.Len(t, got, 1) {
		a := got[0]
		assert.Equal(t, "declared_ci_access", a.Type)
		assert.Equal(t, "arn:aws:iam::210987654321:role/gh-deploy", a.Metadata["target_arn"])
		assert.Equal(t, "210987654321", a.Metadata["account_id"])
		assert.Equal(t, "example-corp/api", a.Metadata["repo"])
		assert.Equal(t, "aws", a.Metadata["provider"])
		assert.False(t, a.LastSeen.IsZero())
	}
}

func TestProjectDeclaredCIAccess_SkipsUnresolved(t *testing.T) {
	got := ProjectDeclaredCIAccess([]DeclaredCIAccess{{Provider: "aws", Resolved: false}}, "r", time.Unix(1, 0))
	assert.Empty(t, got)
}

func TestProjectDeclaredCIAccess_GCPUsesSA(t *testing.T) {
	got := ProjectDeclaredCIAccess([]DeclaredCIAccess{{
		Provider: "gcp", TargetSA: "deploy@p.iam.gserviceaccount.com",
		WorkflowPath: ".github/workflows/g.yml", Resolved: true,
	}}, "org/repo", time.Unix(1, 0))
	if assert.Len(t, got, 1) {
		assert.Equal(t, "deploy@p.iam.gserviceaccount.com", got[0].Metadata["target_sa"])
		assert.Empty(t, got[0].Metadata["account_id"])
	}
}
