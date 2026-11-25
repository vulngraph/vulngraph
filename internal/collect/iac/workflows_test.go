package iac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseWorkflow_AWSConfigureCredentials(t *testing.T) {
	yml := []byte(`
name: deploy
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::210987654321:role/gh-deploy
          aws-region: eu-west-1
`)
	got := ParseWorkflow(".github/workflows/deploy.yml", yml)
	if assert.Len(t, got, 1) {
		assert.Equal(t, "aws", got[0].Provider)
		assert.Equal(t, "arn:aws:iam::210987654321:role/gh-deploy", got[0].TargetARN)
		assert.True(t, got[0].Resolved)
		assert.Equal(t, ".github/workflows/deploy.yml", got[0].WorkflowPath)
	}
}

func TestParseWorkflow_GCPWorkloadIdentity(t *testing.T) {
	yml := []byte(`
jobs:
  d:
    steps:
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: projects/123/locations/global/workloadIdentityPools/gh/providers/gh
          service_account: deploy@my-proj.iam.gserviceaccount.com
`)
	got := ParseWorkflow(".github/workflows/gcp.yml", yml)
	if assert.Len(t, got, 1) {
		assert.Equal(t, "gcp", got[0].Provider)
		assert.Equal(t, "deploy@my-proj.iam.gserviceaccount.com", got[0].TargetSA)
		assert.True(t, got[0].Resolved)
	}
}

func TestParseWorkflow_UnresolvableExpression(t *testing.T) {
	yml := []byte(`
jobs:
  d:
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.DEPLOY_ROLE_ARN }}
`)
	got := ParseWorkflow(".github/workflows/x.yml", yml)
	if assert.Len(t, got, 1) {
		assert.Equal(t, "aws", got[0].Provider)
		assert.Empty(t, got[0].TargetARN)
		assert.False(t, got[0].Resolved) // recognised but not statically resolvable
	}
}

func TestParseWorkflow_MultipleJobsAndSteps(t *testing.T) {
	yml := []byte(`
jobs:
  a:
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with: { role-to-assume: arn:aws:iam::111:role/a }
  b:
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with: { role-to-assume: arn:aws:iam::222:role/b }
`)
	got := ParseWorkflow(".github/workflows/multi.yml", yml)
	assert.Len(t, got, 2)
}

func TestParseWorkflow_NoCloudSteps(t *testing.T) {
	yml := []byte("jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n")
	assert.Empty(t, ParseWorkflow(".github/workflows/ci.yml", yml))
}

func TestParseWorkflow_MalformedYAMLisEmpty(t *testing.T) {
	assert.Empty(t, ParseWorkflow("x.yml", []byte(":\n  - broken: [")))
}
