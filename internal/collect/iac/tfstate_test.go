package iac

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTFBackend(t *testing.T) {
	tf := []byte(`
terraform {
  backend "s3" {
    bucket = "my-state"
    key    = "prod/app.tfstate"
    region = "eu-west-1"
  }
}
`)
	got := ParseTFBackend(tf)
	assert.Equal(t, []S3Backend{{Bucket: "my-state", Key: "prod/app.tfstate"}}, got)
}

func TestParseTFBackend_NoBackend(t *testing.T) {
	tf := []byte(`
resource "aws_iam_role" "app" {
  name = "app"
}
`)
	got := ParseTFBackend(tf)
	assert.Empty(t, got)
}

func TestParseTFBackend_NonS3Ignored(t *testing.T) {
	tf := []byte(`
terraform {
  backend "gcs" {
    bucket = "my-state"
    prefix = "terraform/state"
  }
}
`)
	got := ParseTFBackend(tf)
	assert.Empty(t, got)
}

func TestParseTFResourceAddresses(t *testing.T) {
	tf := []byte(`
resource "aws_iam_role" "app" {
  name = "app"
}

resource "aws_s3_bucket" "data" {
  bucket = "data"
}
`)
	got := ParseTFResourceAddresses(tf)
	assert.Equal(t, []string{"aws_iam_role.app", "aws_s3_bucket.data"}, got)
}

func TestParseTFResourceAddresses_ExcludesDataBlocks(t *testing.T) {
	tf := []byte(`
data "aws_ami" "x" {
  most_recent = true
}

resource "aws_iam_role" "app" {}
`)
	got := ParseTFResourceAddresses(tf)
	assert.Equal(t, []string{"aws_iam_role.app"}, got)
}

func TestParseTFState(t *testing.T) {
	state := []byte(`{
  "version": 4,
  "resources": [
    {
      "mode": "managed",
      "type": "aws_iam_role",
      "name": "app",
      "instances": [
        {
          "attributes": {
            "arn": "arn:aws:iam::123456789012:role/app",
            "id": "app",
            "assume_role_policy": "...secret-policy-document...",
            "some_password": "hunter2"
          }
        }
      ]
    },
    {
      "mode": "data",
      "type": "aws_ami",
      "name": "x",
      "instances": [
        {
          "attributes": {
            "arn": "arn:aws:ec2:us-east-1::image/ami-123",
            "id": "ami-123"
          }
        }
      ]
    }
  ]
}`)
	got, err := ParseTFState(state)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, StateResource{
		Address: "aws_iam_role.app",
		ARN:     "arn:aws:iam::123456789012:role/app",
		ID:      "app",
	}, got[0])
}

// TestParseTFState_DropsNonIdentifierAttributes is the hard secrets-safety
// guarantee: tfstate attributes routinely contain plaintext secrets
// (passwords, keys, tokens). ParseTFState must extract ONLY arn+id — the
// narrow decode struct must make it structurally impossible for any other
// attribute value to reach the returned []StateResource. This test proves
// it by asserting a planted secret string is absent from the JSON-marshaled
// output, not just "not asserted on".
func TestParseTFState_DropsNonIdentifierAttributes(t *testing.T) {
	const planted = "PLANTED-VALUE-MUST-NOT-LEAK"
	state := []byte(`{
  "resources": [
    {
      "mode": "managed",
      "type": "aws_db_instance",
      "name": "primary",
      "instances": [
        {
          "attributes": {
            "arn": "arn:aws:rds:us-east-1:123456789012:db:primary",
            "id": "primary",
            "master_password": "` + planted + `",
            "endpoint": "primary.abc123.us-east-1.rds.amazonaws.com"
          }
        }
      ]
    }
  ]
}`)
	got, err := ParseTFState(state)
	require.NoError(t, err)
	require.Len(t, got, 1)

	out, err := json.Marshal(got)
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(out), planted), "secret leaked into ParseTFState output: %s", out)
}

// A state object that is not JSON (truncated, HTML error page, wrong object) is
// an error, not an empty state: an empty result would read as "this repo's
// Terraform manages nothing".
func TestParseTFState_MalformedIsAnError(t *testing.T) {
	for _, in := range []string{`{"resources": [`, `<html>denied</html>`, ``} {
		got, err := ParseTFState([]byte(in))
		require.Error(t, err, "%q", in)
		assert.Nil(t, got)
	}
}

func TestParseTFState_NoResources(t *testing.T) {
	got, err := ParseTFState([]byte(`{"resources": []}`))
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestParseTFState_MultipleInstances(t *testing.T) {
	state := []byte(`{
  "resources": [
    {
      "mode": "managed",
      "type": "aws_iam_role",
      "name": "app",
      "instances": [
        {"attributes": {"arn": "arn:1", "id": "app-0"}},
        {"attributes": {"arn": "arn:2", "id": "app-1"}}
      ]
    }
  ]
}`)
	got, err := ParseTFState(state)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "app-0", got[0].ID)
	assert.Equal(t, "app-1", got[1].ID)
}
