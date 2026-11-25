package iac

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectDeclaredTF(t *testing.T) {
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)

	t.Run("resource with arn gets target_arn and account_id", func(t *testing.T) {
		resources := []StateResource{
			{Address: "aws_iam_role.app", ARN: "arn:aws:iam::123456789012:role/app"},
		}
		assets := ProjectDeclaredTF(resources, "org/repo", now)
		require.Len(t, assets, 1)
		a := assets[0]
		assert.Equal(t, "declared_tf_resource", a.Type)
		assert.Equal(t, "org/repo", a.Metadata["repo"])
		assert.Equal(t, "aws_iam_role.app", a.Metadata["address"])
		assert.Equal(t, "arn:aws:iam::123456789012:role/app", a.Metadata["target_arn"])
		assert.Equal(t, "123456789012", a.Metadata["account_id"])
		assert.NotContains(t, a.Metadata, "target_id")
		assert.Equal(t, "declared_tf_resource:org/repo:aws_iam_role.app", a.ID)
	})

	t.Run("resource with only id gets target_id, no account_id", func(t *testing.T) {
		resources := []StateResource{
			{Address: "aws_s3_bucket.data", ID: "my-bucket"},
		}
		assets := ProjectDeclaredTF(resources, "org/repo", now)
		require.Len(t, assets, 1)
		a := assets[0]
		assert.Equal(t, "my-bucket", a.Metadata["target_id"])
		assert.NotContains(t, a.Metadata, "target_arn")
		assert.NotContains(t, a.Metadata, "account_id")
	})

	t.Run("resource with neither arn nor id is dropped", func(t *testing.T) {
		resources := []StateResource{{Address: "aws_iam_role.orphan"}}
		assets := ProjectDeclaredTF(resources, "org/repo", now)
		assert.Empty(t, assets)
	})
}
