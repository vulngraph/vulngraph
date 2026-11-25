package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/stretchr/testify/require"
)

func TestCollectECRRepos_LifecyclePolicy(t *testing.T) {
	repos := []ecrtypes.Repository{
		{RepositoryName: awssdk.String("kept"), RepositoryArn: awssdk.String("arn:kept")},
		{RepositoryName: awssdk.String("forever"), RepositoryArn: awssdk.String("arn:forever")},
	}
	got, err := collectECRRepos(context.Background(), &fakeECR{
		repos: repos, policyErr: errNoPolicy,
		lifecycle: map[string]string{"kept": `{"rules":[{"rulePriority":1}]}`},
	}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Equal(t, "true", got[0].Metadata["lifecycle_policy"])
	require.Equal(t, "false", got[1].Metadata["lifecycle_policy"], "LifecyclePolicyNotFoundException is the observed no-policy case")

	got, err = collectECRRepos(context.Background(), &fakeECR{
		repos: repos, policyErr: errNoPolicy, lifecycleErr: errors.New("AccessDeniedException"),
	}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 2, "an unreadable lifecycle policy keeps the repository")
	for _, r := range got {
		require.NotContains(t, r.Metadata, "lifecycle_policy", "a denied read is unknown, never 'no policy'")
	}
}
