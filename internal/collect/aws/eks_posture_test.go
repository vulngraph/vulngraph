package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/stretchr/testify/require"
)

func TestCollectEKSClusters_SecretsEncryptionAndAuditLogging(t *testing.T) {
	enc := fullEKSCluster()
	enc.Name, enc.Arn = awssdk.String("enc"), awssdk.String("arn:aws:eks:eu-west-1:111:cluster/enc")
	enc.EncryptionConfig = []ekstypes.EncryptionConfig{{
		Provider:  &ekstypes.Provider{KeyArn: awssdk.String("arn:aws:kms:eu-west-1:111:key/k")},
		Resources: []string{"secrets"},
	}}
	enc.Logging = &ekstypes.Logging{ClusterLogging: []ekstypes.LogSetup{
		{Enabled: awssdk.Bool(true), Types: []ekstypes.LogType{ekstypes.LogTypeApi, ekstypes.LogTypeAudit}},
		{Enabled: awssdk.Bool(false), Types: []ekstypes.LogType{ekstypes.LogTypeScheduler}},
	}}

	plain := fullEKSCluster()
	plain.Name, plain.Arn = awssdk.String("plain"), awssdk.String("arn:aws:eks:eu-west-1:111:cluster/plain")
	// Audit listed only under the DISABLED setup is not shipped.
	plain.Logging = &ekstypes.Logging{ClusterLogging: []ekstypes.LogSetup{
		{Enabled: awssdk.Bool(false), Types: []ekstypes.LogType{ekstypes.LogTypeAudit}},
	}}

	noLogging := fullEKSCluster()
	noLogging.Name, noLogging.Arn = awssdk.String("unread"), awssdk.String("arn:aws:eks:eu-west-1:111:cluster/unread")

	f := &fakeEKS{names: []string{"enc", "plain", "unread"}, clusters: map[string]*ekstypes.Cluster{
		"enc": enc, "plain": plain, "unread": noLogging,
	}}
	got, _, err := collectEKSClusters(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 3)
	by := map[string]map[string]string{}
	for _, a := range got {
		by[a.Name] = a.Metadata
	}
	require.Equal(t, "true", by["enc"]["secrets_encryption"])
	require.Equal(t, "true", by["enc"]["audit_logging"])
	require.Equal(t, "false", by["plain"]["secrets_encryption"])
	require.Equal(t, "false", by["plain"]["audit_logging"])
	require.NotContains(t, by["unread"], "audit_logging", "no Logging block: the setting was not observed")
	require.Equal(t, "authenticator,controllerManager,scheduler", by["enc"]["logging_disabled_types"])
	require.Equal(t, "api,audit,authenticator,controllerManager,scheduler", by["plain"]["logging_disabled_types"])
	require.NotContains(t, by["unread"], "logging_disabled_types")

	all := &ekstypes.Logging{ClusterLogging: []ekstypes.LogSetup{{Enabled: awssdk.Bool(true), Types: ekstypes.LogType("").Values()}}}
	require.Empty(t, eksDisabledLogTypes(all), "every type shipping is observed as none disabled")
}
