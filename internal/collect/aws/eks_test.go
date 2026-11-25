package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/stretchr/testify/require"
)

// fullEKSCluster is a cluster described with every field the collector reads.
func fullEKSCluster() *ekstypes.Cluster {
	return &ekstypes.Cluster{
		Name:            awssdk.String("prod"),
		Arn:             awssdk.String("arn:aws:eks:eu-west-1:111:cluster/prod"),
		Version:         awssdk.String("1.30"),
		PlatformVersion: awssdk.String("eks.8"),
		Status:          ekstypes.ClusterStatusActive,
		Endpoint:        awssdk.String("https://abc.eks.eu-west-1.amazonaws.com"),
		Identity: &ekstypes.Identity{Oidc: &ekstypes.OIDC{
			Issuer: awssdk.String("https://oidc.eks.eu-west-1.amazonaws.com/id/ABCDEF"),
		}},
		ResourcesVpcConfig: &ekstypes.VpcConfigResponse{
			EndpointPublicAccess:  true,
			EndpointPrivateAccess: true,
			PublicAccessCidrs:     []string{"0.0.0.0/0"},
		},
		AccessConfig: &ekstypes.AccessConfigResponse{
			AuthenticationMode:                      ekstypes.AuthenticationModeApiAndConfigMap,
			BootstrapClusterCreatorAdminPermissions: awssdk.Bool(true),
		},
	}
}

// The OIDC issuer is the join key to IRSA roles: the emitted provider ARN must
// equal, byte for byte, the `federated_provider` an IAM role's trust policy
// yields, so the correlator can join on string equality with no parsing.
func TestCollectEKSClusters_OIDCIssuerAndProviderARN(t *testing.T) {
	f := &fakeEKS{names: []string{"prod"}, clusters: map[string]*ekstypes.Cluster{"prod": fullEKSCluster()}}

	got, _, err := collectEKSClusters(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 1)

	require.Equal(t, "https://oidc.eks.eu-west-1.amazonaws.com/id/ABCDEF", got[0].Metadata["oidc_issuer"])
	require.Equal(t,
		"arn:aws:iam::111:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/ABCDEF",
		got[0].Metadata["oidc_provider_arn"])
}

func TestCollectEKSClusters_EndpointAndAuthPosture(t *testing.T) {
	f := &fakeEKS{names: []string{"prod"}, clusters: map[string]*ekstypes.Cluster{"prod": fullEKSCluster()}}

	got, _, err := collectEKSClusters(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 1)
	m := got[0].Metadata

	require.Equal(t, "true", m["endpoint_public_access"])
	require.Equal(t, "true", m["endpoint_private_access"])
	require.Equal(t, "0.0.0.0/0", m["public_access_cidrs"])
	require.Equal(t, "possible", m["public_access"])
	require.Equal(t, "API_AND_CONFIG_MAP", m["authentication_mode"])
	require.Equal(t, "true", m["bootstrap_cluster_creator_admin"])
	require.Equal(t, "ACTIVE", m["status"])
	require.Equal(t, "eks.8", m["platform_version"])
}

// A public endpoint restricted to corporate CIDRs is not internet-exposed.
func TestCollectEKSClusters_RestrictedPublicEndpointIsNotPublic(t *testing.T) {
	c := fullEKSCluster()
	c.ResourcesVpcConfig.PublicAccessCidrs = []string{"10.0.0.0/8", "203.0.113.4/32"}
	f := &fakeEKS{names: []string{"prod"}, clusters: map[string]*ekstypes.Cluster{"prod": c}}

	got, _, err := collectEKSClusters(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.NotContains(t, got[0].Metadata, "public_access")
	require.Equal(t, "true", got[0].Metadata["endpoint_public_access"])
}

// Unknown must stay unknown: an undescribed field is an OMITTED key, never a
// fabricated "false"/"none".
func TestCollectEKSClusters_UnobservedFieldsAreOmitted(t *testing.T) {
	f := &fakeEKS{names: []string{"bare"}, clusters: map[string]*ekstypes.Cluster{
		"bare": {
			Name: awssdk.String("bare"),
			Arn:  awssdk.String("arn:aws:eks:eu-west-1:111:cluster/bare"),
		},
	}}

	got, _, err := collectEKSClusters(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 1)
	for _, k := range []string{
		"oidc_issuer", "oidc_provider_arn", "authentication_mode",
		"bootstrap_cluster_creator_admin", "endpoint_public_access",
		"endpoint_private_access", "public_access_cidrs", "public_access",
		"version", "platform_version", "status",
	} {
		require.NotContains(t, got[0].Metadata, k, "key %q must be omitted when unobserved", k)
	}
}

// A DescribeCluster failure must NOT drop the cluster: ListClusters already
// observed that it exists, and dropping it makes a transient throttle look like
// a deletion to sync reconciliation.
func TestCollectEKSClusters_DescribeFailureKeepsClusterInInventory(t *testing.T) {
	f := &fakeEKS{
		names: []string{"ok", "undescribable"},
		clusters: map[string]*ekstypes.Cluster{
			"ok": {
				Name: awssdk.String("ok"),
				Arn:  awssdk.String("arn:aws:eks:eu-west-1:111:cluster/ok"),
			},
		},
	}

	got, _, err := collectEKSClusters(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 2, "the undescribable cluster must still be inventoried")

	byName := map[string]int{}
	for i, a := range got {
		byName[a.Name] = i
	}
	bad := got[byName["undescribable"]]
	require.Equal(t, "eks_cluster", bad.Type)
	require.Equal(t, "arn:aws:eks:eu-west-1:111:cluster/undescribable", bad.ID)
	require.Equal(t, "true", bad.Metadata["describe_failed"])
	// Nothing describe-derived may be invented for it.
	require.NotContains(t, bad.Metadata, "endpoint_public_access")
	require.NotContains(t, bad.Metadata, "oidc_issuer")
	require.Empty(t, bad.Endpoint)
}

func TestOIDCProviderARN(t *testing.T) {
	tests := []struct {
		name, region, accountID, issuer, want string
	}{
		{"https stripped", "eu-west-1", "111", "https://oidc.eks.eu-west-1.amazonaws.com/id/ABC",
			"arn:aws:iam::111:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/ABC"},
		{"trailing slash trimmed", "us-east-1", "111", "https://oidc.eks.us-east-1.amazonaws.com/id/XYZ/",
			"arn:aws:iam::111:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/XYZ"},
		{"govcloud partition", "us-gov-west-1", "111", "https://oidc.eks.us-gov-west-1.amazonaws.com/id/G",
			"arn:aws-us-gov:iam::111:oidc-provider/oidc.eks.us-gov-west-1.amazonaws.com/id/G"},
		{"unknown account yields nothing", "eu-west-1", "", "https://oidc.eks.eu-west-1.amazonaws.com/id/ABC", ""},
		{"empty issuer yields nothing", "eu-west-1", "111", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, oidcProviderARN(tt.region, tt.accountID, tt.issuer))
		})
	}
}

func TestAnyOpenCIDR(t *testing.T) {
	require.True(t, anyOpenCIDR([]string{"10.0.0.0/8", "0.0.0.0/0"}))
	require.True(t, anyOpenCIDR([]string{"::/0"}))
	require.False(t, anyOpenCIDR([]string{"10.0.0.0/8"}))
	require.False(t, anyOpenCIDR(nil))
}

func TestEKSClusterARN(t *testing.T) {
	require.Equal(t, "arn:aws:eks:eu-west-1:111:cluster/prod", eksClusterARN("eu-west-1", "111", "prod"))
	require.Equal(t, "arn:aws-cn:eks:cn-north-1:111:cluster/prod", eksClusterARN("cn-north-1", "111", "prod"))
	require.Empty(t, eksClusterARN("eu-west-1", "", "prod"))
	require.Empty(t, eksClusterARN("", "111", "prod"))
}
