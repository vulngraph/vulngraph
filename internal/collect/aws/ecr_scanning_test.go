package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/stretchr/testify/require"
)

func TestWildcardMatch(t *testing.T) {
	for _, tt := range []struct {
		pattern, s string
		want       bool
	}{
		{"*", "team/app", true},
		{"prod-*", "prod-api", true},
		{"prod-*", "dev-api", false},
		{"team/*/api", "team/x/y/api", true},
		{"exact", "exact", true},
		{"exact", "exactly", false},
		{"a*a", "a", false},
	} {
		require.Equal(t, tt.want, wildcardMatch(tt.pattern, tt.s), "%s ~ %s", tt.pattern, tt.s)
	}
}

func TestCollectECRRepos_RegistryScanning(t *testing.T) {
	repos := []ecrtypes.Repository{
		{RepositoryName: awssdk.String("prod/api"), RepositoryArn: awssdk.String("arn:1")},
		{RepositoryName: awssdk.String("dev/api"), RepositoryArn: awssdk.String("arn:2")},
		{RepositoryName: awssdk.String("scratch"), RepositoryArn: awssdk.String("arn:3")},
	}
	f := &fakeECR{repos: repos, policyErr: errNoPolicy, registry: &ecrtypes.RegistryScanningConfiguration{
		ScanType: ecrtypes.ScanTypeEnhanced,
		Rules: []ecrtypes.RegistryScanningRule{
			{ScanFrequency: ecrtypes.ScanFrequencyScanOnPush, RepositoryFilters: []ecrtypes.ScanningRepositoryFilter{{Filter: awssdk.String("*"), FilterType: ecrtypes.ScanningRepositoryFilterTypeWildcard}}},
			{ScanFrequency: ecrtypes.ScanFrequencyContinuousScan, RepositoryFilters: []ecrtypes.ScanningRepositoryFilter{{Filter: awssdk.String("prod/*"), FilterType: ecrtypes.ScanningRepositoryFilterTypeWildcard}}},
		},
	}}
	got, err := collectECRRepos(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	by := map[string]map[string]string{}
	for _, a := range got {
		by[a.Name] = a.Metadata
	}
	require.Equal(t, "ENHANCED", by["prod/api"]["registry_scan_type"])
	require.Equal(t, "CONTINUOUS_SCAN", by["prod/api"]["registry_scan_rule"])
	require.Equal(t, "SCAN_ON_PUSH", by["dev/api"]["registry_scan_rule"])

	// A manual-only rule scans nothing.
	f.registry = &ecrtypes.RegistryScanningConfiguration{ScanType: ecrtypes.ScanTypeBasic, Rules: []ecrtypes.RegistryScanningRule{
		{ScanFrequency: ecrtypes.ScanFrequencyManual, RepositoryFilters: []ecrtypes.ScanningRepositoryFilter{{Filter: awssdk.String("*")}}},
	}}
	got, err = collectECRRepos(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Equal(t, "none", got[0].Metadata["registry_scan_rule"])

	// Unreadable registry config: keys absent, never "none".
	f.registry = nil
	got, err = collectECRRepos(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 3, "repositories are still collected")
	require.NotContains(t, got[0].Metadata, "registry_scan_rule")
	require.NotContains(t, got[0].Metadata, "registry_scan_type")
}
