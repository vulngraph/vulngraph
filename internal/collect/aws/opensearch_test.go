package aws

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	ostypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeOpenSearch struct {
	domains     map[string]ostypes.DomainStatus
	order       []string
	listErr     error
	describeErr error
	calls       [][]string
}

func (f *fakeOpenSearch) ListDomainNames(context.Context, *opensearch.ListDomainNamesInput, ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := &opensearch.ListDomainNamesOutput{}
	for _, n := range f.order {
		out.DomainNames = append(out.DomainNames, ostypes.DomainInfo{DomainName: awssdk.String(n)})
	}
	return out, nil
}

func (f *fakeOpenSearch) DescribeDomains(_ context.Context, in *opensearch.DescribeDomainsInput, _ ...func(*opensearch.Options)) (*opensearch.DescribeDomainsOutput, error) {
	f.calls = append(f.calls, in.DomainNames)
	if len(in.DomainNames) > openSearchDescribeBatch {
		return nil, errors.New("ValidationException: too many domains")
	}
	if f.describeErr != nil && len(f.calls) > 1 {
		return nil, f.describeErr
	}
	out := &opensearch.DescribeDomainsOutput{}
	for _, n := range in.DomainNames {
		out.DomainStatusList = append(out.DomainStatusList, f.domains[n])
	}
	return out, nil
}

const openSearchOpenPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"es:*","Resource":"arn:aws:es:eu-west-1:111122223333:domain/logs/*"}]}`

// hardenedDomain is a fully compliant VPC OpenSearch domain.
func hardenedDomain(name string) ostypes.DomainStatus {
	return ostypes.DomainStatus{
		ARN:           awssdk.String("arn:aws:es:eu-west-1:111122223333:domain/" + name),
		DomainName:    awssdk.String(name),
		EngineVersion: awssdk.String("OpenSearch_2.11"),
		Endpoints:     map[string]string{"vpc": "vpc-" + name + ".es.amazonaws.com"},
		VPCOptions: &ostypes.VPCDerivedInfo{
			VPCId: awssdk.String("vpc-1"), SubnetIds: []string{"subnet-1"},
		},
		EncryptionAtRestOptions:     &ostypes.EncryptionAtRestOptions{Enabled: awssdk.Bool(true)},
		NodeToNodeEncryptionOptions: &ostypes.NodeToNodeEncryptionOptions{Enabled: awssdk.Bool(true)},
		DomainEndpointOptions: &ostypes.DomainEndpointOptions{
			EnforceHTTPS: awssdk.Bool(true), TLSSecurityPolicy: ostypes.TLSSecurityPolicyPolicyMinTls12Pfs202310,
		},
		LogPublishingOptions: map[string]ostypes.LogPublishingOption{
			"ES_APPLICATION_LOGS": {Enabled: awssdk.Bool(true), CloudWatchLogsLogGroupArn: awssdk.String("arn:aws:logs:eu-west-1:111122223333:log-group:err")},
			"AUDIT_LOGS":          {Enabled: awssdk.Bool(true), CloudWatchLogsLogGroupArn: awssdk.String("arn:aws:logs:eu-west-1:111122223333:log-group:audit")},
		},
		ClusterConfig: &ostypes.ClusterConfig{
			InstanceCount: awssdk.Int32(3), ZoneAwarenessEnabled: awssdk.Bool(true),
			DedicatedMasterEnabled: awssdk.Bool(true), DedicatedMasterCount: awssdk.Int32(3),
		},
		AdvancedSecurityOptions: &ostypes.AdvancedSecurityOptions{Enabled: awssdk.Bool(true)},
		ServiceSoftwareOptions:  &ostypes.ServiceSoftwareOptions{UpdateAvailable: awssdk.Bool(false)},
		AccessPolicies:          awssdk.String(openSearchOpenPolicy),
	}
}

func collectOneOpenSearchDomain(t *testing.T, d ostypes.DomainStatus) map[string]string {
	t.Helper()
	n := awssdk.ToString(d.DomainName)
	got, err := collectOpenSearchDomains(context.Background(), &fakeOpenSearch{domains: map[string]ostypes.DomainStatus{n: d}, order: []string{n}}, "eu-west-1", "111122223333", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "opensearch_domain", got[0].Type)
	require.Equal(t, awssdk.ToString(d.ARN), got[0].ID)
	return got[0].Metadata
}

func TestOpenSearchHardenedVPCDomain(t *testing.T) {
	m := collectOneOpenSearchDomain(t, hardenedDomain("logs"))
	require.Equal(t, map[string]string{
		"engine": "OpenSearch", "engine_version": "OpenSearch_2.11",
		"in_vpc": "true", "vpc_id": "vpc-1",
		"encryption_at_rest": "true", "node_to_node_encryption": "true",
		"enforce_https": "true", "tls_security_policy": "Policy-Min-TLS-1-2-PFS-2023-10",
		"error_logs_enabled": "true", "audit_logs_enabled": "true",
		"search_slow_logs_enabled": "false", "index_slow_logs_enabled": "false",
		"instance_count": "3", "zone_awareness": "true",
		"dedicated_master_enabled": "true", "dedicated_master_count": "3",
		"fine_grained_access_control":       "true",
		"service_software_update_available": "false",
		// An open policy on a VPC domain is not internet exposure.
		"access_policy_public": "true",
		"public_access":        asset.PublicAccessNone,
		"policies":             m["policies"],
	}, m)
	require.NotEmpty(t, m["policies"])
}

func TestOpenSearchExposureTiers(t *testing.T) {
	public := func(mut func(*ostypes.DomainStatus)) map[string]string {
		d := hardenedDomain("pub")
		d.VPCOptions = nil
		d.Endpoint = awssdk.String("search-pub.es.amazonaws.com")
		mut(&d)
		return collectOneOpenSearchDomain(t, d)
	}
	// Open policy, no FGAC: anyone on the internet can read and write.
	m := public(func(d *ostypes.DomainStatus) { d.AdvancedSecurityOptions = nil })
	require.Equal(t, "false", m["in_vpc"])
	require.Equal(t, asset.PublicAccessConfirmed, m["public_access"])
	require.Equal(t, "false", m["fine_grained_access_control"], "no AdvancedSecurityOptions is the API saying FGAC is off")

	// Open policy, FGAC authenticating every request: reachable, credential-gated.
	m = public(func(*ostypes.DomainStatus) {})
	require.Equal(t, asset.PublicAccessPossible, m["public_access"])

	// FGAC with anonymous auth lets unauthenticated requests through.
	m = public(func(d *ostypes.DomainStatus) { d.AdvancedSecurityOptions.AnonymousAuthEnabled = awssdk.Bool(true) })
	require.Equal(t, asset.PublicAccessConfirmed, m["public_access"])

	// An IP-conditioned policy restricts the open grant.
	m = public(func(d *ostypes.DomainStatus) {
		d.AdvancedSecurityOptions = nil
		d.AccessPolicies = awssdk.String(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"es:ESHttp*","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}]}`)
	})
	require.Equal(t, asset.PublicAccessPossible, m["public_access"])
	require.Equal(t, "false", m["access_policy_public"])

	// A public grant of a configuration read only is not data access.
	m = public(func(d *ostypes.DomainStatus) {
		d.AdvancedSecurityOptions = nil
		d.AccessPolicies = awssdk.String(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"es:DescribeDomain","Resource":"*"}]}`)
	})
	require.Equal(t, asset.PublicAccessPossible, m["public_access"])

	// No policy at all denies everyone but the owner's IAM principals.
	m = public(func(d *ostypes.DomainStatus) { d.AdvancedSecurityOptions = nil; d.AccessPolicies = nil })
	require.Equal(t, asset.PublicAccessPossible, m["public_access"])
	require.NotContains(t, m, "policies")
}

func TestOpenSearchOmittedBlocksStayUnknown(t *testing.T) {
	d := ostypes.DomainStatus{
		ARN:           awssdk.String("arn:aws:es:eu-west-1:111122223333:domain/old"),
		DomainName:    awssdk.String("old"),
		EngineVersion: awssdk.String("Elasticsearch_5.6"),
	}
	m := collectOneOpenSearchDomain(t, d)
	require.Equal(t, "Elasticsearch", m["engine"])
	for _, k := range []string{
		"encryption_at_rest", "node_to_node_encryption", "enforce_https", "tls_security_policy",
		"instance_count", "zone_awareness", "dedicated_master_enabled", "dedicated_master_count",
		"service_software_update_available",
	} {
		require.NotContains(t, m, k, "an omitted option block is unknown, not off")
	}
	// Omissions that ARE the API's answer.
	require.Equal(t, "false", m["in_vpc"])
	require.Equal(t, "false", m["error_logs_enabled"])
	require.Equal(t, "false", m["audit_logs_enabled"])
	require.Equal(t, "false", m["fine_grained_access_control"])
}

func TestOpenSearchLogPublishedNeedsALogGroup(t *testing.T) {
	d := hardenedDomain("logs")
	d.LogPublishingOptions = map[string]ostypes.LogPublishingOption{
		"ES_APPLICATION_LOGS": {Enabled: awssdk.Bool(true)},
		"AUDIT_LOGS":          {Enabled: awssdk.Bool(false), CloudWatchLogsLogGroupArn: awssdk.String("arn:aws:logs:eu-west-1:1:log-group:a")},
	}
	m := collectOneOpenSearchDomain(t, d)
	require.Equal(t, "false", m["error_logs_enabled"])
	require.Equal(t, "false", m["audit_logs_enabled"])
}

func TestOpenSearchSlowLogKeys(t *testing.T) {
	group := awssdk.String("arn:aws:logs:eu-west-1:1:log-group:slow")
	d := hardenedDomain("slow")
	d.LogPublishingOptions = map[string]ostypes.LogPublishingOption{
		"SEARCH_SLOW_LOGS": {Enabled: awssdk.Bool(true), CloudWatchLogsLogGroupArn: group},
		"INDEX_SLOW_LOGS":  {Enabled: awssdk.Bool(false), CloudWatchLogsLogGroupArn: group},
	}
	m := collectOneOpenSearchDomain(t, d)
	require.Equal(t, "true", m["search_slow_logs_enabled"])
	require.Equal(t, "false", m["index_slow_logs_enabled"])
}

func TestOpenSearchDescribesInBatchesAndFailsWhole(t *testing.T) {
	f := &fakeOpenSearch{domains: map[string]ostypes.DomainStatus{}}
	for i := range 7 {
		n := fmt.Sprintf("d%d", i)
		f.order = append(f.order, n)
		f.domains[n] = hardenedDomain(n)
	}
	got, err := collectOpenSearchDomains(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 7)
	require.Len(t, f.calls, 2)
	require.Len(t, f.calls[0], 5)

	// A failed second batch is a failed listing, not a short one.
	f.calls = nil
	f.describeErr = errors.New("ThrottlingException")
	_, err = collectOpenSearchDomains(context.Background(), f, "eu-west-1", "1", time.Now())
	require.Error(t, err)

	_, err = collectOpenSearchDomains(context.Background(), &fakeOpenSearch{listErr: errors.New("AccessDenied")}, "eu-west-1", "1", time.Now())
	require.Error(t, err)

	// No domains: no describe call, no assets.
	empty := &fakeOpenSearch{}
	got, err = collectOpenSearchDomains(context.Background(), empty, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Empty(t, got)
	require.Empty(t, empty.calls)
}

func TestOpenSearchSkipsDeletedDomains(t *testing.T) {
	d := hardenedDomain("gone")
	d.Deleted = awssdk.Bool(true)
	got, err := collectOpenSearchDomains(context.Background(), &fakeOpenSearch{domains: map[string]ostypes.DomainStatus{"gone": d}, order: []string{"gone"}}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Empty(t, got)
}
