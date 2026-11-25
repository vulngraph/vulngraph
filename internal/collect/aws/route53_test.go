package aws

import (
	"context"
	"fmt"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// fakeRoute53 returns one zone and paginated record sets, recording the
// pagination markers it was called with so the test can assert both
// StartRecordName AND StartRecordType are threaded (paging on the name alone
// can skip or repeat record sets that share a name across types).
type fakeRoute53 struct {
	recordPages []*route53.ListResourceRecordSetsOutput
	call        int
	gotNames    []string
	gotTypes    []r53types.RRType
	// logged are the zone IDs ListQueryLoggingConfigs reports; logErr fails it.
	logged []string
	logErr error
}

func (f *fakeRoute53) ListQueryLoggingConfigs(context.Context, *route53.ListQueryLoggingConfigsInput, ...func(*route53.Options)) (*route53.ListQueryLoggingConfigsOutput, error) {
	if f.logErr != nil {
		return nil, f.logErr
	}
	out := &route53.ListQueryLoggingConfigsOutput{}
	for _, id := range f.logged {
		out.QueryLoggingConfigs = append(out.QueryLoggingConfigs, r53types.QueryLoggingConfig{HostedZoneId: awssdk.String(id)})
	}
	return out, nil
}

func (f *fakeRoute53) ListHostedZones(context.Context, *route53.ListHostedZonesInput, ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	return &route53.ListHostedZonesOutput{
		HostedZones: []r53types.HostedZone{{
			Id:     awssdk.String("/hostedzone/Z1"),
			Name:   awssdk.String("example.com."),
			Config: &r53types.HostedZoneConfig{PrivateZone: false},
		}},
	}, nil
}

func (f *fakeRoute53) ListResourceRecordSets(_ context.Context, in *route53.ListResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	f.gotNames = append(f.gotNames, awssdk.ToString(in.StartRecordName))
	f.gotTypes = append(f.gotTypes, in.StartRecordType)
	out := f.recordPages[f.call]
	f.call++
	return out, nil
}

// fakeRoute53TwoZones returns two zones; ListResourceRecordSets errors for the
// first zone and succeeds for the second, so the test can assert one zone's
// record failure does not sink the whole collector (and hence the account sync).
type fakeRoute53TwoZones struct {
	errZoneID string
}

func (f *fakeRoute53TwoZones) ListQueryLoggingConfigs(context.Context, *route53.ListQueryLoggingConfigsInput, ...func(*route53.Options)) (*route53.ListQueryLoggingConfigsOutput, error) {
	return &route53.ListQueryLoggingConfigsOutput{}, nil
}

func (f *fakeRoute53TwoZones) ListHostedZones(context.Context, *route53.ListHostedZonesInput, ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	return &route53.ListHostedZonesOutput{
		HostedZones: []r53types.HostedZone{
			{Id: awssdk.String("/hostedzone/Zbad"), Name: awssdk.String("bad.com."), Config: &r53types.HostedZoneConfig{PrivateZone: false}},
			{Id: awssdk.String("/hostedzone/Zgood"), Name: awssdk.String("good.com."), Config: &r53types.HostedZoneConfig{PrivateZone: false}},
		},
	}, nil
}

func (f *fakeRoute53TwoZones) ListResourceRecordSets(_ context.Context, in *route53.ListResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	if awssdk.ToString(in.HostedZoneId) == f.errZoneID {
		return nil, fmt.Errorf("AccessDenied: not authorized to list records for this zone")
	}
	return &route53.ListResourceRecordSetsOutput{
		ResourceRecordSets: []r53types.ResourceRecordSet{{
			Name: awssdk.String("www.good.com."), Type: r53types.RRTypeA,
			ResourceRecords: []r53types.ResourceRecord{{Value: awssdk.String("9.9.9.9")}},
		}},
	}, nil
}

// TestRoute53Retryer_WidensBeyondSDKDefault pins the fix for a
// regression: fanning out route53ZoneConcurrency zones with the SDK's default
// 3-attempt retryer reliably tripped Route53's real account-level throttle
// (5 req/s, far tighter than S3's) and permanently skipped zones on
// an account with many of them. The retryer must widen both knobs, not just one — a wider
// MaxAttempts with the default 20s MaxBackoff cap still exhausts too fast
// under sustained throttling, and a wider MaxBackoff with the default 3
// attempts never gets to use it.
func TestRoute53Retryer_WidensBeyondSDKDefault(t *testing.T) {
	var opts route53.Options
	route53Retryer()(&opts)
	require.NotNil(t, opts.Retryer)

	std, ok := opts.Retryer.(*retry.Standard)
	require.True(t, ok, "expected a *retry.Standard so MaxAttempts is inspectable")
	require.Greater(t, std.MaxAttempts(), retry.DefaultMaxAttempts,
		"must exceed the SDK's default 3 attempts — that default is what exhausted after triggering Route53's own throttle")
}

// TestRoute53Retryer_SurvivesAmbientMaxAttempts pins a gap in the retryer
// wiring above: route53.New (run by NewFromConfig right after
// every functional option) calls finalizeRetryMaxAttempts, which — only when
// Options.RetryMaxAttempts != 0 — wraps whatever Retryer is already set in
// retry.AddWithMaxAttempts, silently overriding route53Retryer's 8 back down
// to that ambient value. RetryMaxAttempts resolves from AWS_MAX_ATTEMPTS (or
// a shared-config max_attempts) — exactly what this package's own
// noNetworkCfg test helper sets (to 1, for a different reason: fast-failing
// unit tests), proving the mechanism is real, not hypothetical. This test
// drives the REAL route53.NewFromConfig construction path (unlike the test
// above, which only calls route53Retryer against a bare Options{} and so
// cannot see finalizeRetryMaxAttempts run at all) with AWS_MAX_ATTEMPTS set,
// and asserts the widened retryer survives intact.
func TestRoute53Retryer_SurvivesAmbientMaxAttempts(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_MAX_ATTEMPTS", "1")

	awsCfg, err := baseConfig(context.Background(), map[string]string{
		"region": "eu-west-1", "aws_access_key_id": "test", "aws_secret_access_key": "test",
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, awsCfg.RetryMaxAttempts, "sanity: the ambient env var did resolve onto the loaded config")

	client := route53.NewFromConfig(awsCfg, route53Retryer())
	std, ok := client.Options().Retryer.(*retry.Standard)
	require.True(t, ok,
		"the real client's Retryer must still be our *retry.Standard — a retry.withMaxAttempts wrapper here means "+
			"finalizeRetryMaxAttempts silently overrode it back down to the ambient AWS_MAX_ATTEMPTS value")
	require.Equal(t, 8, std.MaxAttempts())
}

// One zone's record listing failing must not discard the other zones' records or
// error the whole collector — that would sink the entire account sync (fixed).
func TestCollectDNSRecords_SkipsZoneOnRecordError(t *testing.T) {
	fake := &fakeRoute53TwoZones{errZoneID: "/hostedzone/Zbad"}
	assets, _, partial, err := collectDNSRecords(context.Background(), fake, "acct-1", time.Now())
	require.NoError(t, err, "a per-zone record error is skipped, not fatal")
	require.True(t, partial, "a per-zone record failure must flag partial so the account isn't read as having deleted those records")

	var gotRecord, gotBadZone, gotGoodZone bool
	for _, a := range assets {
		switch {
		case a.Type == "dns_record" && a.Name == "www.good.com":
			gotRecord = true
		case a.Type == "dns_zone" && a.Metadata["zone_id"] == "/hostedzone/Zbad":
			gotBadZone = true // zone asset still emitted even though its records failed
		case a.Type == "dns_zone" && a.Metadata["zone_id"] == "/hostedzone/Zgood":
			gotGoodZone = true
		}
	}
	require.True(t, gotRecord, "the healthy zone's records are still collected")
	require.True(t, gotBadZone, "the failing zone is still inventoried as a zone")
	require.True(t, gotGoodZone)
}

func TestCollectDNSRecords_PaginatesWithNameAndType(t *testing.T) {
	fake := &fakeRoute53{
		recordPages: []*route53.ListResourceRecordSetsOutput{
			{
				ResourceRecordSets: []r53types.ResourceRecordSet{{
					Name: awssdk.String("a.example.com."), Type: r53types.RRTypeA,
					ResourceRecords: []r53types.ResourceRecord{{Value: awssdk.String("1.2.3.4")}},
				}},
				IsTruncated:    true,
				NextRecordName: awssdk.String("b.example.com."),
				NextRecordType: r53types.RRTypeCname,
			},
			{
				ResourceRecordSets: []r53types.ResourceRecordSet{{
					Name: awssdk.String("b.example.com."), Type: r53types.RRTypeCname,
					ResourceRecords: []r53types.ResourceRecord{{Value: awssdk.String("target.example.net")}},
				}},
			},
		},
	}

	assets, edges, partial, err := collectDNSRecords(context.Background(), fake, "123456789012", time.Now())
	require.NoError(t, err)
	require.False(t, partial)
	// 2 dns_record assets + 1 dns_zone asset
	require.Len(t, assets, 3)
	require.Len(t, edges, 2)

	// Second call must carry BOTH markers from the first page's Next* fields.
	require.Equal(t, 2, fake.call)
	require.Equal(t, "b.example.com.", fake.gotNames[1])
	require.Equal(t, r53types.RRTypeCname, fake.gotTypes[1])

	// assets[0] is the dns_zone; dns_records follow.
	require.Equal(t, "dns_zone", assets[0].Type)
	require.Equal(t, "aws-zone:/hostedzone/Z1", assets[0].ID)
	require.Equal(t, "dns_record", assets[1].Type)
	require.Equal(t, "1.2.3.4", assets[1].Metadata["values"])
	require.Equal(t, "target.example.net", assets[2].Metadata["values"])
	require.Equal(t, "member_of_zone", edges[0].EdgeType)
	require.Equal(t, "aws-zone:/hostedzone/Z1", edges[0].DstID)
}

func TestCollectDNSRecordsStampsZoneQueryLogging(t *testing.T) {
	zone := func(assets []asset.Asset) asset.Asset {
		for _, a := range assets {
			if a.Type == "dns_zone" {
				return a
			}
		}
		t.Fatal("no dns_zone asset")
		return asset.Asset{}
	}
	page := func() []*route53.ListResourceRecordSetsOutput {
		return []*route53.ListResourceRecordSetsOutput{{}}
	}

	got, _, _, err := collectDNSRecords(context.Background(), &fakeRoute53{recordPages: page(), logged: []string{"Z1"}}, "111", time.Now())
	require.NoError(t, err)
	require.Equal(t, "true", zone(got).Metadata["query_logging"], "the listing's bare zone ID matches the prefixed one")
	require.Equal(t, "false", zone(got).Metadata["private_zone"])

	got, _, _, err = collectDNSRecords(context.Background(), &fakeRoute53{recordPages: page()}, "111", time.Now())
	require.NoError(t, err)
	require.Equal(t, "false", zone(got).Metadata["query_logging"])

	got, _, _, err = collectDNSRecords(context.Background(), &fakeRoute53{recordPages: page(), logErr: fmt.Errorf("AccessDenied")}, "111", time.Now())
	require.NoError(t, err, "query logging is one fact, not the zone inventory")
	require.NotContains(t, zone(got).Metadata, "query_logging", "an unread listing is unknown, never unlogged")
}
