package aws

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// sdkDNSErr is the error chain the SDK returns when a host does not resolve:
// OperationError → RequestSendError → url.Error → OpError → DNSError.
func sdkDNSErr(host string, notFound bool) error {
	dns := &net.DNSError{Err: "no such host", Name: host, IsNotFound: notFound, IsTemporary: !notFound}
	return fmt.Errorf("collectX: %w", &smithy.OperationError{
		ServiceID: "X", OperationName: "ListX",
		Err: &smithyhttp.RequestSendError{Err: &url.Error{Op: "Post", URL: "https://" + host, Err: &net.OpError{Op: "dial", Net: "tcp", Err: dns}}},
	})
}

func TestRegionalServiceHostsComeFromTheSDK(t *testing.T) {
	for _, svc := range regionalServices {
		require.NotNil(t, svc.host, svc.name)
		h := svc.host("eu-west-1")
		require.True(t, strings.HasSuffix(h, ".eu-west-1.amazonaws.com"), "%s: %q", svc.name, h)
		require.NotContains(t, h, "fips", svc.name)
		require.True(t, strings.HasSuffix(svc.host("cn-north-1"), ".amazonaws.com.cn"), "%s resolves China's own DNS suffix", svc.name)
	}
	require.Equal(t, "api.sagemaker.us-east-1.amazonaws.com", sagemakerHost("us-east-1"))
	require.Equal(t, "email.us-east-1.amazonaws.com", sesHost("us-east-1"))
}

func TestEndpointNotFound(t *testing.T) {
	host := appSyncHost("ap-east-2")
	require.True(t, endpointNotFound(sdkDNSErr(host, true), host))
	require.True(t, endpointNotFound(sdkDNSErr(host+".", true), host), "a fully qualified name is the same host")
	require.False(t, endpointNotFound(sdkDNSErr(host, false), host), "a resolver failure is not proof the service is absent")
	require.False(t, endpointNotFound(sdkDNSErr("appsync-fips.ap-east-2.amazonaws.com", true), host), "a FIPS host that does not exist says nothing about the service")
	require.False(t, endpointNotFound(sdkDNSErr("proxy.corp.internal", true), host), "the proxy's own name failing is not the service's")
	require.False(t, endpointNotFound(&smithy.GenericAPIError{Code: "AccessDenied"}, host))
	require.False(t, endpointNotFound(sdkDNSErr("", true), ""), "no standard host, no verdict")
}

func TestEndpointsOverridden(t *testing.T) {
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "AWS_ENDPOINT_URL") {
			k, _, _ := strings.Cut(kv, "=")
			t.Setenv(k, "")
			require.NoError(t, os.Unsetenv(k))
		}
	}
	require.False(t, endpointsOverridden(awssdk.Config{}))
	require.True(t, endpointsOverridden(awssdk.Config{BaseEndpoint: awssdk.String("https://localstack:4566")}))
	require.True(t, endpointsOverridden(awssdk.Config{ConfigSources: []any{config.EnvConfig{UseFIPSEndpoint: awssdk.FIPSEndpointStateEnabled}}}))
	require.True(t, endpointsOverridden(awssdk.Config{ConfigSources: []any{config.SharedConfig{UseDualStackEndpoint: awssdk.DualStackEndpointStateEnabled}}}))
	require.True(t, endpointsOverridden(awssdk.Config{ConfigSources: []any{config.SharedConfig{
		Services: config.Services{ServiceValues: map[string]map[string]string{"appsync": {"endpoint_url": "https://x"}}},
	}}}))
	require.False(t, endpointsOverridden(awssdk.Config{ConfigSources: []any{config.EnvConfig{UseFIPSEndpoint: awssdk.FIPSEndpointStateDisabled}}}))
	t.Setenv("AWS_ENDPOINT_URL_APPSYNC", "https://appsync.example")
	require.True(t, endpointsOverridden(awssdk.Config{}))
}

func TestRegionalServiceTasks(t *testing.T) {
	saved := regionalServices
	t.Cleanup(func() { regionalServices = saved })
	fixedHost := func(string) string { return "x.eu-west-1.amazonaws.com" }
	failing := func(err error) regionalFn {
		return whole(func(context.Context, map[string]string, string, string, time.Time) ([]asset.Asset, error) {
			return nil, err
		})
	}
	regionalServices = []regionalService{
		{name: "absent", host: fixedHost, regionLimited: true, fn: failing(sdkDNSErr("x.eu-west-1.amazonaws.com", true))},
		// An everywhere-service is never absent: its NXDOMAIN is a DNS firewall.
		{name: "everywhere", host: fixedHost, fn: failing(sdkDNSErr("x.eu-west-1.amazonaws.com", true))},
		{name: "proxied", host: fixedHost, fn: failing(sdkDNSErr("egress-proxy.internal", true))},
		{name: "denied", host: fixedHost, fn: failing(&smithy.GenericAPIError{Code: "AccessDeniedException"})},
		{name: "unproven", host: fixedHost, proves: "x:read", fn: failing(fmt.Errorf("gate: %w", errCapabilityUnproven))},
		{name: "used", host: fixedHost, family: "x:things", types: []string{"x_thing"}, proves: "x:read", fn: whole(func(context.Context, map[string]string, string, string, time.Time) ([]asset.Asset, error) {
			return []asset.Asset{{ID: "a", Type: "x_thing"}, {ID: "s", Type: "x_settings"}}, nil
		})},
		{name: "half", host: fixedHost, family: "x:halves", types: []string{"x_half"}, fn: func(context.Context, map[string]string, string, string, time.Time) ([]asset.Asset, bool, error) {
			return []asset.Asset{{ID: "h", Type: "x_half"}}, true, nil
		}},
	}
	unproven := 0
	run := func(cfg map[string]string) (skipped, notOffered, proven []string, added int, partial bool, completed map[string]int) {
		completed = map[string]int{}
		unproven = 0
		h := regionalHooks{
			unproven:   func() { unproven++ },
			skip:       func(_ error, _, what string) { skipped = append(skipped, what) },
			notOffered: func(_ error, what string) { notOffered = append(notOffered, what) },
			complete:   func(region, family string, _ []string, n int) { completed[region+"/"+family] = n },
			add: func(a []asset.Asset, p bool, c string) {
				added += len(a)
				partial = partial || p
				if c != "" {
					proven = append(proven, c)
				}
			},
		}
		for _, task := range regionalServiceTasks(context.Background(), cfg, "eu-west-1", "1", time.Now(), h) {
			task()
		}
		return skipped, notOffered, proven, added, partial, completed
	}

	cfg := map[string]string{"region": "eu-west-1", "aws_access_key_id": "AKIDEXAMPLE", "aws_secret_access_key": "x"}
	skipped, notOffered, proven, added, partial, completed := run(cfg)
	require.Equal(t, []string{"absent service"}, notOffered, "only an NXDOMAIN for the service's own host is a candidate")
	require.ElementsMatch(t, []string{"everywhere service", "proxied service", "denied service"}, skipped,
		"an everywhere-service NXDOMAIN and any other failure are skipped collectors, never empty ones; an unproven capability is neither")
	require.Equal(t, 1, unproven, "an unproven capability reaches the ledger")
	require.Equal(t, 3, added)
	require.True(t, partial, "a partial outcome reaches the sweep")
	require.Equal(t, []string{"x:read"}, proven, "only a successful run proves its capability")
	require.Equal(t, map[string]int{"eu-west-1/x:things": 1}, completed, "completeness counts only the declared types, and a partial run proves nothing complete")

	t.Setenv("AWS_ENDPOINT_URL", "https://localstack:4566")
	skipped, notOffered, _, _, _, _ = run(cfg)
	require.Empty(t, notOffered, "with a custom endpoint the standard host was never dialled")
	require.Len(t, skipped, 4)
}

// Services AWS runs in every commercial region are never withdrawn as not
// offered: their NXDOMAIN is a DNS firewall or proxy, so it must flag the
// sweep partial instead of reading as a clean, empty region.
func TestEverywhereServicesAreNeverRegionLimited(t *testing.T) {
	everywhere := map[string]bool{
		"kms": true, "ecr": true, "sqs": true, "sns": true, "apigateway": true, "acm": true,
		"secretsmanager": true, "ssm": true, "region settings": true, "rds": true, "dynamodb": true,
		"s3 access points": true, "elasticache": true, "kinesis": true, "cloudformation": true,
		"eventbridge": true, "stepfunctions": true, "auto scaling": true, "elbv2 target groups": true,
		"network acl": true, "launch template": true,
	}
	seen := 0
	for _, svc := range regionalServices {
		if everywhere[svc.name] {
			seen++
			require.False(t, svc.regionLimited, "%s runs in every commercial region", svc.name)
		}
	}
	require.Equal(t, len(everywhere), seen, "every pinned service is in the catalogue")
}

// No collector judges a DNS failure itself: the region ledger is the one
// place an NXDOMAIN can read as "not offered", so a collector-level shortcut
// (a net.DNSError check, a "not offered" helper) must not come back.
func TestNoCollectorJudgesNXDOMAIN(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "regional_offered.go" {
			continue
		}
		src, err := os.ReadFile(f)
		require.NoError(t, err)
		require.NotContains(t, string(src), "net.DNSError", "%s judges a DNS failure outside the region ledger", f)
		require.NotContains(t, string(src), "IsNotFound", "%s judges a DNS failure outside the region ledger", f)
	}
}

func TestRegionLedgerSettle(t *testing.T) {
	deny := regionFailure{err: &smithy.GenericAPIError{Code: "AccessDenied"}, what: "d"}
	throttle := regionFailure{err: errors.New("throttled"), what: "t"}
	nx := sdkDNSErr("x.eu-west-1.amazonaws.com", true)

	t.Run("core up: the candidate is withdrawn", func(t *testing.T) {
		var l regionLedger
		tally := &sweepTally{ran: 4}
		l.coreSucceeded()
		l.notOffered(nx, "absent service")
		denied, report := l.settle(4, []regionFailure{throttle}, tally)
		require.False(t, denied)
		require.Equal(t, []regionFailure{throttle}, report)
		require.Equal(t, 3, tally.ran, "withdrawn from the sweep tally too")
	})
	t.Run("core down: the candidate is an ordinary failure", func(t *testing.T) {
		var l regionLedger
		tally := &sweepTally{ran: 4}
		l.notOffered(nx, "absent service")
		denied, report := l.settle(4, []regionFailure{throttle}, tally)
		require.False(t, denied)
		require.Len(t, report, 2, "unverified NXDOMAIN reads as a failed read and flags the sweep partial")
		require.Equal(t, 4, tally.ran)
	})
	t.Run("deny-SCP region: still denied with a candidate in it", func(t *testing.T) {
		var l regionLedger
		l.notOffered(nx, "absent service")
		denied, _ := l.settle(3, []regionFailure{deny, deny}, &sweepTally{ran: 3})
		require.True(t, denied, "counting the not-offered task would hide the deny")
	})
	t.Run("deny-SCP region with an unproven capability task: still denied", func(t *testing.T) {
		var l regionLedger
		l.coreSucceeded()
		l.unproven()
		tally := &sweepTally{ran: 3}
		denied, _ := l.settle(3, []regionFailure{deny, deny}, tally)
		require.True(t, denied, "the unproven task proves nothing, so it must not hide the deny")
		require.Equal(t, 2, tally.ran, "and it leaves the sweep tally too")
	})
	t.Run("withdrawals are logged with service, region and host", func(t *testing.T) {
		var buf bytes.Buffer
		saved := zlog.Logger
		zlog.Logger = zerolog.New(&buf)
		t.Cleanup(func() { zlog.Logger = saved })
		var l regionLedger
		l.coreSucceeded()
		l.notOffered(nx, "absent service")
		denied, report := l.settle(2, nil, &sweepTally{ran: 2})
		require.False(t, denied)
		require.Empty(t, report, "withdrawn, not failed")
		l.warnWithdrawn(context.Background(), "eu-west-1")
		out := buf.String()
		require.Contains(t, out, `"level":"warn"`)
		require.Contains(t, out, `"service":"absent service"`)
		require.Contains(t, out, `"region":"eu-west-1"`)
		require.Contains(t, out, `"host":"x.eu-west-1.amazonaws.com"`)
	})
	t.Run("core up but every offered call denied", func(t *testing.T) {
		var l regionLedger
		l.coreSucceeded()
		l.notOffered(nx, "absent service")
		denied, _ := l.settle(2, []regionFailure{deny}, &sweepTally{ran: 2})
		require.True(t, denied)
	})
}

// The region loop must judge regions through the ledger: a revert to counting
// every task (regionDenied(len(tasks), …)) or a lost core-read signal would
// silently change what a missing endpoint means, and collectAll's regional
// services cannot run without real credentials, so the wiring is pinned here.
func TestRegionLoopSettlesThroughLedger(t *testing.T) {
	src, err := os.ReadFile("aws.go")
	require.NoError(t, err)
	s := string(src)
	require.NotContains(t, s, "regionDenied(", "aws.go judges a region only through regionLedger.settle")
	require.Contains(t, s, "ledger.settle(len(tasks), regionFailures, tally)")
	require.Contains(t, s, "notOffered: ledger.notOffered, unproven: ledger.unproven,")
	require.Contains(t, s, "ledger.warnWithdrawn(ctx, region)", "a withdrawal is never silent")
	i := strings.Index(s, `complete(region, "ec2:instances"`)
	require.Positive(t, i)
	require.Contains(t, s[i:i+120], "ledger.coreSucceeded()", "the core read signal sits on the EC2 instance listing's success path")
}
