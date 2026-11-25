package aws

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/waf"
	waftypes "github.com/aws/aws-sdk-go-v2/service/waf/types"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeWAFv2 struct {
	aclPages [][]wafv2types.WebACLSummary
	acls     map[string]*wafv2types.WebACL
	aclErr   map[string]error
	groups   []wafv2types.RuleGroupSummary
	group    map[string]*wafv2types.RuleGroup
	listErr  error
}

func (f *fakeWAFv2) ListWebACLs(_ context.Context, in *wafv2.ListWebACLsInput, _ ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error) {
	i := 0
	if in.NextMarker != nil {
		i = 1
		if f.listErr != nil {
			return nil, f.listErr
		}
	}
	out := &wafv2.ListWebACLsOutput{WebACLs: f.aclPages[i]}
	if i+1 < len(f.aclPages) {
		out.NextMarker = awssdk.String("next")
	}
	return out, nil
}

func (f *fakeWAFv2) GetWebACL(_ context.Context, in *wafv2.GetWebACLInput, _ ...func(*wafv2.Options)) (*wafv2.GetWebACLOutput, error) {
	if err := f.aclErr[awssdk.ToString(in.Id)]; err != nil {
		return nil, err
	}
	return &wafv2.GetWebACLOutput{WebACL: f.acls[awssdk.ToString(in.Id)]}, nil
}

func (f *fakeWAFv2) ListRuleGroups(context.Context, *wafv2.ListRuleGroupsInput, ...func(*wafv2.Options)) (*wafv2.ListRuleGroupsOutput, error) {
	return &wafv2.ListRuleGroupsOutput{RuleGroups: f.groups}, nil
}

func (f *fakeWAFv2) GetRuleGroup(_ context.Context, in *wafv2.GetRuleGroupInput, _ ...func(*wafv2.Options)) (*wafv2.GetRuleGroupOutput, error) {
	return &wafv2.GetRuleGroupOutput{RuleGroup: f.group[awssdk.ToString(in.Id)]}, nil
}

func v2Rule(name string, metrics bool) wafv2types.Rule {
	return wafv2types.Rule{Name: awssdk.String(name), VisibilityConfig: &wafv2types.VisibilityConfig{CloudWatchMetricsEnabled: metrics}}
}

func byID(as []asset.Asset) map[string]asset.Asset {
	out := map[string]asset.Asset{}
	for _, a := range as {
		out[a.ID] = a
	}
	return out
}

func TestReadWAFv2(t *testing.T) {
	sum := func(id string) wafv2types.WebACLSummary {
		return wafv2types.WebACLSummary{ARN: awssdk.String("arn:acl/" + id), Id: awssdk.String(id), Name: awssdk.String(id)}
	}
	f := &fakeWAFv2{
		aclPages: [][]wafv2types.WebACLSummary{{sum("empty"), sum("full")}, {sum("fms"), sum("denied")}},
		acls: map[string]*wafv2types.WebACL{
			"empty": {},
			"full":  {Rules: []wafv2types.Rule{v2Rule("ok", true), v2Rule("dark", false), {Name: awssdk.String("novis")}}},
			"fms":   {PreProcessFirewallManagerRuleGroups: []wafv2types.FirewallManagerRuleGroup{{Name: awssdk.String("fms-pre"), VisibilityConfig: &wafv2types.VisibilityConfig{CloudWatchMetricsEnabled: true}}}},
		},
		aclErr: map[string]error{"denied": errors.New("AccessDenied")},
		groups: []wafv2types.RuleGroupSummary{{ARN: awssdk.String("arn:rg/g1"), Id: awssdk.String("g1"), Name: awssdk.String("g1")}},
		group:  map[string]*wafv2types.RuleGroup{"g1": {Rules: []wafv2types.Rule{v2Rule("grp-dark", false)}}},
	}
	got, err := readWAFv2(context.Background(), f, wafv2types.ScopeRegional, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	m := byID(got)
	require.Len(t, m, 5, "both list pages are read")
	require.Equal(t, "0", m["arn:acl/empty"].Metadata["rule_count"])
	require.Equal(t, "3", m["arn:acl/full"].Metadata["rule_count"])
	require.Equal(t, "dark,novis", m["arn:acl/full"].Metadata["rules_without_metrics"])
	require.Equal(t, "1", m["arn:acl/fms"].Metadata["rule_count"], "Firewall Manager rule groups are rules the ACL evaluates")
	_, ok := m["arn:acl/denied"].Metadata["rule_count"]
	require.False(t, ok, "an unread ACL is unknown, not empty")
	require.Equal(t, wafRuleGroupType, m["arn:rg/g1"].Type)
	require.Equal(t, "grp-dark", m["arn:rg/g1"].Metadata["rules_without_metrics"])
	require.Equal(t, "false", m["arn:acl/full"].Metadata["classic"])
}

func TestReadWAFv2FailedPageFails(t *testing.T) {
	f := &fakeWAFv2{aclPages: [][]wafv2types.WebACLSummary{{{ARN: awssdk.String("a"), Id: awssdk.String("a")}}, nil}, listErr: errors.New("Throttling")}
	_, err := readWAFv2(context.Background(), f, wafv2types.ScopeRegional, "eu-west-1", "1", time.Now())
	require.Error(t, err)
}

type fakeWAFClassic struct {
	acls       []waftypes.WebACLSummary
	acl        map[string]*waftypes.WebACL
	rules      []waftypes.RuleSummary
	rule       map[string]*waftypes.Rule
	ruleErr    map[string]error
	groups     []waftypes.RuleGroupSummary
	activated  map[string][]waftypes.ActivatedRule
	logging    []waftypes.LoggingConfiguration
	loggingErr error
	aclsErr    error
}

func (f *fakeWAFClassic) ListWebACLs(context.Context, *waf.ListWebACLsInput, ...func(*waf.Options)) (*waf.ListWebACLsOutput, error) {
	if f.aclsErr != nil {
		return nil, f.aclsErr
	}
	return &waf.ListWebACLsOutput{WebACLs: f.acls}, nil
}

func (f *fakeWAFClassic) GetWebACL(_ context.Context, in *waf.GetWebACLInput, _ ...func(*waf.Options)) (*waf.GetWebACLOutput, error) {
	return &waf.GetWebACLOutput{WebACL: f.acl[awssdk.ToString(in.WebACLId)]}, nil
}

func (f *fakeWAFClassic) ListRules(context.Context, *waf.ListRulesInput, ...func(*waf.Options)) (*waf.ListRulesOutput, error) {
	return &waf.ListRulesOutput{Rules: f.rules}, nil
}

func (f *fakeWAFClassic) GetRule(_ context.Context, in *waf.GetRuleInput, _ ...func(*waf.Options)) (*waf.GetRuleOutput, error) {
	if err := f.ruleErr[awssdk.ToString(in.RuleId)]; err != nil {
		return nil, err
	}
	return &waf.GetRuleOutput{Rule: f.rule[awssdk.ToString(in.RuleId)]}, nil
}

func (f *fakeWAFClassic) ListRuleGroups(context.Context, *waf.ListRuleGroupsInput, ...func(*waf.Options)) (*waf.ListRuleGroupsOutput, error) {
	return &waf.ListRuleGroupsOutput{RuleGroups: f.groups}, nil
}

func (f *fakeWAFClassic) ListActivatedRulesInRuleGroup(_ context.Context, in *waf.ListActivatedRulesInRuleGroupInput, _ ...func(*waf.Options)) (*waf.ListActivatedRulesInRuleGroupOutput, error) {
	return &waf.ListActivatedRulesInRuleGroupOutput{ActivatedRules: f.activated[awssdk.ToString(in.RuleGroupId)]}, nil
}

func (f *fakeWAFClassic) ListLoggingConfigurations(context.Context, *waf.ListLoggingConfigurationsInput, ...func(*waf.Options)) (*waf.ListLoggingConfigurationsOutput, error) {
	if f.loggingErr != nil {
		return nil, f.loggingErr
	}
	return &waf.ListLoggingConfigurationsOutput{LoggingConfigurations: f.logging}, nil
}

func TestReadWAFClassic(t *testing.T) {
	arnA := "arn:aws:waf::1:webacl/a"
	f := &fakeWAFClassic{
		acls: []waftypes.WebACLSummary{{WebACLId: awssdk.String("a"), Name: awssdk.String("a")}, {WebACLId: awssdk.String("b"), Name: awssdk.String("b")}},
		acl: map[string]*waftypes.WebACL{
			"a": {WebACLArn: awssdk.String(arnA), Rules: []waftypes.ActivatedRule{{RuleId: awssdk.String("r1")}}},
			"b": {WebACLArn: awssdk.String("arn:aws:waf::1:webacl/b")},
		},
		rules:     []waftypes.RuleSummary{{RuleId: awssdk.String("r1")}, {RuleId: awssdk.String("r2")}, {RuleId: awssdk.String("r3")}},
		rule:      map[string]*waftypes.Rule{"r1": {Predicates: []waftypes.Predicate{{}}}, "r2": {}},
		ruleErr:   map[string]error{"r3": errors.New("AccessDenied")},
		groups:    []waftypes.RuleGroupSummary{{RuleGroupId: awssdk.String("g1")}},
		activated: map[string][]waftypes.ActivatedRule{},
		logging:   []waftypes.LoggingConfiguration{{ResourceArn: awssdk.String(arnA), LogDestinationConfigs: []string{"arn:firehose"}}},
	}
	got, err := readWAFClassic(context.Background(), wafGlobal{f}, "GLOBAL", "waf", "us-east-1", "global", "1", time.Now())
	require.NoError(t, err)
	logged, err := classicLoggedACLs(f)(context.Background())
	require.NoError(t, err)
	stampClassicLogging(got, logged)
	m := byID(got)
	require.Equal(t, "1", m[arnA].Metadata["rule_count"])
	require.Equal(t, "true", m[arnA].Metadata["logging_enabled"])
	require.Equal(t, "0", m["arn:aws:waf::1:webacl/b"].Metadata["rule_count"])
	require.Equal(t, "false", m["arn:aws:waf::1:webacl/b"].Metadata["logging_enabled"])
	require.Equal(t, "1", m["arn:aws:waf::1:rule/r1"].Metadata["condition_count"])
	require.Equal(t, "0", m["arn:aws:waf::1:rule/r2"].Metadata["condition_count"])
	_, ok := m["arn:aws:waf::1:rule/r3"].Metadata["condition_count"]
	require.False(t, ok, "an unread rule is unknown")
	require.Equal(t, "0", m["arn:aws:waf::1:rulegroup/g1"].Metadata["rule_count"])
	require.Equal(t, "true", m[arnA].Metadata["classic"])

	f.loggingErr = errors.New("AccessDenied")
	_, err = classicLoggedACLs(f)(context.Background())
	require.Error(t, err, "an unreadable logging listing must not read as 'not logged'")
}

func TestReadWAFClassicEmptyAccountEmitsNothing(t *testing.T) {
	got, err := readWAFClassic(context.Background(), wafGlobal{&fakeWAFClassic{}}, "GLOBAL", "waf", "us-east-1", "global", "1", time.Now())
	require.NoError(t, err)
	require.Empty(t, got)
}

func classicHTTPErr(status int, code string) error {
	return &awshttp.ResponseError{ResponseError: &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
		Err:      &smithy.GenericAPIError{Code: code},
	}}
}

// WAF Classic ended on 2025-09-30: a service-side 4xx refusal of a Classic
// listing is an empty account, not a failure that flags every region partial
// on every sweep. Denials, throttling and 5xx still fail the read.
func TestReadWAFClassicRetiredAPIIsEmpty(t *testing.T) {
	for _, tt := range []struct {
		name  string
		err   error
		empty bool
	}{
		{"unsupported operation", classicHTTPErr(400, "UnsupportedOperation"), true},
		{"unknown operation", classicHTTPErr(404, "UnknownOperationException"), true},
		{"access denied stays a failure", classicHTTPErr(403, "AccessDeniedException"), false},
		{"throttling stays a failure", classicHTTPErr(400, "ThrottlingException"), false},
		{"server error stays a failure", classicHTTPErr(503, "ServiceUnavailable"), false},
		{"a non-HTTP error stays a failure", errors.New("connection reset"), false},
		{"an NXDOMAIN stays a failure (the region ledger judges it)", &net.DNSError{Err: "no such host", Name: "waf-regional.ap-east-2.amazonaws.com", IsNotFound: true}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readWAFClassic(context.Background(), wafGlobal{&fakeWAFClassic{aclsErr: tt.err}}, "GLOBAL", "waf", "us-east-1", "global", "1", time.Now())
			if tt.empty {
				require.NoError(t, err)
				require.Empty(t, got)
				return
			}
			require.Error(t, err)
		})
	}
}
