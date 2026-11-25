package aws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"
)

// fakeOrgs is a two-level organization: root r-1 → ou-1 → ou-2.
type fakeOrgs struct {
	pages    []*organizations.ListAccountsOutput
	pageErr  map[int]error
	calls    int
	children map[string][]string // parent → OU ids
	accounts map[string][]string // parent → account ids
}

func (f *fakeOrgs) ListAccounts(_ context.Context, in *organizations.ListAccountsInput, _ ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error) {
	i := f.calls
	f.calls++
	if err := f.pageErr[i]; err != nil {
		return nil, err
	}
	return f.pages[i], nil
}

func (f *fakeOrgs) ListRoots(context.Context, *organizations.ListRootsInput, ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	return &organizations.ListRootsOutput{Roots: []orgtypes.Root{{Id: awssdk.String("r-1")}}}, nil
}

func (f *fakeOrgs) ListOrganizationalUnitsForParent(_ context.Context, in *organizations.ListOrganizationalUnitsForParentInput, _ ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
	var ous []orgtypes.OrganizationalUnit
	for _, id := range f.children[*in.ParentId] {
		ous = append(ous, orgtypes.OrganizationalUnit{Id: awssdk.String(id)})
	}
	return &organizations.ListOrganizationalUnitsForParentOutput{OrganizationalUnits: ous}, nil
}

func (f *fakeOrgs) ListAccountsForParent(_ context.Context, in *organizations.ListAccountsForParentInput, _ ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error) {
	var accts []orgtypes.Account
	for _, id := range f.accounts[*in.ParentId] {
		accts = append(accts, orgtypes.Account{Id: awssdk.String(id)})
	}
	return &organizations.ListAccountsForParentOutput{Accounts: accts}, nil
}

func orgWith(orgs orgsAPI, s hubSTSAPI, probe memberProbeAPI) *Org {
	return &Org{
		hubConfig: func(context.Context, map[string]string) (awssdk.Config, error) {
			return awssdk.Config{Region: "eu-west-1"}, nil
		},
		newOrgs:  func(awssdk.Config) orgsAPI { return orgs },
		newSTS:   func(awssdk.Config) hubSTSAPI { return s },
		newProbe: func(awssdk.Config) memberProbeAPI { return probe },
	}
}

var orgCfg = map[string]string{
	orgKeyManagementRoleARN: "arn:aws:iam::111111111111:role/GraphOrgDiscovery",
	orgKeyExternalID:        "ext-123",
}

func acct(id string, state orgtypes.AccountState) orgtypes.Account {
	return orgtypes.Account{Id: awssdk.String(id), Name: awssdk.String("n" + id), State: state}
}

func TestOrgListAccounts_PagesAndKeepsEveryState(t *testing.T) {
	f := &fakeOrgs{pages: []*organizations.ListAccountsOutput{
		{Accounts: []orgtypes.Account{acct("222222222222", orgtypes.AccountStateActive)}, NextToken: awssdk.String("p2")},
		{Accounts: []orgtypes.Account{
			acct("333333333333", orgtypes.AccountStateSuspended),
			// An older response carrying only the retired Status field.
			{Id: awssdk.String("444444444444"), Status: orgtypes.AccountStatusActive},
		}},
	}}
	got, err := orgWith(f, nil, nil).ListAccounts(context.Background(), orgCfg, false)
	require.NoError(t, err)
	require.Len(t, got, 3)
	require.Equal(t, "ACTIVE", got[0].State)
	require.Equal(t, "SUSPENDED", got[1].State, "non-active accounts are returned for the caller to act on")
	require.Equal(t, "ACTIVE", got[2].State, "Status is read when State is absent")
	require.False(t, got[0].OUPathKnown)
}

// A failure on a later page fails the listing as a whole: the first page
// alone would read as "every other account left the organization".
func TestOrgListAccounts_LaterPageFailureFailsAll(t *testing.T) {
	f := &fakeOrgs{
		pages:   []*organizations.ListAccountsOutput{{Accounts: []orgtypes.Account{acct("222222222222", orgtypes.AccountStateActive)}, NextToken: awssdk.String("p2")}},
		pageErr: map[int]error{1: &smithy.GenericAPIError{Code: "TooManyRequestsException"}},
	}
	got, err := orgWith(f, nil, nil).ListAccounts(context.Background(), orgCfg, false)
	require.Error(t, err)
	require.Nil(t, got)
}

func TestOrgListAccounts_OUPaths(t *testing.T) {
	f := &fakeOrgs{
		pages: []*organizations.ListAccountsOutput{{Accounts: []orgtypes.Account{
			acct("111111111111", orgtypes.AccountStateActive),
			acct("222222222222", orgtypes.AccountStateActive),
			acct("333333333333", orgtypes.AccountStateActive),
		}}},
		children: map[string][]string{"r-1": {"ou-1"}, "ou-1": {"ou-2"}},
		accounts: map[string][]string{"r-1": {"111111111111"}, "ou-2": {"222222222222"}},
	}
	got, err := orgWith(f, nil, nil).ListAccounts(context.Background(), orgCfg, true)
	require.NoError(t, err)
	require.Equal(t, []string{"r-1"}, got[0].OUPath)
	require.True(t, got[0].OUPathKnown)
	require.Equal(t, []string{"r-1", "ou-1", "ou-2"}, got[1].OUPath)
	require.False(t, got[2].OUPathKnown, "an account the walk did not reach has an unknown path, not an empty one")
}

func TestOrgListAccounts_RequiresManagementRole(t *testing.T) {
	_, err := orgWith(&fakeOrgs{}, nil, nil).ListAccounts(context.Background(), map[string]string{}, false)
	require.Error(t, err)
}

// fakeHubSTS answers AssumeRole per role ARN.
type fakeHubSTS struct {
	identityErr error
	assumeErr   map[string]error
	mu          sync.Mutex
	assumed     []*sts.AssumeRoleInput
}

func (f *fakeHubSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if f.identityErr != nil {
		return nil, f.identityErr
	}
	return &sts.GetCallerIdentityOutput{Arn: awssdk.String("arn:aws:sts::999999999999:assumed-role/GraphHub/pod")}, nil
}

func (f *fakeHubSTS) AssumeRole(_ context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.mu.Lock()
	f.assumed = append(f.assumed, in)
	f.mu.Unlock()
	if err := f.assumeErr[*in.RoleArn]; err != nil {
		return nil, err
	}
	return &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: awssdk.String("ASIA"), SecretAccessKey: awssdk.String("s"), SessionToken: awssdk.String("t"),
	}}, nil
}

type fakeMemberProbe struct{ err error }

func (f fakeMemberProbe) GetAccountSummary(context.Context, *iam.GetAccountSummaryInput, ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	return &iam.GetAccountSummaryOutput{}, f.err
}

func deny(msg string) error { return &smithy.GenericAPIError{Code: "AccessDenied", Message: msg} }

func TestOrgTest_ReportsPerAccountCause(t *testing.T) {
	role := func(id string) string { return "arn:aws:iam::" + id + ":role/GraphReadOnly" }
	s := &fakeHubSTS{assumeErr: map[string]error{
		role("333333333333"): deny("User: arn:aws:sts::999999999999:assumed-role/GraphHub/pod is not authorized to perform: sts:AssumeRole on resource: " + role("333333333333")),
		role("444444444444"): deny("... is not authorized to perform: sts:AssumeRole on resource: x with an explicit deny in a service control policy"),
		role("555555555555"): deny("... is not authorized to perform: sts:AssumeRole on resource: x because no identity-based policy allows the sts:AssumeRole action"),
		role("666666666666"): &smithy.GenericAPIError{Code: "Throttling"},
	}}
	f := &fakeOrgs{pages: []*organizations.ListAccountsOutput{{Accounts: []orgtypes.Account{
		acct("222222222222", orgtypes.AccountStateActive), acct("333333333333", orgtypes.AccountStateActive),
		acct("444444444444", orgtypes.AccountStateActive), acct("555555555555", orgtypes.AccountStateActive),
		acct("666666666666", orgtypes.AccountStateActive), acct("777777777777", orgtypes.AccountStateSuspended),
	}}}}
	res := orgWith(f, s, fakeMemberProbe{}).Test(context.Background(), orgCfg)

	require.True(t, res.HubOK)
	require.True(t, res.ListOK)
	require.Equal(t, 6, res.AccountCount)
	causes := map[string]string{}
	for _, m := range res.Members {
		causes[m.AccountID] = m.Cause
	}
	require.Equal(t, map[string]string{
		"222222222222": CauseOK,
		"333333333333": CauseRoleMissingOrDenied,
		"444444444444": CauseSCPDeny,
		"555555555555": CauseHubNotPermitted,
		"666666666666": CauseThrottled,
	}, causes, "suspended accounts are not sampled")
	for _, in := range s.assumed {
		require.Equal(t, "ext-123", awssdk.ToString(in.ExternalId), "every member assume presents the ExternalId")
	}
}

func TestOrgTest_AssumedButReadsDenied(t *testing.T) {
	f := &fakeOrgs{pages: []*organizations.ListAccountsOutput{{Accounts: []orgtypes.Account{acct("222222222222", orgtypes.AccountStateActive)}}}}
	for _, tc := range []struct {
		err  error
		want string
	}{
		{deny("not authorized to perform: iam:GetAccountSummary with an explicit deny in a service control policy"), CauseSCPDeny},
		{deny("not authorized to perform: iam:GetAccountSummary"), CauseReadsDenied},
	} {
		res := orgWith(&fakeOrgs{pages: f.pages}, &fakeHubSTS{}, fakeMemberProbe{err: tc.err}).Test(context.Background(), orgCfg)
		require.Len(t, res.Members, 1)
		require.False(t, res.Members[0].OK)
		require.Equal(t, tc.want, res.Members[0].Cause)
	}
}

func TestOrgTest_StopsAtFirstFailedStep(t *testing.T) {
	res := orgWith(&fakeOrgs{}, &fakeHubSTS{identityErr: errors.New("no credentials")}, nil).Test(context.Background(), orgCfg)
	require.False(t, res.HubOK)
	require.NotEmpty(t, res.HubError)
	require.False(t, res.ListRan)

	f := &fakeOrgs{pageErr: map[int]error{0: deny("not authorized to perform: sts:AssumeRole")}}
	res = orgWith(f, &fakeHubSTS{}, nil).Test(context.Background(), orgCfg)
	require.True(t, res.HubOK)
	require.True(t, res.ListRan)
	require.False(t, res.ListOK)
	require.Contains(t, res.ListError, "management role")
	require.Empty(t, res.Members)
}

func TestTestSample_CapsAndSorts(t *testing.T) {
	var accts []OrgAccount
	for i := 20; i > 0; i-- {
		accts = append(accts, OrgAccount{ID: fmt.Sprintf("%012d", i), State: "ACTIVE"})
	}
	got := testSample(accts)
	require.Len(t, got, maxTestSample)
	require.Equal(t, "000000000001", got[0])
}

func TestMemberRoleARN(t *testing.T) {
	require.Equal(t, "arn:aws:iam::222222222222:role/GraphReadOnly", memberRoleARN("arn:aws:iam::1:role/x", "222222222222", ""))
	require.Equal(t, "arn:aws-us-gov:iam::222222222222:role/R", memberRoleARN("arn:aws-us-gov:iam::1:role/x", "222222222222", "R"))
}

// stsServer is a fake STS endpoint recording each AssumeRole it is sent.
type stsCall struct {
	form          url.Values
	authorization string
}

func stsServer(t *testing.T) (*httptest.Server, *[]stsCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []stsCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		mu.Lock()
		calls = append(calls, stsCall{form: form, authorization: r.Header.Get("Authorization")})
		mu.Unlock()
		w.Header().Set("Content-Type", "text/xml")
		if form.Get("Action") == "GetCallerIdentity" {
			_, _ = io.WriteString(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>
<Arn>arn:aws:sts::333333333333:assumed-role/GraphHub/graph-hub</Arn><UserId>AROA:graph-hub</UserId><Account>333333333333</Account>
</GetCallerIdentityResult></GetCallerIdentityResponse>`)
			return
		}
		// The hub role's session is ASIAHUB, every other role's ASIAMEMBER, so
		// a test can tell which identity signed the next hop.
		key := "ASIAMEMBER"
		if strings.HasSuffix(form.Get("RoleArn"), ":role/GraphHub") {
			key = "ASIAHUB"
		}
		_, _ = io.WriteString(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult>
<Credentials><AccessKeyId>`+key+`</AccessKeyId><SecretAccessKey>s</SecretAccessKey><SessionToken>t</SessionToken>
<Expiration>2099-01-01T00:00:00Z</Expiration></Credentials>
<AssumedRoleUser><Arn>arn:aws:sts::222222222222:assumed-role/GraphReadOnly/x</Arn><AssumedRoleId>AROA:x</AssumedRoleId></AssumedRoleUser>
</AssumeRoleResult></AssumeRoleResponse>`)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// The collector credential chain for an org child, as connector.Service.Get
// resolves it: the hub credential signs ONE sts:AssumeRole into the member
// role, presenting the org's ExternalId, and the sweep reads as the member.
func TestBuildConfig_OrgChildChain(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     map[string]string
		signing string
	}{
		{"stored hub key", map[string]string{
			"aws_access_key_id": "AKIAHUBKEY", "aws_secret_access_key": "hub-secret",
		}, "AKIAHUBKEY"},
		// hub_auth=ambient: no key in the config; graph's own identity (here
		// the environment, as IRSA/Pod Identity would supply) signs.
		{"ambient hub", map[string]string{}, "AKIAAMBIENT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, calls := stsServer(t)
			t.Setenv("AWS_ENDPOINT_URL_STS", srv.URL)
			t.Setenv("AWS_ACCESS_KEY_ID", "AKIAAMBIENT")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret")
			t.Setenv("AWS_CONFIG_FILE", "/dev/null")
			t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
			cfg := map[string]string{
				"region": "eu-west-1", "org_connector_id": "org-1", "aws_account_id": "222222222222",
				"role_arn": "arn:aws:iam::222222222222:role/GraphReadOnly", "external_id": "ext-123",
			}
			for k, v := range tc.cfg {
				cfg[k] = v
			}
			awsCfg, err := baseConfig(withConfigCache(context.Background()), cfg)
			require.NoError(t, err)
			creds, err := awsCfg.Credentials.Retrieve(context.Background())
			require.NoError(t, err)
			require.Equal(t, "ASIAMEMBER", creds.AccessKeyID, "the sweep runs as the member role")

			require.Len(t, *calls, 1)
			got := (*calls)[0]
			require.Equal(t, "AssumeRole", got.form.Get("Action"))
			require.Equal(t, "arn:aws:iam::222222222222:role/GraphReadOnly", got.form.Get("RoleArn"))
			require.Equal(t, "ext-123", got.form.Get("ExternalId"))
			require.True(t, strings.Contains(got.authorization, "Credential="+tc.signing+"/"),
				"AssumeRole is signed by the hub credential, got %q", got.authorization)
		})
	}
}

const testHubRole = "arn:aws:iam::333333333333:role/GraphHub"

// stsEnv points STS at srv and gives the process an ambient key, as an
// instance role or IRSA would.
func stsEnv(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("AWS_ENDPOINT_URL_STS", srv.URL)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAAMBIENT")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret")
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
}

func signedBy(t *testing.T, c stsCall, key string) {
	t.Helper()
	require.True(t, strings.Contains(c.authorization, "Credential="+key+"/"),
		"want the call signed by %s, got %q", key, c.authorization)
}

// TrustType=principal: the hub role trusts an instance role or an IAM user,
// not graph's session itself, so with hub_role_arn the base credential
// assumes the hub role (no ExternalId: its principal trust has none) and the
// hub config is that session. Without hub_role_arn no STS call is made.
func TestHubConfig_HubRoleARN(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     map[string]string
		signing string
		want    string
	}{
		{"ambient, no hub role", map[string]string{}, "", "AKIAAMBIENT"},
		{"ambient principal", map[string]string{orgKeyHubRoleARN: testHubRole}, "AKIAAMBIENT", "ASIAHUB"},
		{"stored key principal", map[string]string{
			orgKeyHubAuth: hubAuthAccessKey, "aws_access_key_id": "AKIAHUBKEY", "aws_secret_access_key": "hub-secret",
			orgKeyHubRoleARN: testHubRole,
		}, "AKIAHUBKEY", "ASIAHUB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, calls := stsServer(t)
			stsEnv(t, srv)
			hub, err := hubConfig(context.Background(), tc.cfg)
			require.NoError(t, err)
			creds, err := hub.Credentials.Retrieve(context.Background())
			require.NoError(t, err)
			require.Equal(t, tc.want, creds.AccessKeyID)
			if tc.signing == "" {
				require.Empty(t, *calls)
				return
			}
			require.Len(t, *calls, 1)
			got := (*calls)[0]
			require.Equal(t, "AssumeRole", got.form.Get("Action"))
			require.Equal(t, testHubRole, got.form.Get("RoleArn"))
			require.Equal(t, "graph-hub", got.form.Get("RoleSessionName"))
			require.Empty(t, got.form.Get("ExternalId"))
			signedBy(t, got, tc.signing)
		})
	}
}

// A stored IAM user key is never itself a hub session.
func TestHubConfig_AccessKeyRequiresHubRole(t *testing.T) {
	_, err := hubConfig(context.Background(), map[string]string{
		orgKeyHubAuth: hubAuthAccessKey, "aws_access_key_id": "AKIAHUBKEY", "aws_secret_access_key": "hub-secret",
	})
	require.ErrorContains(t, err, "hub_role_arn")
}

// The connection test runs on the same hub credentials as discovery: with
// hub_role_arn, GetCallerIdentity and every member AssumeRole are signed by
// the hub role's session, not by the principal's own key.
func TestOrgTest_UsesHubRoleSession(t *testing.T) {
	srv, calls := stsServer(t)
	stsEnv(t, srv)
	orgs := &fakeOrgs{pages: []*organizations.ListAccountsOutput{{Accounts: []orgtypes.Account{
		acct("222222222222", orgtypes.AccountStateActive),
	}}}}
	o := &Org{
		hubConfig: hubConfig,
		newOrgs:   func(awssdk.Config) orgsAPI { return orgs },
		newSTS:    func(c awssdk.Config) hubSTSAPI { return sts.NewFromConfig(c) },
		newProbe:  func(awssdk.Config) memberProbeAPI { return okProbe{} },
	}
	cfg := map[string]string{
		orgKeyManagementRoleARN: "arn:aws:iam::111111111111:role/GraphOrgDiscovery",
		orgKeyExternalID:        "ext-123",
		orgKeyHubAuth:           hubAuthAccessKey, "aws_access_key_id": "AKIAHUBKEY", "aws_secret_access_key": "hub-secret",
		orgKeyHubRoleARN: testHubRole,
	}
	res := o.Test(context.Background(), cfg)
	require.True(t, res.HubOK, res.HubError)
	require.Equal(t, "arn:aws:sts::333333333333:assumed-role/GraphHub/graph-hub", res.HubIdentity)
	require.True(t, res.ListOK, res.ListError)
	require.Len(t, res.Members, 1)
	require.True(t, res.Members[0].OK, res.Members[0].Detail)

	require.Len(t, *calls, 3)
	require.Equal(t, testHubRole, (*calls)[0].form.Get("RoleArn"))
	signedBy(t, (*calls)[0], "AKIAHUBKEY")
	require.Equal(t, "GetCallerIdentity", (*calls)[1].form.Get("Action"))
	signedBy(t, (*calls)[1], "ASIAHUB")
	require.Equal(t, "arn:aws:iam::222222222222:role/GraphReadOnly", (*calls)[2].form.Get("RoleArn"))
	require.Equal(t, "ext-123", (*calls)[2].form.Get("ExternalId"))
	signedBy(t, (*calls)[2], "ASIAHUB")
}

type okProbe struct{}

func (okProbe) GetAccountSummary(context.Context, *iam.GetAccountSummaryInput, ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	return &iam.GetAccountSummaryOutput{}, nil
}

// An org child whose hub trusts a principal: the base credential assumes the
// hub role, and the hub session (not the base key) assumes the member role.
func TestBuildConfig_OrgChildChainThroughHubRole(t *testing.T) {
	for _, tc := range []struct {
		name, signing string
		cfg           map[string]string
	}{
		{"stored hub key", "AKIAHUBKEY", map[string]string{"aws_access_key_id": "AKIAHUBKEY", "aws_secret_access_key": "hub-secret"}},
		{"ambient principal", "AKIAAMBIENT", map[string]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, calls := stsServer(t)
			stsEnv(t, srv)
			cfg := map[string]string{
				"region": "eu-west-1", "org_connector_id": "org-1", "aws_account_id": "222222222222",
				"role_arn": "arn:aws:iam::222222222222:role/GraphReadOnly", "external_id": "ext-123",
				keyHubRoleARN: testHubRole,
			}
			for k, v := range tc.cfg {
				cfg[k] = v
			}
			awsCfg, err := baseConfig(withConfigCache(context.Background()), cfg)
			require.NoError(t, err)
			creds, err := awsCfg.Credentials.Retrieve(context.Background())
			require.NoError(t, err)
			require.Equal(t, "ASIAMEMBER", creds.AccessKeyID)

			require.Len(t, *calls, 2)
			require.Equal(t, testHubRole, (*calls)[0].form.Get("RoleArn"))
			signedBy(t, (*calls)[0], tc.signing)
			require.Equal(t, "arn:aws:iam::222222222222:role/GraphReadOnly", (*calls)[1].form.Get("RoleArn"))
			require.Equal(t, "ext-123", (*calls)[1].form.Get("ExternalId"))
			signedBy(t, (*calls)[1], "ASIAHUB")
		})
	}
}

// The OU walk is one throttled call per OU; the client must retry adaptively
// and must not let an ambient AWS_MAX_ATTEMPTS cut that back down.
func TestOrganizationsRetryerIsAdaptive(t *testing.T) {
	o := organizations.Options{RetryMaxAttempts: 3}
	organizationsRetryer(&o)
	require.Zero(t, o.RetryMaxAttempts)
	require.IsType(t, &retry.AdaptiveMode{}, o.Retryer)
	require.Equal(t, 10, o.Retryer.MaxAttempts())
}
