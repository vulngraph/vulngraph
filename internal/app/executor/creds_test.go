package executor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/connector"
)

// The control: no separate write role means no mutation, whatever mode the
// connector is in. Fail closed, and say which key is missing.
func TestExecutionAWSConfig_RefusesWithoutAnExecutionRole(t *testing.T) {
	c := rwConnector(connector.TypeAWS, map[string]string{
		"region":   "eu-west-1",
		"role_arn": "arn:aws:iam::1:role/collector",
	})
	_, err := executionAWSConfig(context.Background(), c, "eu-west-1")
	require.ErrorIs(t, err, ErrNoExecutionRole)
	require.Contains(t, err.Error(), ConfigExecuteRoleARN)
}

// The defect this whole file exists for: mutating with the credential the
// platform uses to collect the estate.
func TestExecutionAWSConfig_RefusesTheCollectionRole(t *testing.T) {
	c := rwConnector(connector.TypeAWS, map[string]string{
		"region":             "eu-west-1",
		"role_arn":           "arn:aws:iam::1:role/collector",
		ConfigExecuteRoleARN: "arn:aws:iam::1:role/collector",
	})
	_, err := executionAWSConfig(context.Background(), c, "eu-west-1")
	require.ErrorIs(t, err, ErrNoExecutionRole)
	require.Contains(t, err.Error(), "collects with")
}

// The read ceiling role is not a write role; pointing the executor at it would
// collapse the three principals back into two and fail confusingly at the API.
func TestExecutionAWSConfig_RefusesTheReadOnlyRole(t *testing.T) {
	c := rwConnector(connector.TypeAWS, map[string]string{
		"region":             "eu-west-1",
		"role_arn":           "arn:aws:iam::1:role/collector",
		"readonly_role_arn":  "arn:aws:iam::1:role/viewonly",
		ConfigExecuteRoleARN: "arn:aws:iam::1:role/viewonly",
	})
	_, err := executionAWSConfig(context.Background(), c, "eu-west-1")
	require.ErrorIs(t, err, ErrNoExecutionRole)
	require.Contains(t, err.Error(), "read ceiling")
}

// Static access keys are a supported collection path. They
// must not become a write path: a connector with keys and no execute role still
// mutates nothing.
func TestExecutionAWSConfig_StaticCollectionKeysAreNotAWritePath(t *testing.T) {
	c := rwConnector(connector.TypeAWS, map[string]string{
		"region":                "eu-west-1",
		"aws_access_key_id":     "AKIAEXAMPLE",
		"aws_secret_access_key": "shhh",
	})
	_, err := executionAWSConfig(context.Background(), c, "eu-west-1")
	require.ErrorIs(t, err, ErrNoExecutionRole)
}

// An org child whose hub role trusts a principal: the ambient identity assumes
// the hub role, and the hub session (never the connector's stored key) assumes
// the execution role.
func TestExecutionAWSConfig_AssumesTheHubRoleFirst(t *testing.T) {
	hops := hubChainSTS(t)
	c := rwConnector(connector.TypeAWS, map[string]string{
		"region":                   "eu-west-1",
		"role_arn":                 "arn:aws:iam::222222222222:role/GraphReadOnly",
		"aws_access_key_id":        "AKIASTOREDHUBKEY",
		"aws_secret_access_key":    "shhh",
		connector.OrgKeyHubRoleARN: "arn:aws:iam::333333333333:role/GraphHub",
		ConfigExecuteRoleARN:       "arn:aws:iam::222222222222:role/GraphExecute",
		ConfigExecuteExternalID:    "ext-123",
	})
	cfg, err := executionAWSConfig(context.Background(), c, "eu-west-1")
	require.NoError(t, err)
	creds, err := cfg.Credentials.Retrieve(context.Background())
	require.NoError(t, err)
	require.Equal(t, "ASIAROLE", creds.AccessKeyID)
	require.Equal(t, []stsHop{
		{role: "arn:aws:iam::333333333333:role/GraphHub", signedBy: "AKIAAMBIENT"},
		{role: "arn:aws:iam::222222222222:role/GraphExecute", signedBy: "ASIAHUB"},
	}, *hops)
}

// hubChainSTS is a fake STS endpoint that records each AssumeRole (role and
// signing key). The hub role's session is ASIAHUB, any other role's ASIAROLE,
// so a test can tell which identity signed each hop. It also gives the
// process an ambient key (AKIAAMBIENT), as an instance role would.
type stsHop struct{ role, signedBy string }

func hubChainSTS(t *testing.T) *[]stsHop {
	t.Helper()
	var mu sync.Mutex
	var hops []stsHop
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		auth := r.Header.Get("Authorization")
		signer := ""
		if _, after, ok := strings.Cut(auth, "Credential="); ok {
			signer, _, _ = strings.Cut(after, "/")
		}
		mu.Lock()
		hops = append(hops, stsHop{role: form.Get("RoleArn"), signedBy: signer})
		mu.Unlock()
		key := "ASIAROLE"
		if strings.HasSuffix(form.Get("RoleArn"), ":role/GraphHub") {
			key = "ASIAHUB"
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult>
<Credentials><AccessKeyId>`+key+`</AccessKeyId><SecretAccessKey>s</SecretAccessKey><SessionToken>t</SessionToken>
<Expiration>2099-01-01T00:00:00Z</Expiration></Credentials>
<AssumedRoleUser><Arn>arn:aws:sts::222222222222:assumed-role/x/x</Arn><AssumedRoleId>AROA:x</AssumedRoleId></AssumedRoleUser>
</AssumeRoleResult></AssumeRoleResponse>`)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("AWS_ENDPOINT_URL_STS", srv.URL)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAAMBIENT")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret")
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
	return &hops
}

// A GCP connector with no execution account is refused as a configuration
// error; no other config value (here a stray access_token) stands in for it.
func TestExecutionGCPOptions_RefusesWithoutAnExecutionServiceAccount(t *testing.T) {
	c := rwConnector(connector.TypeGCP, map[string]string{
		"project_id":   "proj",
		"access_token": "collection-token",
	})
	_, err := executionGCPOptions(context.Background(), c, "https://www.googleapis.com/auth/compute")
	require.ErrorIs(t, err, ErrNoExecutionRole)
	require.Contains(t, err.Error(), ConfigExecuteServiceAccount)
}

// With an execution account configured, the config gate is passed and the
// impersonation is actually attempted. Whether that attempt succeeds depends on
// ambient GCP credentials this test cannot assume, so the assertion is the one
// that matters: it is no longer a CONFIGURATION refusal.
func TestExecutionGCPOptions_WithAnExecutionAccountGetsPastTheConfigGate(t *testing.T) {
	c := rwConnector(connector.TypeGCP, map[string]string{
		"access_token":              "collection-token",
		ConfigExecuteServiceAccount: "remediator@proj.iam.gserviceaccount.com",
	})
	_, err := executionGCPOptions(context.Background(), c, "https://www.googleapis.com/auth/compute")
	if err != nil {
		require.Contains(t, err.Error(), "remediator@proj.iam.gserviceaccount.com",
			"a failure here must be about the EXECUTION account, not the collection token")
	}
}

func TestExecutionAzureCredential_RefusesWithoutAnExecutionPrincipal(t *testing.T) {
	c := rwConnector(connector.TypeAzure, map[string]string{
		"subscription_id": "sub", "tenant_id": "tenant",
		"client_id": "collector", "client_secret": "shhh",
	})
	_, err := executionAzureCredential(c)
	require.ErrorIs(t, err, ErrNoExecutionRole)
	require.Contains(t, err.Error(), ConfigExecuteClientID)
}

func TestExecutionAzureCredential_RefusesTheCollectionPrincipal(t *testing.T) {
	c := rwConnector(connector.TypeAzure, map[string]string{
		"tenant_id": "tenant", "client_id": "collector", "client_secret": "shhh",
		ConfigExecuteClientID: "collector", ConfigExecuteClientSecret: "other",
	})
	_, err := executionAzureCredential(c)
	require.ErrorIs(t, err, ErrNoExecutionRole)
	require.Contains(t, err.Error(), "collects with")
}

func TestExecutionAzureCredential_RefusesWithoutATenant(t *testing.T) {
	c := rwConnector(connector.TypeAzure, map[string]string{
		ConfigExecuteClientID: "remediator", ConfigExecuteClientSecret: "shhh",
	})
	_, err := executionAzureCredential(c)
	require.ErrorIs(t, err, ErrNoExecutionRole)
}

func TestExecutionAzureCredential_AcceptsADistinctPrincipal(t *testing.T) {
	c := rwConnector(connector.TypeAzure, map[string]string{
		"tenant_id": "tenant", "client_id": "collector",
		ConfigExecuteClientID: "remediator", ConfigExecuteClientSecret: "shhh",
	})
	cred, err := executionAzureCredential(c)
	require.NoError(t, err)
	require.NotNil(t, cred)
}
