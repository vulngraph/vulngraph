package mcp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/require"
)

// fakeConnectorConfig implements connectorConfig with a fixed config map —
// used to drive LiveAWSCallerImpl.awsConfig without a real connector.Service.
type fakeConnectorConfig struct {
	cfg map[string]string
	err error
}

func (f *fakeConnectorConfig) GetConfig(_ context.Context, _ string) (map[string]string, error) {
	return f.cfg, f.err
}

// staticConnectorCfg returns a connector config that authenticates with static
// keys against the given region — no STS AssumeRole call, so a test can point
// the IAM client at a local httptest server via AWS_ENDPOINT_URL_IAM without
// any real AWS network traffic (assuming a role would additionally hit STS).
func staticConnectorCfg(region string) map[string]string {
	return map[string]string{
		"region":                region,
		"aws_access_key_id":     "AKIAFAKEFAKEFAKEFAKE",
		"aws_secret_access_key": "fakefakefakefakefakefakefakefakefakefake",
	}
}

// An org child whose hub role trusts a principal: the base credential (here
// the hub key the org stores) assumes the hub role, and the hub session
// assumes the member role.
func TestAWSConfig_AssumesTheHubRoleFirst(t *testing.T) {
	hops := hubChainSTS(t)
	caller := NewLiveAWSCaller(&fakeConnectorConfig{cfg: map[string]string{
		"region":                "eu-west-1",
		"aws_access_key_id":     "AKIASTOREDHUBKEY",
		"aws_secret_access_key": "shhh",
		"hub_role_arn":          "arn:aws:iam::333333333333:role/GraphHub",
		"role_arn":              "arn:aws:iam::222222222222:role/GraphReadOnly",
		"external_id":           "ext-123",
	}})
	cfg, err := caller.awsConfig(context.Background(), "conn-1")
	require.NoError(t, err)
	creds, err := cfg.Credentials.Retrieve(context.Background())
	require.NoError(t, err)
	require.Equal(t, "ASIAROLE", creds.AccessKeyID)
	require.Equal(t, []stsHop{
		{role: "arn:aws:iam::333333333333:role/GraphHub", signedBy: "AKIASTOREDHUBKEY"},
		{role: "arn:aws:iam::222222222222:role/GraphReadOnly", signedBy: "ASIAHUB"},
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

const getRoleXML = `<GetRoleResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <GetRoleResult>
    <Role>
      <Path>/service-role/</Path>
      <RoleName>deploy</RoleName>
      <RoleId>AROAEXAMPLEID</RoleId>
      <Arn>arn:aws:iam::123456789012:role/service-role/deploy</Arn>
      <CreateDate>2015-03-09T20:00:35Z</CreateDate>
      <MaxSessionDuration>3600</MaxSessionDuration>
    </Role>
  </GetRoleResult>
  <ResponseMetadata>
    <RequestId>4a93ceee-c584-11e5-8395-6547e3f7e947</RequestId>
  </ResponseMetadata>
</GetRoleResponse>`

func TestGetRole_MapsRoleFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(getRoleXML))
	}))
	defer srv.Close()
	t.Setenv("AWS_ENDPOINT_URL_IAM", srv.URL)

	caller := NewLiveAWSCaller(&fakeConnectorConfig{cfg: staticConnectorCfg("us-east-1")})

	got, err := caller.GetRole(context.Background(), "conn-1", "arn:aws:iam::123456789012:role/service-role/deploy")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if got["arn"] != "arn:aws:iam::123456789012:role/service-role/deploy" {
		t.Errorf("arn = %v, want role ARN", got["arn"])
	}
	if got["role_name"] != "deploy" {
		t.Errorf("role_name = %v, want %q", got["role_name"], "deploy")
	}
	if got["path"] != "/service-role/" {
		t.Errorf("path = %v, want %q", got["path"], "/service-role/")
	}
	if got["max_session_duration"] != int32(3600) {
		t.Errorf("max_session_duration = %v, want 3600", got["max_session_duration"])
	}
}

func TestGetRole_UnparseableARN(t *testing.T) {
	caller := NewLiveAWSCaller(&fakeConnectorConfig{cfg: staticConnectorCfg("us-east-1")})

	_, err := caller.GetRole(context.Background(), "conn-1", "not-an-arn")
	if err == nil {
		t.Fatal("GetRole: expected error for unparseable ARN, got nil")
	}
}

// isGetBucketLocationRequest reports whether r is an S3 GetBucketLocation
// call (a GET on the bucket root with a "location" query param) as opposed
// to a GetObject call (a GET on the bucket+key path).
func isGetBucketLocationRequest(r *http.Request) bool {
	_, ok := r.URL.Query()["location"]
	return ok
}

// locationXML renders a GetBucketLocation response body for the given
// LocationConstraint value ("" means us-east-1/US Standard).
func locationXML(constraint string) string {
	if constraint == "" {
		return `<?xml version="1.0" encoding="UTF-8"?>
<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>`
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` + constraint + `</LocationConstraint>`
}

// newGetObjectFakeServer returns an httptest server that answers
// GetBucketLocation with locationXML(locationConstraint) and GetObject with
// objectBody/objectStatus — mirroring how a real S3-compatible endpoint
// multiplexes both operations on the same bucket path.
func newGetObjectFakeServer(t *testing.T, locationConstraint string, objectStatus int, objectBody []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isGetBucketLocationRequest(r) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(locationXML(locationConstraint)))
			return
		}
		if objectStatus != http.StatusOK {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(objectStatus)
			_, _ = w.Write(objectBody)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(objectBody)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGetObject_ReturnsBytes(t *testing.T) {
	want := []byte("terraform state blob contents")
	srv := newGetObjectFakeServer(t, "", http.StatusOK, want)
	t.Setenv("AWS_ENDPOINT_URL_S3", srv.URL)

	caller := NewLiveAWSCaller(&fakeConnectorConfig{cfg: staticConnectorCfg("us-east-1")})

	got, err := caller.GetObject(context.Background(), "conn-1", "tf-state-bucket", "envs/prod/terraform.tfstate")
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("GetObject = %q, want %q", got, want)
	}
}

func TestGetObject_OverCapReturnsError(t *testing.T) {
	oversized := bytes.Repeat([]byte("a"), s3GetObjectMaxBytes+1)
	srv := newGetObjectFakeServer(t, "", http.StatusOK, oversized)
	t.Setenv("AWS_ENDPOINT_URL_S3", srv.URL)

	caller := NewLiveAWSCaller(&fakeConnectorConfig{cfg: staticConnectorCfg("us-east-1")})

	got, err := caller.GetObject(context.Background(), "conn-1", "tf-state-bucket", "big.tfstate")
	if err == nil {
		t.Fatal("GetObject: expected error for object over size cap, got nil")
	}
	if got != nil {
		t.Errorf("GetObject: expected nil bytes on over-cap error, got %d bytes", len(got))
	}
}

func TestGetObject_ExactlyAtCapReturnsBytes(t *testing.T) {
	atCap := bytes.Repeat([]byte("a"), s3GetObjectMaxBytes)
	srv := newGetObjectFakeServer(t, "", http.StatusOK, atCap)
	t.Setenv("AWS_ENDPOINT_URL_S3", srv.URL)

	caller := NewLiveAWSCaller(&fakeConnectorConfig{cfg: staticConnectorCfg("us-east-1")})

	got, err := caller.GetObject(context.Background(), "conn-1", "tf-state-bucket", "at-cap.tfstate")
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	if !bytes.Equal(got, atCap) {
		t.Errorf("GetObject: got %d bytes, want %d bytes at exactly the cap", len(got), len(atCap))
	}
}

func TestGetObject_AccessDeniedWrapped(t *testing.T) {
	const accessDeniedXML = `<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied</Message>
  <RequestId>4a93ceee-c584-11e5-8395-6547e3f7e947</RequestId>
</Error>`
	srv := newGetObjectFakeServer(t, "", http.StatusForbidden, []byte(accessDeniedXML))
	t.Setenv("AWS_ENDPOINT_URL_S3", srv.URL)

	caller := NewLiveAWSCaller(&fakeConnectorConfig{cfg: staticConnectorCfg("us-east-1")})

	_, err := caller.GetObject(context.Background(), "conn-1", "tf-state-bucket", "secret.tfstate")
	if err == nil {
		t.Fatal("GetObject: expected error for AccessDenied, got nil")
	}
	if !strings.Contains(err.Error(), "GetObject:") {
		t.Errorf("GetObject error = %q, want wrapped with %q prefix", err.Error(), "GetObject:")
	}
}

// TestGetObject_CrossRegionBucket_ResolvesRegion covers the cross-region
// tfstate-bucket bug: GetBucketLocation reports eu-west-1 for a bucket whose
// connector is configured for us-east-1. GetObject must still succeed against
// the fake (both operations are served by the same httptest endpoint here,
// mirroring how AWS_ENDPOINT_URL_S3 pins every S3 call — including the
// rebuilt regional client — to one origin) and the resolved region must be
// threaded through to the S3 client build, not just the initial lookup.
func TestGetObject_CrossRegionBucket_ResolvesRegion(t *testing.T) {
	want := []byte("cross-region tfstate blob")
	srv := newGetObjectFakeServer(t, "eu-west-1", http.StatusOK, want)
	t.Setenv("AWS_ENDPOINT_URL_S3", srv.URL)

	caller := NewLiveAWSCaller(&fakeConnectorConfig{cfg: staticConnectorCfg("us-east-1")})

	got, err := caller.GetObject(context.Background(), "conn-1", "eu-tf-state-bucket", "envs/prod/terraform.tfstate")
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("GetObject = %q, want %q", got, want)
	}

	region := caller.resolveBucketRegion(context.Background(), mustAWSConfig(t, caller, "conn-1"), true, "eu-tf-state-bucket", "us-east-1")
	if region != "eu-west-1" {
		t.Errorf("resolveBucketRegion = %q, want %q", region, "eu-west-1")
	}
}

// TestGetObject_USEast1EmptyConstraint_ResolvesUSEast1 covers the AWS quirk
// where GetBucketLocation returns an empty LocationConstraint for buckets in
// us-east-1 (US Standard) rather than the literal string "us-east-1".
func TestGetObject_USEast1EmptyConstraint_ResolvesUSEast1(t *testing.T) {
	want := []byte("us-east-1 tfstate blob")
	srv := newGetObjectFakeServer(t, "", http.StatusOK, want)
	t.Setenv("AWS_ENDPOINT_URL_S3", srv.URL)

	caller := NewLiveAWSCaller(&fakeConnectorConfig{cfg: staticConnectorCfg("us-east-1")})

	got, err := caller.GetObject(context.Background(), "conn-1", "tf-state-bucket", "envs/prod/terraform.tfstate")
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("GetObject = %q, want %q", got, want)
	}

	region := caller.resolveBucketRegion(context.Background(), mustAWSConfig(t, caller, "conn-1"), true, "tf-state-bucket", "us-east-1")
	if region != "us-east-1" {
		t.Errorf("resolveBucketRegion = %q, want %q", region, "us-east-1")
	}
}

// TestGetObject_LocationLookupFails_FallsBackAndStillReads covers the
// fail-open path: GetBucketLocation errors (e.g. the caller's role lacks
// s3:GetBucketLocation, or the call itself fails) but GetObject must not
// hard-fail on the lookup — it falls back to the connector's config region
// and still attempts the read.
func TestGetObject_LocationLookupFails_FallsBackAndStillReads(t *testing.T) {
	want := []byte("fallback-region tfstate blob")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isGetBucketLocationRequest(r) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>boom</Message></Error>`))
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(want)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("AWS_ENDPOINT_URL_S3", srv.URL)

	caller := NewLiveAWSCaller(&fakeConnectorConfig{cfg: staticConnectorCfg("us-east-1")})

	got, err := caller.GetObject(context.Background(), "conn-1", "tf-state-bucket", "envs/prod/terraform.tfstate")
	if err != nil {
		t.Fatalf("GetObject: expected fallback to config region and a successful read, got error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("GetObject = %q, want %q", got, want)
	}
}

// mustAWSConfig is a test helper that builds the AWS config the same way
// GetObject does, for directly exercising resolveBucketRegion.
func mustAWSConfig(t *testing.T, caller *LiveAWSCallerImpl, connectorID string) awssdk.Config {
	t.Helper()
	cfg, err := caller.awsConfig(context.Background(), connectorID)
	if err != nil {
		t.Fatalf("awsConfig: %v", err)
	}
	return cfg
}

// LookupEvents' typed fields carry neither the caller IP nor the principal, so a
// credential-exfiltration investigation is blind without these. The raw record
// is the only source.
func TestParseCloudTrailDetail(t *testing.T) {
	const raw = `{
	  "eventVersion": "1.08",
	  "sourceIPAddress": "203.0.113.10",
	  "userAgent": "aws-cli/2.15.0",
	  "awsRegion": "us-west-2",
	  "errorCode": "AccessDenied",
	  "userIdentity": {
	    "type": "AssumedRole",
	    "arn": "arn:aws:sts::111122223333:assumed-role/orders-app-Task/abc123",
	    "principalId": "AROAEXAMPLE:abc123",
	    "accessKeyId": "ASIAEXAMPLE",
	    "sessionContext": {
	      "sessionIssuer": {
	        "userName": "orders-app-Task",
	        "arn": "arn:aws:iam::111122223333:role/orders-app-Task"
	      }
	    }
	  }
	}`

	got := parseCloudTrailDetail(raw)

	if got["source_ip"] != "203.0.113.10" {
		t.Errorf("source_ip = %v, want 203.0.113.10", got["source_ip"])
	}
	if got["principal_type"] != "AssumedRole" {
		t.Errorf("principal_type = %v, want AssumedRole", got["principal_type"])
	}
	if got["access_key_id"] != "ASIAEXAMPLE" {
		t.Errorf("access_key_id = %v, want ASIAEXAMPLE", got["access_key_id"])
	}
	if got["assumed_role_arn"] != "arn:aws:iam::111122223333:role/orders-app-Task" {
		t.Errorf("assumed_role_arn = %v", got["assumed_role_arn"])
	}
	if got["error_code"] != "AccessDenied" {
		t.Errorf("error_code = %v, want AccessDenied", got["error_code"])
	}
	if got["user_agent"] != "aws-cli/2.15.0" {
		t.Errorf("user_agent = %v", got["user_agent"])
	}
}

// A malformed or absent record must not fail the surrounding lookup.
func TestParseCloudTrailDetail_Unparseable(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":     "",
		"not json":  "{{{",
		"truncated": `{"sourceIPAddress":`,
		// Valid JSON that unmarshals cleanly into the zero value — must still be
		// reported as "nothing parsed" rather than a map of empty strings.
		"null":         "null",
		"empty object": "{}",
	} {
		t.Run(name, func(t *testing.T) {
			if got := parseCloudTrailDetail(raw); got != nil {
				t.Errorf("parseCloudTrailDetail(%q) = %v, want nil", raw, got)
			}
		})
	}
}

// Optional fields absent from the record must simply be omitted, not emitted as
// empty strings that read like real data.
func TestParseCloudTrailDetail_OmitsAbsentOptionals(t *testing.T) {
	got := parseCloudTrailDetail(`{"sourceIPAddress":"10.0.0.1","userIdentity":{"type":"IAMUser"}}`)

	if got["source_ip"] != "10.0.0.1" {
		t.Fatalf("source_ip = %v", got["source_ip"])
	}
	for _, k := range []string{
		"error_code", "invoked_by", "assumed_role_arn",
		// The ones that matter most: an empty access_key_id / principal_arn reads
		// like real data when it actually means "not recorded".
		"access_key_id", "principal_arn", "user_agent", "aws_region", "principal_id",
	} {
		if _, ok := got[k]; ok {
			t.Errorf("key %q present for a record that has no such field", k)
		}
	}
}
