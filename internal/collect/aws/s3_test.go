package aws

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"
)

type fakeS3 struct {
	buckets      []s3types.Bucket
	blocked      map[string]bool // bucket name -> public-access-block fully locked
	policyPublic map[string]bool // bucket name -> policy status IsPublic
	aclPublic    map[string]bool // bucket name -> ACL grants AllUsers
	// enc maps a bucket to its GetBucketEncryption outcome. Nil means the
	// package default: the "not configured" AWS error.
	enc map[string]encResult
	// logErr / verErr fail GetBucketLogging / GetBucketVersioning for a bucket.
	// Neither API has a "not configured" error — a bucket with no logging or no
	// versioning answers 200 with an empty body — so every error here is a
	// permission, throttle, or transport gap and must NOT read as "disabled".
	logErr map[string]error
	verErr map[string]error
	// logOn / verStatus are the success-path answers.
	logOn     map[string]bool
	verStatus map[string]s3types.BucketVersioningStatus
	mfaOn     map[string]bool
	// pubDenied fails ALL THREE exposure calls (public-access-block, policy
	// status, ACL) for a bucket — the AccessDenied case that used to be graded
	// "possible" and badged PUBLIC? on the DSPM page.
	pubDenied map[string]bool
	// websiteErr fails GetBucketWebsite with something other than "no website".
	websiteErr error
	// panicOn makes GetBucketVersioning panic for that bucket.
	panicOn string
	// policy maps a bucket to its GetBucketPolicy document; policyErr fails
	// the call. A bucket in neither gets AWS's NoSuchBucketPolicy.
	policy    map[string]string
	policyErr error
	// ownership / acl / lifecycle feed s3_exposure.go's reads; see
	// s3_exposure_test.go for their defaults.
	ownership map[string]s3types.ObjectOwnership
	acl       map[string][]s3types.Grant
	lifecycle map[string][]s3types.LifecycleRule
	ownBlock  map[string]*s3types.PublicAccessBlockConfiguration
}

// encResult is one canned GetBucketEncryption answer.
type encResult struct {
	algo string // SSE algorithm to report on success
	err  error  // when set, the call fails with this
}

// apiErr is a smithy API error with a chosen code — S3 signals "no default
// encryption configured" as ServerSideEncryptionConfigurationNotFoundError and
// a permission gap as AccessDenied, and the collector must tell them apart.
type apiErr struct{ code string }

func (e apiErr) Error() string                 { return e.code }
func (e apiErr) ErrorCode() string             { return e.code }
func (e apiErr) ErrorMessage() string          { return e.code }
func (e apiErr) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func (f *fakeS3) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{Buckets: f.buckets}, nil
}
func (f *fakeS3) GetBucketLocation(context.Context, *s3.GetBucketLocationInput, ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	return &s3.GetBucketLocationOutput{LocationConstraint: "eu-west-1"}, nil
}
func (f *fakeS3) GetBucketPolicyStatus(_ context.Context, in *s3.GetBucketPolicyStatusInput, _ ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error) {
	if f.pubDenied[awssdk.ToString(in.Bucket)] {
		return nil, apiErr{code: "AccessDenied"}
	}
	if f.policyPublic[awssdk.ToString(in.Bucket)] {
		return &s3.GetBucketPolicyStatusOutput{PolicyStatus: &s3types.PolicyStatus{IsPublic: awssdk.Bool(true)}}, nil
	}
	return nil, errors.New("no policy") // force the ACL / public-access-block path
}
func (f *fakeS3) GetBucketAcl(_ context.Context, in *s3.GetBucketAclInput, _ ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	if f.pubDenied[awssdk.ToString(in.Bucket)] {
		return nil, apiErr{code: "AccessDenied"}
	}
	if g, ok := f.acl[awssdk.ToString(in.Bucket)]; ok {
		return &s3.GetBucketAclOutput{Grants: g, Owner: &s3types.Owner{ID: awssdk.String("owner-id")}}, nil
	}
	if f.aclPublic[awssdk.ToString(in.Bucket)] {
		return &s3.GetBucketAclOutput{Grants: []s3types.Grant{{
			Grantee:    &s3types.Grantee{Type: s3types.TypeGroup, URI: awssdk.String("http://acs.amazonaws.com/groups/global/AllUsers")},
			Permission: s3types.PermissionRead,
		}}}, nil
	}
	return &s3.GetBucketAclOutput{}, nil // owner-only ACL
}
func (f *fakeS3) GetBucketVersioning(_ context.Context, in *s3.GetBucketVersioningInput, _ ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	b := awssdk.ToString(in.Bucket)
	if b == f.panicOn {
		panic("simulated versioning panic")
	}
	if err := f.verErr[b]; err != nil {
		return nil, err
	}
	out := &s3.GetBucketVersioningOutput{Status: f.verStatus[b]} // empty status = never versioned
	if f.mfaOn[b] {
		out.MFADelete = s3types.MFADeleteStatusEnabled
	}
	return out, nil
}

func (f *fakeS3) GetBucketLogging(_ context.Context, in *s3.GetBucketLoggingInput, _ ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
	b := awssdk.ToString(in.Bucket)
	if err := f.logErr[b]; err != nil {
		return nil, err
	}
	if f.logOn[b] {
		return &s3.GetBucketLoggingOutput{LoggingEnabled: &s3types.LoggingEnabled{
			TargetBucket: awssdk.String("log-bucket"), TargetPrefix: awssdk.String(b + "/"),
		}}, nil
	}
	return &s3.GetBucketLoggingOutput{}, nil // 200 with no LoggingEnabled = observed off
}

func (f *fakeS3) GetBucketEncryption(_ context.Context, in *s3.GetBucketEncryptionInput, _ ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	r, ok := f.enc[awssdk.ToString(in.Bucket)]
	if !ok {
		// AWS's explicit "nothing configured" answer, not a failure.
		return nil, apiErr{code: "ServerSideEncryptionConfigurationNotFoundError"}
	}
	if r.err != nil {
		return nil, r.err
	}
	return &s3.GetBucketEncryptionOutput{
		ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
			Rules: []s3types.ServerSideEncryptionRule{{
				ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
					SSEAlgorithm: s3types.ServerSideEncryption(r.algo),
				},
			}},
		},
	}, nil
}

func (f *fakeS3) GetBucketWebsite(_ context.Context, _ *s3.GetBucketWebsiteInput, _ ...func(*s3.Options)) (*s3.GetBucketWebsiteOutput, error) {
	if f.websiteErr != nil {
		return nil, f.websiteErr
	}
	return nil, apiErr{code: "NoSuchWebsiteConfiguration"} // no website by default in tests
}

func (f *fakeS3) GetBucketPolicy(_ context.Context, in *s3.GetBucketPolicyInput, _ ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	if f.policyErr != nil {
		return nil, f.policyErr
	}
	if doc, ok := f.policy[awssdk.ToString(in.Bucket)]; ok {
		return &s3.GetBucketPolicyOutput{Policy: awssdk.String(doc)}, nil
	}
	return nil, apiErr{code: "NoSuchBucketPolicy"}
}

func (f *fakeS3) GetPublicAccessBlock(_ context.Context, in *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	if c, ok := f.ownBlock[awssdk.ToString(in.Bucket)]; ok {
		return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: c}, nil
	}
	if f.blocked[awssdk.ToString(in.Bucket)] {
		t := awssdk.Bool(true)
		return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls: t, IgnorePublicAcls: t, BlockPublicPolicy: t, RestrictPublicBuckets: t,
		}}, nil
	}
	if f.pubDenied[awssdk.ToString(in.Bucket)] {
		return nil, apiErr{code: "AccessDenied"}
	}
	// AWS's explicit "there is no block here" answer — an observation, which is
	// exactly the condition "possible" describes. A permission failure is NOT
	// this, and must not be graded.
	return nil, apiErr{code: "NoSuchPublicAccessBlockConfiguration"}
}

func TestCollectS3Buckets_PublicDetection(t *testing.T) {
	f := &fakeS3{
		buckets: []s3types.Bucket{
			{Name: awssdk.String("policy-public")},
			{Name: awssdk.String("acl-public")},
			{Name: awssdk.String("open-bucket")},
			{Name: awssdk.String("locked-bucket")},
		},
		blocked:      map[string]bool{"locked-bucket": true},
		policyPublic: map[string]bool{"policy-public": true},
		aclPublic:    map[string]bool{"acl-public": true},
	}
	got, edges, _, err := collectS3Buckets(context.Background(), f, accountBPA{}, "111122223333", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 4)

	// Only confirmed-public buckets create an internet edge.
	require.Len(t, edges, 2, "only confirmed-public buckets should be exposed")
	exposed := map[string]bool{}
	for _, e := range edges {
		require.Equal(t, "exposed_to_internet", e.EdgeType)
		exposed[e.SrcID] = true
	}
	require.True(t, exposed["policy-public"])
	require.True(t, exposed["acl-public"])

	pub := map[string]string{}
	tier := map[string]string{}
	for _, a := range got {
		require.Equal(t, "s3_bucket", a.Type)
		require.Equal(t, "eu-west-1", a.Region)
		pub[a.Name] = a.Metadata["public"]
		tier[a.Name] = a.Metadata["public_access"]
	}
	require.Equal(t, "true", pub["policy-public"])
	require.Equal(t, "confirmed", tier["policy-public"], "public policy status → confirmed")
	require.Equal(t, "true", pub["acl-public"])
	require.Equal(t, "confirmed", tier["acl-public"], "AllUsers ACL grant → confirmed")
	require.Equal(t, "true", pub["open-bucket"], "no public-access-block → still counts as public")
	require.Equal(t, "possible", tier["open-bucket"], "no public policy/ACL → only possible")
	require.Equal(t, "false", pub["locked-bucket"], "fully blocked → not public")
	require.Equal(t, "none", tier["locked-bucket"],
		"fully blocked is an OBSERVATION (read it, nothing public), not silence")
}

// TestCollectS3Buckets_PublicUnknownOnDeniedReads is the regression guard for the
// denied-reads-graded-public defect: a bucket whose public-access-block,
// policy status and ACL reads were ALL refused used to fall through to
// "possible", and the DSPM page badged it PUBLIC? on the strength of an
// AccessDenied. An error is unknown, not a signal.
func TestCollectS3Buckets_PublicUnknownOnDeniedReads(t *testing.T) {
	f := &fakeS3{
		buckets: []s3types.Bucket{
			{Name: awssdk.String("denied-bucket")},
			{Name: awssdk.String("readable-bucket")},
		},
		pubDenied: map[string]bool{"denied-bucket": true},
	}
	got, edges, _, err := collectS3Buckets(context.Background(), f, accountBPA{}, "111122223333", time.Now())
	require.NoError(t, err)
	require.Empty(t, edges, "an unreadable bucket must not seed an internet-exposure edge")

	tier := map[string]string{}
	pub := map[string]string{}
	for _, a := range got {
		tier[a.Name] = a.Metadata["public_access"]
		pub[a.Name] = a.Metadata["public"]
	}
	require.Equal(t, publicAccessUnknown, tier["denied-bucket"],
		"all three exposure reads refused → unknown, not possible")
	_, present := got[0].Metadata["public"]
	if got[0].Name != "denied-bucket" {
		_, present = got[1].Metadata["public"]
	}
	require.False(t, present,
		"unknown is neither public (inflates exposure counts) nor not-public (closes real findings)")
	require.Equal(t, "possible", tier["readable-bucket"],
		"an OBSERVED missing public-access-block is still possible")
	require.Equal(t, "true", pub["readable-bucket"])
}

// TestBucketPublicAccessPartialObservation pins the middle ground: one readable
// answer is enough to grade. Only a total blackout is unknown.
func TestBucketPublicAccessPartialObservation(t *testing.T) {
	// PAB and policy-status refused, but the ACL read fine and is owner-only.
	f := &fakeS3{
		buckets: []s3types.Bucket{{Name: awssdk.String("acl-only")}},
	}
	// Deny PAB + policy status, leave the ACL readable, by denying nothing and
	// relying on the fake's defaults for the ACL: assert via the helper directly.
	acl := readBucketACL(context.Background(), f, "acl-only", nil)
	require.False(t, acl.hasPublicGrantee())
	require.True(t, acl.aclObserved, "a 200 owner-only ACL is an observation")
}

// Encryption must distinguish "we could not read it" from "it is off". Writing
// "" for both turns a permission gap into High findings: a mostly-unencrypted
// result is not credible when AWS has applied SSE-S3 by default since
// January 2023.
func TestCollectS3Buckets_EncryptionUnknownVsNone(t *testing.T) {
	f := &fakeS3{
		buckets: []s3types.Bucket{
			{Name: awssdk.String("kms-bucket")},
			{Name: awssdk.String("sse-s3-bucket")},
			{Name: awssdk.String("none-bucket")},
			{Name: awssdk.String("denied-bucket")},
			{Name: awssdk.String("throttled-bucket")},
		},
		enc: map[string]encResult{
			"kms-bucket":       {algo: "aws:kms"},
			"sse-s3-bucket":    {algo: "AES256"},
			"denied-bucket":    {err: apiErr{code: "AccessDenied"}},
			"throttled-bucket": {err: errors.New("dial tcp: i/o timeout")},
			// none-bucket is absent → the "not configured" AWS error.
		},
	}
	got, _, _, err := collectS3Buckets(context.Background(), f, accountBPA{}, "111122223333", time.Now())
	require.NoError(t, err)

	meta := map[string]map[string]string{}
	for _, a := range got {
		meta[a.Name] = a.Metadata
	}
	require.Equal(t, "aws:kms", meta["kms-bucket"]["encryption"])
	require.Equal(t, "AES256", meta["sse-s3-bucket"]["encryption"])

	// Observed-none: the key is PRESENT and empty — that is what checks.observedNone
	// requires to fire. Unknown: the key is absent, so nothing fires.
	require.Contains(t, meta["none-bucket"], "encryption", "AWS said nothing is configured — a real observation")
	require.Equal(t, "", meta["none-bucket"]["encryption"])
	require.NotContains(t, meta["denied-bucket"], "encryption", "AccessDenied is not evidence of missing encryption")
	require.NotContains(t, meta["throttled-bucket"], "encryption", "a transport failure is not evidence either")
}

func TestBucketEncryptionAlgorithm_ObservedFlag(t *testing.T) {
	cases := []struct {
		name         string
		enc          map[string]encResult
		wantAlgo     string
		wantObserved bool
	}{
		{"kms", map[string]encResult{"b": {algo: "aws:kms"}}, "aws:kms", true},
		{"sse-s3", map[string]encResult{"b": {algo: "AES256"}}, "AES256", true},
		{"not configured", nil, "", true},
		{"access denied", map[string]encResult{"b": {err: apiErr{code: "AccessDenied"}}}, "", false},
		{"throttled", map[string]encResult{"b": {err: apiErr{code: "SlowDown"}}}, "", false},
		{"transport", map[string]encResult{"b": {err: errors.New("i/o timeout")}}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			algo, observed := bucketEncryptionAlgorithm(context.Background(), &fakeS3{enc: tc.enc}, "b", regionOpt(""))
			require.Equal(t, tc.wantObserved, observed)
			require.Equal(t, tc.wantAlgo, algo)
		})
	}
}

func TestIsNoEncryptionConfigErr(t *testing.T) {
	require.True(t, isNoEncryptionConfigErr(fmt.Errorf("wrapped: %w", apiErr{code: "ServerSideEncryptionConfigurationNotFoundError"})))
	require.False(t, isNoEncryptionConfigErr(apiErr{code: "AccessDenied"}))
	require.False(t, isNoEncryptionConfigErr(errors.New("i/o timeout")))
	require.False(t, isNoEncryptionConfigErr(nil))
}

// The logging and versioning halves of the same fix: bucketEncryptionAlgorithm
// was converted to distinguish a failed call from an observed absence, and its
// two per-bucket siblings in the same file were left returning "disabled" /
// "Disabled" on error — the exact values aws-s3-access-logging-disabled,
// aws-s3-no-versioning and aws-s3-no-mfa-delete fire on. Under a permission gap
// those three fire on every affected bucket.
func TestCollectS3Buckets_LoggingVersioningUnknownVsObserved(t *testing.T) {
	f := &fakeS3{
		buckets: []s3types.Bucket{
			{Name: awssdk.String("logged")},
			{Name: awssdk.String("unlogged")},
			{Name: awssdk.String("log-denied")},
			{Name: awssdk.String("versioned")},
			{Name: awssdk.String("suspended")},
			{Name: awssdk.String("unversioned")},
			{Name: awssdk.String("ver-throttled")},
		},
		logOn:  map[string]bool{"logged": true},
		logErr: map[string]error{"log-denied": apiErr{code: "AccessDenied"}},
		verStatus: map[string]s3types.BucketVersioningStatus{
			"versioned": s3types.BucketVersioningStatusEnabled,
			"suspended": s3types.BucketVersioningStatusSuspended,
		},
		mfaOn:  map[string]bool{"versioned": true},
		verErr: map[string]error{"ver-throttled": errors.New("dial tcp: i/o timeout")},
	}
	got, _, _, err := collectS3Buckets(context.Background(), f, accountBPA{}, "111122223333", time.Now())
	require.NoError(t, err)

	meta := map[string]map[string]string{}
	for _, a := range got {
		meta[a.Name] = a.Metadata
	}

	require.Equal(t, "enabled", meta["logged"]["logging"])
	require.Equal(t, "disabled", meta["unlogged"]["logging"], "a 200 with no LoggingEnabled is a real observation")
	require.NotContains(t, meta["log-denied"], "logging", "AccessDenied is not evidence that logging is off")

	require.Equal(t, "enabled", meta["versioned"]["versioning"])
	require.Equal(t, "Enabled", meta["versioned"]["mfa_delete"])
	require.Equal(t, "suspended", meta["suspended"]["versioning"])
	require.Equal(t, "disabled", meta["unversioned"]["versioning"], "an empty Status is a real observation")
	require.Equal(t, "Disabled", meta["unversioned"]["mfa_delete"])
	// Both keys come from the one call, so both must go when it fails — otherwise
	// aws-s3-no-mfa-delete reads the surviving half as a violation.
	require.NotContains(t, meta["ver-throttled"], "versioning", "a transport failure is not evidence either")
	require.NotContains(t, meta["ver-throttled"], "mfa_delete")
}

func TestBucketLoggingStatus_ObservedFlag(t *testing.T) {
	cases := []struct {
		name         string
		f            *fakeS3
		wantStatus   string
		wantObserved bool
	}{
		{"logging on", &fakeS3{logOn: map[string]bool{"b": true}}, "enabled", true},
		{"logging off", &fakeS3{}, "disabled", true},
		{"access denied", &fakeS3{logErr: map[string]error{"b": apiErr{code: "AccessDenied"}}}, "", false},
		{"throttled", &fakeS3{logErr: map[string]error{"b": apiErr{code: "SlowDown"}}}, "", false},
		{"transport", &fakeS3{logErr: map[string]error{"b": errors.New("i/o timeout")}}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, observed := bucketLoggingStatus(context.Background(), tc.f, "b", regionOpt(""))
			require.Equal(t, tc.wantObserved, observed)
			require.Equal(t, tc.wantStatus, status)
		})
	}
}

func TestBucketVersioningAndMFA_ObservedFlag(t *testing.T) {
	cases := []struct {
		name         string
		f            *fakeS3
		wantVer      string
		wantMFA      string
		wantObserved bool
	}{
		{"enabled with mfa", &fakeS3{
			verStatus: map[string]s3types.BucketVersioningStatus{"b": s3types.BucketVersioningStatusEnabled},
			mfaOn:     map[string]bool{"b": true},
		}, "enabled", "Enabled", true},
		{"suspended", &fakeS3{
			verStatus: map[string]s3types.BucketVersioningStatus{"b": s3types.BucketVersioningStatusSuspended},
		}, "suspended", "Disabled", true},
		{"never versioned", &fakeS3{}, "disabled", "Disabled", true},
		{"access denied", &fakeS3{verErr: map[string]error{"b": apiErr{code: "AccessDenied"}}}, "", "", false},
		{"transport", &fakeS3{verErr: map[string]error{"b": errors.New("i/o timeout")}}, "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ver, mfa, observed := bucketVersioningAndMFA(context.Background(), tc.f, "b", regionOpt(""))
			require.Equal(t, tc.wantObserved, observed)
			require.Equal(t, tc.wantVer, ver)
			require.Equal(t, tc.wantMFA, mfa)
		})
	}
}

// pagedS3 serves its buckets one page at a time, echoing a ContinuationToken exactly as
// the real API does, and records how many calls it received.
type pagedS3 struct {
	fakeS3
	pages [][]s3types.Bucket
	calls int
	// failOnPage, when >0, returns an error on that 1-indexed page so the test can
	// assert a mid-listing failure aborts rather than returning a partial set.
	failOnPage int
}

func (p *pagedS3) ListBuckets(_ context.Context, in *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	idx := 0
	if in != nil && in.ContinuationToken != nil {
		// Token is the next page index, encoded as a string.
		_, _ = fmt.Sscanf(*in.ContinuationToken, "%d", &idx)
	}
	p.calls++
	if p.failOnPage == p.calls {
		return nil, errors.New("throttled mid-listing")
	}
	if idx >= len(p.pages) {
		return &s3.ListBucketsOutput{}, nil
	}
	out := &s3.ListBucketsOutput{Buckets: p.pages[idx]}
	if idx+1 < len(p.pages) {
		next := fmt.Sprintf("%d", idx+1)
		out.ContinuationToken = &next
	}
	return out, nil
}

// TestCollectS3Buckets_PaginatesToExhaustion pins the completeness guarantee.
//
// ListBuckets was called exactly once. An account past one page therefore reported a
// SUBSET of its buckets, and that is worse than incomplete inventory: SyncWorker treats
// a non-partial collect as proof of a complete enumeration and resolves the findings of
// every asset the sweep did not return (jobs/sync.go, "absent≠deleted"), so a truncated
// page reads as "these buckets were deleted". Latent for accounts below the
// default page size, and silent for any account above it.
func TestCollectS3Buckets_PaginatesToExhaustion(t *testing.T) {
	name := func(s string) *string { return &s }
	client := &pagedS3{pages: [][]s3types.Bucket{
		{{Name: name("a")}, {Name: name("b")}},
		{{Name: name("c")}},
		{{Name: name("d")}},
	}}

	assets, _, _, err := collectS3Buckets(context.Background(), client, accountBPA{}, "111122223333", time.Now())
	require.NoError(t, err)
	require.Len(t, assets, 4, "every page must be collected; got only the first %d", len(assets))
	require.Equal(t, 3, client.calls, "should stop when the token clears, not re-request")

	got := make([]string, 0, len(assets))
	for _, a := range assets {
		got = append(got, a.Name)
	}
	require.ElementsMatch(t, []string{"a", "b", "c", "d"}, got)
}

// A page failure must abort the whole listing. Returning the pages that happened to
// arrive is what would let a throttle read as a mass deletion.
func TestCollectS3Buckets_PageErrorAbortsListing(t *testing.T) {
	name := func(s string) *string { return &s }
	client := &pagedS3{
		pages:      [][]s3types.Bucket{{{Name: name("a")}}, {{Name: name("b")}}},
		failOnPage: 2,
	}
	assets, _, _, err := collectS3Buckets(context.Background(), client, accountBPA{}, "111122223333", time.Now())
	require.Error(t, err, "a mid-listing page error must propagate, never return a partial set")
	require.Empty(t, assets, "no assets may be returned from a failed listing")
}
