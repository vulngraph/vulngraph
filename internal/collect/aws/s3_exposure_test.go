package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/require"
)

// fakeS3 defaults: no ownership controls (OwnershipControlsNotFoundError, the
// pre-2023 ACLs-enabled state) and no lifecycle configuration.
func (f *fakeS3) GetBucketOwnershipControls(_ context.Context, in *s3.GetBucketOwnershipControlsInput, _ ...func(*s3.Options)) (*s3.GetBucketOwnershipControlsOutput, error) {
	o, ok := f.ownership[awssdk.ToString(in.Bucket)]
	if !ok {
		return nil, apiErr{code: "OwnershipControlsNotFoundError"}
	}
	return &s3.GetBucketOwnershipControlsOutput{OwnershipControls: &s3types.OwnershipControls{
		Rules: []s3types.OwnershipControlsRule{{ObjectOwnership: o}},
	}}, nil
}

func (f *fakeS3) GetBucketLifecycleConfiguration(_ context.Context, in *s3.GetBucketLifecycleConfigurationInput, _ ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	r, ok := f.lifecycle[awssdk.ToString(in.Bucket)]
	if !ok {
		return nil, apiErr{code: "NoSuchLifecycleConfiguration"}
	}
	return &s3.GetBucketLifecycleConfigurationOutput{Rules: r}, nil
}

func (f *regionalS3) GetBucketOwnershipControls(_ context.Context, in *s3.GetBucketOwnershipControlsInput, opts ...func(*s3.Options)) (*s3.GetBucketOwnershipControlsOutput, error) {
	if err := f.check(awssdk.ToString(in.Bucket), opts); err != nil {
		return nil, err
	}
	return &s3.GetBucketOwnershipControlsOutput{OwnershipControls: &s3types.OwnershipControls{
		Rules: []s3types.OwnershipControlsRule{{ObjectOwnership: s3types.ObjectOwnershipBucketOwnerEnforced}},
	}}, nil
}

func (f *regionalS3) GetBucketLifecycleConfiguration(_ context.Context, in *s3.GetBucketLifecycleConfigurationInput, opts ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	if err := f.check(awssdk.ToString(in.Bucket), opts); err != nil {
		return nil, err
	}
	return nil, &apiErr{code: "NoSuchLifecycleConfiguration"}
}

func (f *boundedConcurrencyS3) GetBucketOwnershipControls(context.Context, *s3.GetBucketOwnershipControlsInput, ...func(*s3.Options)) (*s3.GetBucketOwnershipControlsOutput, error) {
	return nil, &apiErr{code: "OwnershipControlsNotFoundError"}
}

func (f *boundedConcurrencyS3) GetBucketLifecycleConfiguration(context.Context, *s3.GetBucketLifecycleConfigurationInput, ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	return nil, &apiErr{code: "NoSuchLifecycleConfiguration"}
}

func TestPolicyPublicGrants(t *testing.T) {
	tests := []struct {
		name               string
		doc                string
		read, write, known bool
	}{
		{"read only", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`, true, false, true},
		{"write only", `{"Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":["s3:PutObject"],"Resource":"arn:aws:s3:::b/*"}}`, false, true, true},
		{"s3 wildcard", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"*"}]}`, true, true, true},
		{"write taken back by a wildcard deny", `{"Statement":[
			{"Effect":"Allow","Principal":"*","Action":["s3:GetObject","s3:PutObject"],"Resource":"*"},
			{"Effect":"Deny","Principal":"*","Action":"s3:Put*","Resource":"*"}]}`, true, false, true},
		// The unconditioned statement is what is public; the VPC-endpoint
		// scoped write is not counted against it.
		{"unconditioned read, scoped write", `{"Statement":[
			{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"},
			{"Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"*","Condition":{"StringEquals":{"aws:SourceVpce":"vpce-1"}}}]}`, true, false, true},
		// AWS called it public on a condition it does not consider
		// restricting: the conditioned grant is the public one.
		{"only non-restricting conditioned grants", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"*","Condition":{"StringLike":{"aws:UserAgent":"*"}}}]}`, false, true, true},
		// A VPC-scoped GetObject is not public read just because a metadata
		// action is public: the split cannot name the public part.
		{"vpc-scoped read beside a public metadata grant", `{"Statement":[
			{"Effect":"Allow","Principal":"*","Action":"s3:GetBucketAcl","Resource":"*"},
			{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:SourceVpc":"vpc-1"}}}]}`, false, false, false},
		{"org-scoped grants only", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1"},"StringLike":{"aws:UserAgent":"*"}}}]}`, false, false, false},
		{"metadata action only", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetBucketLocation","Resource":"*"}]}`, false, false, false},
		{"named principal", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"s3:*","Resource":"*"}]}`, false, false, false},
		{"world source IP is no restriction", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"0.0.0.0/0"}}}]}`, true, false, true},
		{"Allow NotAction", `{"Statement":[{"Effect":"Allow","Principal":"*","NotAction":"s3:Delete*","Resource":"*"}]}`, true, true, true},
		{"everyone but one role", `{"Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":"arn:aws:iam::111122223333:role/r"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`, true, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, w, known := policyPublicGrants(tt.doc)
			require.Equal(t, tt.read, r, "read")
			require.Equal(t, tt.write, w, "write")
			require.Equal(t, tt.known, known, "known")
		})
	}
}

// A VPC-scoped read beside a public metadata grant stays with
// aws-s3-public-bucket (split unknown), not public_read=true.
func TestCollectS3Buckets_ScopedReadIsNotPublicRead(t *testing.T) {
	f := &fakeS3{
		buckets:      []s3types.Bucket{{Name: awssdk.String("b")}},
		policyPublic: map[string]bool{"b": true},
		policy: map[string]string{"b": `{"Statement":[
			{"Effect":"Allow","Principal":"*","Action":"s3:GetBucketAcl","Resource":"*"},
			{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:SourceVpc":"vpc-1"}}}]}`},
	}
	m := exposureMeta(t, f, accountBPA{observed: true})
	require.Equal(t, "confirmed", m["b"]["public_access"])
	require.NotContains(t, m["b"], "public_read")
	require.NotContains(t, m["b"], "public_write")
}

func exposureMeta(t *testing.T, f *fakeS3, acct accountBPA) map[string]map[string]string {
	t.Helper()
	assets, _, _, err := collectS3Buckets(context.Background(), f, acct, "111111111111", time.Now())
	require.NoError(t, err)
	out := map[string]map[string]string{}
	for _, a := range assets {
		out[a.Name] = a.Metadata
	}
	return out
}

func TestCollectS3Buckets_PublicReadWriteSplit(t *testing.T) {
	allUsers := func(p s3types.Permission) []s3types.Grant {
		return []s3types.Grant{{Grantee: &s3types.Grantee{Type: s3types.TypeGroup, URI: awssdk.String(s3AllUsersURI)}, Permission: p}}
	}
	f := &fakeS3{
		buckets: []s3types.Bucket{
			{Name: awssdk.String("policy-read")}, {Name: awssdk.String("acl-write")},
			{Name: awssdk.String("private")}, {Name: awssdk.String("denied")},
		},
		policyPublic: map[string]bool{"policy-read": true},
		policy: map[string]string{
			"policy-read": `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-read/*"}]}`,
		},
		acl:       map[string][]s3types.Grant{"acl-write": allUsers(s3types.PermissionWrite)},
		pubDenied: map[string]bool{"denied": true},
	}
	m := exposureMeta(t, f, accountBPA{observed: true})

	require.Equal(t, "confirmed", m["policy-read"]["public_access"])
	require.Equal(t, "true", m["policy-read"]["public_read"])
	require.Equal(t, "false", m["policy-read"]["public_write"])

	require.Equal(t, "confirmed", m["acl-write"]["public_access"])
	require.Equal(t, "false", m["acl-write"]["public_read"])
	require.Equal(t, "true", m["acl-write"]["public_write"])

	// No policy (NoSuchBucketPolicy) and an owner-only ACL: observed not-public.
	require.Equal(t, "false", m["private"]["public_read"])
	require.Equal(t, "false", m["private"]["public_write"])

	// PAB, policy status and ACL all refused: nothing is known.
	require.NotContains(t, m["denied"], "public_read")
	require.NotContains(t, m["denied"], "public_write")
}

func TestCollectS3Buckets_UnreadPolicyLeavesSplitUnknown(t *testing.T) {
	f := &fakeS3{
		buckets:      []s3types.Bucket{{Name: awssdk.String("b")}},
		policyPublic: map[string]bool{"b": true},
		policyErr:    apiErr{code: "AccessDenied"},
	}
	m := exposureMeta(t, f, accountBPA{observed: true})
	require.Equal(t, "confirmed", m["b"]["public_access"])
	require.NotContains(t, m["b"], "public_read", "a public policy that could not be read grants unknown actions")
	require.NotContains(t, m["b"], "policy_tls_enforced")
}

func TestCollectS3Buckets_BucketLevelBlockUnderAccountBlock(t *testing.T) {
	on := awssdk.Bool(true)
	full := &s3types.PublicAccessBlockConfiguration{BlockPublicAcls: on, IgnorePublicAcls: on, BlockPublicPolicy: on, RestrictPublicBuckets: on}
	f := &fakeS3{
		buckets:  []s3types.Bucket{{Name: awssdk.String("own-none")}, {Name: awssdk.String("own-full")}, {Name: awssdk.String("own-partial")}},
		ownBlock: map[string]*s3types.PublicAccessBlockConfiguration{"own-full": full, "own-partial": {BlockPublicAcls: on}},
	}
	m := exposureMeta(t, f, accountBPA{observed: true, cfg: full})
	for _, b := range []string{"own-none", "own-full", "own-partial"} {
		require.Equal(t, "true", m[b]["bpa_all_enabled"], "the account block makes every bucket effectively blocked")
		require.Equal(t, "false", m[b]["public_read"])
	}
	require.Equal(t, "false", m["own-none"]["bucket_bpa_all_enabled"])
	require.Equal(t, "true", m["own-full"]["bucket_bpa_all_enabled"])
	require.Equal(t, "false", m["own-partial"]["bucket_bpa_all_enabled"])
}

func TestCollectS3Buckets_OwnershipACLAndLifecycle(t *testing.T) {
	f := &fakeS3{
		buckets: []s3types.Bucket{{Name: awssdk.String("enforced")}, {Name: awssdk.String("legacy")}, {Name: awssdk.String("shared")}},
		ownership: map[string]s3types.ObjectOwnership{
			"enforced": s3types.ObjectOwnershipBucketOwnerEnforced,
			"shared":   s3types.ObjectOwnershipBucketOwnerPreferred,
		},
		acl: map[string][]s3types.Grant{
			"legacy": {{Grantee: &s3types.Grantee{Type: s3types.TypeCanonicalUser, ID: awssdk.String("owner-id")}, Permission: s3types.PermissionFullControl}},
			"shared": {
				{Grantee: &s3types.Grantee{Type: s3types.TypeCanonicalUser, ID: awssdk.String("owner-id")}, Permission: s3types.PermissionFullControl},
				{Grantee: &s3types.Grantee{Type: s3types.TypeCanonicalUser, ID: awssdk.String("partner")}, Permission: s3types.PermissionRead},
			},
		},
		lifecycle: map[string][]s3types.LifecycleRule{
			"enforced": {{Status: s3types.ExpirationStatusEnabled}, {Status: s3types.ExpirationStatusDisabled}},
			"legacy":   {{Status: s3types.ExpirationStatusDisabled}},
		},
	}
	m := exposureMeta(t, f, accountBPA{observed: true})
	require.Equal(t, "BucketOwnerEnforced", m["enforced"]["object_ownership"])
	require.Equal(t, "0", m["enforced"]["acl_non_owner_grants"], "ACLs disabled grant nothing")
	ownership, ok := m["legacy"]["object_ownership"]
	require.True(t, ok, "no ownership controls is an observation")
	require.Empty(t, ownership)
	require.Equal(t, "0", m["legacy"]["acl_non_owner_grants"])
	require.Equal(t, "1", m["shared"]["acl_non_owner_grants"])

	require.Equal(t, "1", m["enforced"]["lifecycle_rules_enabled"])
	require.Equal(t, "0", m["legacy"]["lifecycle_rules_enabled"])
	require.Equal(t, "0", m["shared"]["lifecycle_rules_enabled"], "NoSuchLifecycleConfiguration is an observed none")
}
