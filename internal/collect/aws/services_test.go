package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// errNoPolicy simulates the NoSuchEntity/ResourceNotFound/AccessDenied family
// of errors AWS returns for a resource with no resource-based policy attached
// — the common case for every service in this file.
var errNoPolicy = errors.New("no resource policy")

type fakeKMS struct {
	keys        []kmstypes.KeyListEntry
	keyPolicy   string
	policyErr   error
	rotationErr error
	meta        *kmstypes.KeyMetadata // nil: a customer key pending deletion
}

func (f *fakeKMS) ListKeys(context.Context, *kms.ListKeysInput, ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	return &kms.ListKeysOutput{Keys: f.keys}, nil
}

func (f *fakeKMS) DescribeKey(_ context.Context, in *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if f.meta != nil {
		return &kms.DescribeKeyOutput{KeyMetadata: f.meta}, nil
	}
	return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{
		KeyId:      in.KeyId,
		KeyManager: kmstypes.KeyManagerTypeCustomer,
		KeyState:   kmstypes.KeyStatePendingDeletion,
	}}, nil
}

func (f *fakeKMS) GetKeyRotationStatus(_ context.Context, _ *kms.GetKeyRotationStatusInput, _ ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
	if f.rotationErr != nil {
		return nil, f.rotationErr
	}
	return &kms.GetKeyRotationStatusOutput{KeyRotationEnabled: true}, nil
}

func (f *fakeKMS) GetKeyPolicy(context.Context, *kms.GetKeyPolicyInput, ...func(*kms.Options)) (*kms.GetKeyPolicyOutput, error) {
	if f.policyErr != nil {
		return nil, f.policyErr
	}
	return &kms.GetKeyPolicyOutput{Policy: awssdk.String(f.keyPolicy)}, nil
}

type fakeECR struct {
	repos      []ecrtypes.Repository
	repoPolicy string
	policyErr  error
	// registry is the registry scanning configuration; nil answers with an
	// error, the unreadable case.
	registry *ecrtypes.RegistryScanningConfiguration
	// lifecycle maps a repository to its lifecycle policy text; a repository
	// absent from it has none (LifecyclePolicyNotFoundException).
	lifecycle    map[string]string
	lifecycleErr error
}

func (f *fakeECR) GetLifecyclePolicy(_ context.Context, in *ecr.GetLifecyclePolicyInput, _ ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error) {
	if f.lifecycleErr != nil {
		return nil, f.lifecycleErr
	}
	text, ok := f.lifecycle[awssdk.ToString(in.RepositoryName)]
	if !ok {
		return nil, &ecrtypes.LifecyclePolicyNotFoundException{Message: awssdk.String("Lifecycle policy does not exist")}
	}
	return &ecr.GetLifecyclePolicyOutput{RepositoryName: in.RepositoryName, LifecyclePolicyText: awssdk.String(text)}, nil
}

func (f *fakeECR) GetRegistryScanningConfiguration(context.Context, *ecr.GetRegistryScanningConfigurationInput, ...func(*ecr.Options)) (*ecr.GetRegistryScanningConfigurationOutput, error) {
	if f.registry == nil {
		return nil, errors.New("AccessDeniedException")
	}
	return &ecr.GetRegistryScanningConfigurationOutput{ScanningConfiguration: f.registry}, nil
}

func (f *fakeECR) DescribeRepositories(context.Context, *ecr.DescribeRepositoriesInput, ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	return &ecr.DescribeRepositoriesOutput{Repositories: f.repos}, nil
}

func (f *fakeECR) GetRepositoryPolicy(context.Context, *ecr.GetRepositoryPolicyInput, ...func(*ecr.Options)) (*ecr.GetRepositoryPolicyOutput, error) {
	if f.policyErr != nil {
		return nil, f.policyErr
	}
	return &ecr.GetRepositoryPolicyOutput{PolicyText: awssdk.String(f.repoPolicy)}, nil
}

type fakeSQS struct {
	urls        []string
	queuePolicy string
	policyErr   error
	extra       map[string]string // further attributes, e.g. the encryption pair
}

func (f *fakeSQS) ListQueues(context.Context, *sqs.ListQueuesInput, ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
	return &sqs.ListQueuesOutput{QueueUrls: f.urls}, nil
}

func (f *fakeSQS) GetQueueAttributes(context.Context, *sqs.GetQueueAttributesInput, ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	if f.policyErr != nil {
		return nil, f.policyErr
	}
	attrs := map[string]string{}
	for k, v := range f.extra {
		attrs[k] = v
	}
	if f.queuePolicy != "" {
		attrs["Policy"] = f.queuePolicy
	}
	return &sqs.GetQueueAttributesOutput{Attributes: attrs}, nil
}

type fakeSNS struct {
	topics      []snstypes.Topic
	topicPolicy string
	policyErr   error
}

func (f *fakeSNS) ListTopics(context.Context, *sns.ListTopicsInput, ...func(*sns.Options)) (*sns.ListTopicsOutput, error) {
	return &sns.ListTopicsOutput{Topics: f.topics}, nil
}

func (f *fakeSNS) GetTopicAttributes(context.Context, *sns.GetTopicAttributesInput, ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error) {
	if f.policyErr != nil {
		return nil, f.policyErr
	}
	attrs := map[string]string{}
	if f.topicPolicy != "" {
		attrs["Policy"] = f.topicPolicy
	}
	return &sns.GetTopicAttributesOutput{Attributes: attrs}, nil
}

func TestSimpleServiceCollectors(t *testing.T) {
	now := time.Now()

	k, err := collectKMSKeys(context.Background(), &fakeKMS{keys: []kmstypes.KeyListEntry{
		{KeyId: awssdk.String("k1"), KeyArn: awssdk.String("arn:aws:kms:eu-west-1:1:key/k1")},
	}}, "eu-west-1", "1", now)
	require.NoError(t, err)
	require.Len(t, k, 1)
	require.Equal(t, "kms_key", k[0].Type)
	require.Equal(t, "PendingDeletion", k[0].Metadata["key_state"])

	e, err := collectECRRepos(context.Background(), &fakeECR{repos: []ecrtypes.Repository{
		{RepositoryName: awssdk.String("app"), RepositoryArn: awssdk.String("arn:..."), RepositoryUri: awssdk.String("1.dkr.ecr.eu-west-1.amazonaws.com/app")},
	}}, "eu-west-1", "1", now)
	require.NoError(t, err)
	require.Len(t, e, 1)
	require.Equal(t, "ecr_repository", e[0].Type)
	require.Contains(t, e[0].Endpoint, "dkr.ecr")

	q, err := collectSQSQueues(context.Background(), &fakeSQS{urls: []string{"https://sqs.eu-west-1.amazonaws.com/1/orders"}}, "eu-west-1", "1", now)
	require.NoError(t, err)
	require.Len(t, q, 1)
	require.Equal(t, "sqs_queue", q[0].Type)
	require.Equal(t, "orders", q[0].Name)

	s, err := collectSNSTopics(context.Background(), &fakeSNS{topics: []snstypes.Topic{
		{TopicArn: awssdk.String("arn:aws:sns:eu-west-1:1:alerts")},
	}}, "eu-west-1", "1", now)
	require.NoError(t, err)
	require.Len(t, s, 1)
	require.Equal(t, "sns_topic", s[0].Type)
	require.Equal(t, "alerts", s[0].Name)
}

// TestKMSResourcePolicy_PublicKeyPolicy verifies collectKMSKeys wires the
// GetKeyPolicy result through to public_access + policies metadata, and that
// a policy fetch error (AccessDenied under a restrictive collector role)
// does not drop the key or fail collection.
func TestKMSResourcePolicy_PublicKeyPolicy(t *testing.T) {
	now := time.Now()

	k, err := collectKMSKeys(context.Background(), &fakeKMS{
		keys:      []kmstypes.KeyListEntry{{KeyId: awssdk.String("k1"), KeyArn: awssdk.String("arn:aws:kms:eu-west-1:1:key/k1")}},
		keyPolicy: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:Decrypt","Resource":"*"}]}`,
	}, "eu-west-1", "1", now)
	require.NoError(t, err)
	require.Len(t, k, 1)
	require.Equal(t, asset.PublicAccessConfirmed, k[0].Metadata["public_access"])
	require.Contains(t, k[0].Metadata["policies"], `"type":"resource"`)

	k2, err := collectKMSKeys(context.Background(), &fakeKMS{
		keys:      []kmstypes.KeyListEntry{{KeyId: awssdk.String("k2"), KeyArn: awssdk.String("arn:aws:kms:eu-west-1:1:key/k2")}},
		policyErr: errNoPolicy,
	}, "eu-west-1", "1", now)
	require.NoError(t, err)
	require.Len(t, k2, 1)
	require.Empty(t, k2[0].Metadata["public_access"])
	require.Empty(t, k2[0].Metadata["policies"])
}

// A failed rotation read keeps the key in inventory with rotation_enabled
// absent (unknown), instead of dropping the key.
func TestKMSRotationErrorKeepsKeyOmitsRotation(t *testing.T) {
	k, err := collectKMSKeys(context.Background(), &fakeKMS{
		keys:        []kmstypes.KeyListEntry{{KeyId: awssdk.String("k1"), KeyArn: awssdk.String("arn:aws:kms:eu-west-1:1:key/k1")}},
		rotationErr: errors.New("throttled"),
	}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Len(t, k, 1)
	_, present := k[0].Metadata["rotation_enabled"]
	require.False(t, present)
}

// DescribeKey's spec, origin, custom key store and multi-Region role are
// recorded so rotation is graded only on keys that can rotate; an unset value
// stays absent.
func TestKMSKeyKindMetadata(t *testing.T) {
	keys := []kmstypes.KeyListEntry{{KeyId: awssdk.String("k1"), KeyArn: awssdk.String("arn:aws:kms:eu-west-1:1:key/k1")}}
	tests := []struct {
		name string
		meta kmstypes.KeyMetadata
		want map[string]string
		gone []string
	}{
		{"symmetric KMS-generated", kmstypes.KeyMetadata{
			KeyManager: kmstypes.KeyManagerTypeCustomer, KeyState: kmstypes.KeyStateEnabled,
			KeySpec: kmstypes.KeySpecSymmetricDefault, Origin: kmstypes.OriginTypeAwsKms, MultiRegion: awssdk.Bool(false),
		}, map[string]string{"key_spec": "SYMMETRIC_DEFAULT", "key_origin": "AWS_KMS", "custom_key_store_id": "", "multi_region_key_type": ""}, nil},
		{"multi-Region primary", kmstypes.KeyMetadata{
			KeyManager: kmstypes.KeyManagerTypeCustomer, KeyState: kmstypes.KeyStateEnabled, MultiRegion: awssdk.Bool(true),
			MultiRegionConfiguration: &kmstypes.MultiRegionConfiguration{MultiRegionKeyType: kmstypes.MultiRegionKeyTypePrimary},
		}, map[string]string{"multi_region_key_type": "PRIMARY"}, nil},
		{"multi-Region replica", kmstypes.KeyMetadata{
			KeyManager: kmstypes.KeyManagerTypeCustomer, KeyState: kmstypes.KeyStateEnabled, MultiRegion: awssdk.Bool(true),
			MultiRegionConfiguration: &kmstypes.MultiRegionConfiguration{MultiRegionKeyType: kmstypes.MultiRegionKeyTypeReplica},
		}, map[string]string{"multi_region_key_type": "REPLICA"}, nil},
		{"multi-Region without its configuration", kmstypes.KeyMetadata{
			KeyManager: kmstypes.KeyManagerTypeCustomer, KeyState: kmstypes.KeyStateEnabled, MultiRegion: awssdk.Bool(true),
		}, nil, []string{"multi_region_key_type"}},
		{"CloudHSM key store", kmstypes.KeyMetadata{
			KeyManager: kmstypes.KeyManagerTypeCustomer, KeyState: kmstypes.KeyStateEnabled,
			KeySpec: kmstypes.KeySpecSymmetricDefault, Origin: kmstypes.OriginTypeAwsCloudhsm, CustomKeyStoreId: awssdk.String("cks-1"),
		}, map[string]string{"key_spec": "SYMMETRIC_DEFAULT", "key_origin": "AWS_CLOUDHSM", "custom_key_store_id": "cks-1"}, nil},
		{"spec and origin unset", kmstypes.KeyMetadata{
			KeyManager: kmstypes.KeyManagerTypeCustomer, KeyState: kmstypes.KeyStateEnabled,
		}, map[string]string{"custom_key_store_id": ""}, []string{"key_spec", "key_origin", "multi_region_key_type"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := tt.meta
			k, err := collectKMSKeys(context.Background(), &fakeKMS{keys: keys, meta: &meta}, "eu-west-1", "1", time.Now())
			require.NoError(t, err)
			require.Len(t, k, 1)
			for key, v := range tt.want {
				got, ok := k[0].Metadata[key]
				require.True(t, ok, key)
				require.Equal(t, v, got, key)
			}
			for _, key := range tt.gone {
				require.NotContains(t, k[0].Metadata, key)
			}
		})
	}
	k, err := collectKMSKeys(context.Background(), &fakeKMS{keys: keys, meta: &kmstypes.KeyMetadata{
		KeyManager: kmstypes.KeyManagerTypeAws, KeyState: kmstypes.KeyStateEnabled,
	}}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Empty(t, k, "AWS-managed keys are not collected")
}

func TestECRResourcePolicy_PublicRepoPolicy(t *testing.T) {
	now := time.Now()

	e, err := collectECRRepos(context.Background(), &fakeECR{
		repos:      []ecrtypes.Repository{{RepositoryName: awssdk.String("app"), RepositoryArn: awssdk.String("arn:..."), RepositoryUri: awssdk.String("uri")}},
		repoPolicy: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"ecr:BatchGetImage","Resource":"*"}]}`,
	}, "eu-west-1", "1", now)
	require.NoError(t, err)
	require.Len(t, e, 1)
	require.Equal(t, asset.PublicAccessConfirmed, e[0].Metadata["public_access"])

	// A public grant of a describe-only action must not be graded public.
	e2, err := collectECRRepos(context.Background(), &fakeECR{
		repos:      []ecrtypes.Repository{{RepositoryName: awssdk.String("app2"), RepositoryArn: awssdk.String("arn:...2"), RepositoryUri: awssdk.String("uri2")}},
		repoPolicy: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"ecr:DescribeImages","Resource":"*"}]}`,
	}, "eu-west-1", "1", now)
	require.NoError(t, err)
	require.Len(t, e2, 1)
	require.Equal(t, asset.PublicAccessNone, e2[0].Metadata["public_access"],
		"a policy that grants nothing sensitive to the public must be an observation, not absence")

	// A generic policy fetch error (AccessDenied, throttle) must leave BOTH keys
	// absent: this repository was never described at all, and an unreadable
	// policy must not be guessed at in either direction.
	e3, err := collectECRRepos(context.Background(), &fakeECR{
		repos:     []ecrtypes.Repository{{RepositoryName: awssdk.String("app3"), RepositoryArn: awssdk.String("arn:...3"), RepositoryUri: awssdk.String("uri3")}},
		policyErr: errNoPolicy,
	}, "eu-west-1", "1", now)
	require.NoError(t, err)
	require.Len(t, e3, 1)
	require.NotContains(t, e3[0].Metadata, "public_access")

	// The COMMON case, distinguished from the generic error above:
	// RepositoryPolicyNotFoundException is what GetRepositoryPolicy answers for
	// the majority of repositories, which have no resource policy at all. This IS
	// an observation — nothing is granted to the public — same shape as the
	// three-way verdict lambdaPublicAccess (collect/aws/lambda.go) already has.
	e4, err := collectECRRepos(context.Background(), &fakeECR{
		repos:     []ecrtypes.Repository{{RepositoryName: awssdk.String("app4"), RepositoryArn: awssdk.String("arn:...4"), RepositoryUri: awssdk.String("uri4")}},
		policyErr: &ecrtypes.RepositoryPolicyNotFoundException{},
	}, "eu-west-1", "1", now)
	require.NoError(t, err)
	require.Len(t, e4, 1)
	require.Equal(t, asset.PublicAccessNone, e4[0].Metadata["public_access"])
	require.NotContains(t, e4[0].Metadata, "policies", "no document exists to store, only the observation")
}

func TestSQSResourcePolicy_PublicQueuePolicy(t *testing.T) {
	now := time.Now()

	q, err := collectSQSQueues(context.Background(), &fakeSQS{
		urls:        []string{"https://sqs.eu-west-1.amazonaws.com/1/orders"},
		queuePolicy: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:ReceiveMessage","Resource":"*"}]}`,
	}, "eu-west-1", "1", now)
	require.NoError(t, err)
	require.Len(t, q, 1)
	require.Equal(t, asset.PublicAccessConfirmed, q[0].Metadata["public_access"])

	// Condition-scoped wildcard (standard cross-account pattern) is NOT public.
	q2, err := collectSQSQueues(context.Background(), &fakeSQS{
		urls: []string{"https://sqs.eu-west-1.amazonaws.com/1/internal"},
		queuePolicy: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:ReceiveMessage","Resource":"*",
			"Condition":{"StringEquals":{"aws:SourceAccount":"999988887777"}}}]}`,
	}, "eu-west-1", "1", now)
	require.NoError(t, err)
	require.Len(t, q2, 1)
	require.Equal(t, asset.PublicAccessNone, q2[0].Metadata["public_access"],
		"a Condition-scoped wildcard is not public — but it WAS observed and read, so the key must not be absent")

	// A queue with genuinely NO policy: GetQueueAttributes succeeds and the
	// "Policy" attribute is simply absent from the map — not an error. This is
	// the common case (most queues have no policy) and must not collapse
	// into the same missing key as an unreadable queue.
	q3, err := collectSQSQueues(context.Background(), &fakeSQS{
		urls: []string{"https://sqs.eu-west-1.amazonaws.com/1/no-policy"},
	}, "eu-west-1", "1", now)
	require.NoError(t, err)
	require.Len(t, q3, 1)
	require.Equal(t, asset.PublicAccessNone, q3[0].Metadata["public_access"],
		"no policy is a real observation (nothing is granted), not an unreadable queue")
}

func TestSNSResourcePolicy_PublicTopicPolicy(t *testing.T) {
	now := time.Now()

	s, err := collectSNSTopics(context.Background(), &fakeSNS{
		topics:      []snstypes.Topic{{TopicArn: awssdk.String("arn:aws:sns:eu-west-1:1:alerts")}},
		topicPolicy: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sns:Subscribe","Resource":"*"}]}`,
	}, "eu-west-1", "1", now)
	require.NoError(t, err)
	require.Len(t, s, 1)
	require.Equal(t, asset.PublicAccessConfirmed, s[0].Metadata["public_access"])

	// An explicit Deny that names the same action neutralizes the Allow.
	s2, err := collectSNSTopics(context.Background(), &fakeSNS{
		topics: []snstypes.Topic{{TopicArn: awssdk.String("arn:aws:sns:eu-west-1:1:locked")}},
		topicPolicy: `{"Statement":[
			{"Effect":"Allow","Principal":"*","Action":"sns:Subscribe","Resource":"*"},
			{"Effect":"Deny","Principal":"*","Action":"sns:Subscribe","Resource":"*"}
		]}`,
	}, "eu-west-1", "1", now)
	require.NoError(t, err)
	require.Len(t, s2, 1)
	require.Equal(t, asset.PublicAccessNone, s2[0].Metadata["public_access"],
		"the policy WAS read and the Deny neutralizes the grant — observed, not absent")

	// A topic with genuinely NO policy: GetTopicAttributes succeeds and the
	// "Policy" attribute is simply absent — the common case, and it must not
	// collapse into the same missing key as an unreadable topic.
	s3, err := collectSNSTopics(context.Background(), &fakeSNS{
		topics: []snstypes.Topic{{TopicArn: awssdk.String("arn:aws:sns:eu-west-1:1:no-policy")}},
	}, "eu-west-1", "1", now)
	require.NoError(t, err)
	require.Len(t, s3, 1)
	require.Equal(t, asset.PublicAccessNone, s3[0].Metadata["public_access"])
}

// TestECRScanOnPush records whether ECR examines images for CVEs at all.
//
// DescribeRepositories has always returned ImageScanningConfiguration and the
// collector discarded it, so nothing could distinguish "this repository's images have
// no known CVEs" from "this repository's images have never been looked at". That
// distinction is the precondition for treating ECR as a vulnerability source: reading
// scan results from an unscanned repository reports clean over images nobody examined.
func TestECRScanOnPush(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name string
		cfg  *ecrtypes.ImageScanningConfiguration
		want string
	}{
		{"scanning on", &ecrtypes.ImageScanningConfiguration{ScanOnPush: true}, "true"},
		{"scanning off", &ecrtypes.ImageScanningConfiguration{ScanOnPush: false}, "false"},
		// A nil configuration is AWS's shape for "not configured", which behaves as
		// off. It must record false rather than being absent, or the check cannot
		// fire and an unscanned repository stays invisible.
		{"configuration absent behaves as off", nil, "false"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, err := collectECRRepos(context.Background(), &fakeECR{
				repos: []ecrtypes.Repository{{
					RepositoryName:             awssdk.String("app"),
					RepositoryArn:              awssdk.String("arn:aws:ecr:eu-west-1:1:repository/app"),
					RepositoryUri:              awssdk.String("uri"),
					ImageScanningConfiguration: tc.cfg,
				}},
				policyErr: errNoPolicy,
			}, "eu-west-1", "1", now)
			require.NoError(t, err)
			require.Len(t, e, 1)
			require.Equal(t, tc.want, e[0].Metadata["scan_on_push"])
		})
	}
}
