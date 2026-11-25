package aws

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// This file holds the simple list-and-emit regional collectors: KMS keys, ECR
// repositories, SQS queues, SNS topics. Each builds its own client from the
// region-scoped cfg and is called once per region from collectAll.
//
// Each also reads its resource-based policy (best-effort: a missing policy —
// the common case — is not an error) and grades public exposure deny-aware
// via publicResourceAccess (resourcepolicy.go), the same shape lambda.go
// uses for function policies. A policy that exists is stored in the same
// {name,type,document} shape the IAM collector uses for identity/trust/
// boundary policies (encodePolicies, iam.go), typed ciem.PolicyResource, so
// a later pass can intersect a role's identity grant against the resource's
// grant — the union AWS itself evaluates access by.

// kmsSensitiveActions are the KMS actions that actually expose the
// underlying data (or key material for signing) to whoever holds them. A
// public grant of e.g. kms:DescribeKey or kms:GetKeyPolicy is metadata
// disclosure, not decrypt access, and must not be graded the same.
var kmsSensitiveActions = []string{"kms:decrypt"}

// sqsSensitiveActions are the SQS actions that expose queue message content.
var sqsSensitiveActions = []string{"sqs:receivemessage", "sqs:sendmessage"}

// snsSensitiveActions are the SNS actions that expose topic message content.
var snsSensitiveActions = []string{"sns:subscribe", "sns:publish"}

// ecrSensitiveActions are the ECR actions that expose image content itself
// (as opposed to e.g. ecr:DescribeImages, which only discloses metadata).
var ecrSensitiveActions = []string{"ecr:batchgetimage", "ecr:getdownloadurlforlayer"}

// ── KMS ──────────────────────────────────────────────────────────────────────

type kmsAPI interface {
	ListKeys(context.Context, *kms.ListKeysInput, ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetKeyRotationStatus(context.Context, *kms.GetKeyRotationStatusInput, ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
	// GetKeyPolicy returns the key's resource-based policy (the "default" named
	// policy — KMS keys support exactly one). A key with no policy attached is
	// not a valid state in AWS (every key has at least a default policy), but
	// an AccessDenied on this call is common under a restrictive collector role
	// and must not fail the rest of the key's collection.
	GetKeyPolicy(context.Context, *kms.GetKeyPolicyInput, ...func(*kms.Options)) (*kms.GetKeyPolicyOutput, error)
}

func collectKMS(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectKMS: %w", err)
	}
	return collectKMSKeys(ctx, kms.NewFromConfig(awsCfg), region, accountID, now)
}

func collectKMSKeys(ctx context.Context, client kmsAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		marker *string
	)
	for {
		out, err := client.ListKeys(ctx, &kms.ListKeysInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("collectKMSKeys: %w", err)
		}
		for _, k := range out.Keys {
			keyID := awssdk.ToString(k.KeyId)

			desc, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: k.KeyId})
			if err != nil {
				// Skip this key rather than dropping every key already collected
				// in this region (matches the other regional collectors).
				continue
			}
			meta := desc.KeyMetadata
			// Skip AWS-managed and AWS-owned keys — rotation is not configurable for them.
			if meta.KeyManager != kmstypes.KeyManagerTypeCustomer {
				continue
			}

			am := map[string]string{
				"key_id":      keyID,
				"key_manager": string(meta.KeyManager),
				// Enabled | Disabled | PendingDeletion | …: rotation only matters
				// on a usable key, and a pending deletion is its own finding.
				"key_state": string(meta.KeyState),
				// "" = the key is not in a custom key store.
				"custom_key_store_id": awssdk.ToString(meta.CustomKeyStoreId),
			}
			// Automatic rotation exists only for SYMMETRIC_DEFAULT keys whose
			// material KMS generated (origin AWS_KMS). An empty value is unread,
			// so it is left absent rather than recorded as some other kind.
			if meta.KeySpec != "" {
				am["key_spec"] = string(meta.KeySpec)
			}
			if meta.Origin != "" {
				am["key_origin"] = string(meta.Origin)
			}
			// Rotation of a multi-Region key is set on its primary only.
			// "" = a single-Region key; absent = unread.
			if mrk, ok := kmsMultiRegionKeyType(meta); ok {
				am["multi_region_key_type"] = mrk
			}
			// The key was listed and described, so it is emitted either way; a
			// failed rotation read only leaves rotation_enabled absent (unknown).
			if rot, err := client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: k.KeyId}); err == nil && rot != nil {
				am["rotation_enabled"] = fmt.Sprintf("%t", rot.KeyRotationEnabled)
			}
			// Best-effort: a key policy fetch failure (AccessDenied under a
			// restrictive collector role) leaves the key's other fields intact.
			if pol, err := client.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
				KeyId: k.KeyId, PolicyName: awssdk.String("default"),
			}); err == nil {
				doc := awssdk.ToString(pol.Policy)
				pub, policies := resourcePolicyMetadata(doc, keyID+"-resource", kmsSensitiveActions)
				am["public_access"] = pub
				if policies != "" {
					am["policies"] = policies
				}
			}

			assets = append(assets, asset.Asset{
				ID:           awssdk.ToString(k.KeyArn),
				Name:         keyID,
				Type:         "kms_key",
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Metadata:     am,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if !out.Truncated {
			return assets, nil
		}
		marker = out.NextMarker
	}
}

// kmsMultiRegionKeyType returns PRIMARY or REPLICA for a multi-Region key and
// "" for a single-Region one. ok is false when DescribeKey did not say: no
// MultiRegion flag, or a multi-Region key without its configuration.
func kmsMultiRegionKeyType(meta *kmstypes.KeyMetadata) (string, bool) {
	if meta.MultiRegion == nil {
		return "", false
	}
	if !*meta.MultiRegion {
		return "", true
	}
	if meta.MultiRegionConfiguration == nil || meta.MultiRegionConfiguration.MultiRegionKeyType == "" {
		return "", false
	}
	return string(meta.MultiRegionConfiguration.MultiRegionKeyType), true
}

// ── ECR ──────────────────────────────────────────────────────────────────────

type ecrAPI interface {
	DescribeRepositories(context.Context, *ecr.DescribeRepositoriesInput, ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	// GetRepositoryPolicy returns the repository's resource-based policy.
	// RepositoryPolicyNotFoundException is the normal case for a repository
	// with no cross-account/public grant attached.
	GetRepositoryPolicy(context.Context, *ecr.GetRepositoryPolicyInput, ...func(*ecr.Options)) (*ecr.GetRepositoryPolicyOutput, error)
	// GetRegistryScanningConfiguration returns the region's registry-level
	// scanning rules (ecr_scanning.go) — one call per region.
	GetRegistryScanningConfiguration(context.Context, *ecr.GetRegistryScanningConfigurationInput, ...func(*ecr.Options)) (*ecr.GetRegistryScanningConfigurationOutput, error)
	// GetLifecyclePolicy answers a repository without one with a typed
	// LifecyclePolicyNotFoundException (FSBP ECR.3).
	GetLifecyclePolicy(context.Context, *ecr.GetLifecyclePolicyInput, ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error)
}

func collectECR(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectECR: %w", err)
	}
	return collectECRRepos(ctx, ecr.NewFromConfig(awsCfg), region, accountID, now)
}

func collectECRRepos(ctx context.Context, client ecrAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		next   *string
	)
	// A failed registry read leaves the registry_scan_* keys absent on every
	// repository, so aws-ecr-scanning-disabled stays silent (unknown) rather
	// than reporting repositories a registry rule may well be scanning.
	registry, regErr := readRegistryScanning(ctx, client)
	if regErr != nil {
		log.FromContext(ctx).Warn().Err(regErr).Str("region", region).
			Msg("ecr: registry scanning configuration unreadable (check ecr:GetRegistryScanningConfiguration); scan coverage unknown this sweep")
	}
	for {
		out, err := client.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("collectECRRepos: %w", err)
		}
		for _, r := range out.Repositories {
			name := awssdk.ToString(r.RepositoryName)
			am := map[string]string{
				"tag_mutability": string(r.ImageTagMutability),
				// scan_on_push records whether ECR scans images for CVEs at all —
				// the prerequisite for a scan-results integration to mean anything.
				"scan_on_push": strconv.FormatBool(
					r.ImageScanningConfiguration != nil && r.ImageScanningConfiguration.ScanOnPush),
			}
			if registry != nil {
				am["registry_scan_type"] = registry.scanType
				am["registry_scan_rule"] = registry.ruleFor(name)
			}
			// Unlike SQS/SNS/Secrets Manager, ECR answers a repository with no
			// resource policy with a TYPED error (RepositoryPolicyNotFoundException)
			// rather than a success carrying an empty policy. Distinguished from
			// any other error so AccessDenied still leaves both keys unwritten
			// (unread, not "not public"), while "no policy" becomes the
			// observation it is.
			var notFound *ecrtypes.RepositoryPolicyNotFoundException
			switch pol, err := client.GetRepositoryPolicy(ctx, &ecr.GetRepositoryPolicyInput{
				RepositoryName: r.RepositoryName,
			}); {
			case err == nil:
				doc := awssdk.ToString(pol.PolicyText)
				pub, policies := resourcePolicyMetadata(doc, name+"-resource", ecrSensitiveActions)
				am["public_access"] = pub
				if policies != "" {
					am["policies"] = policies
				}
			case errors.As(err, &notFound):
				am["public_access"] = asset.PublicAccessNone
			}
			if has, ok := repoHasLifecyclePolicy(ctx, client, r.RepositoryName); ok {
				am["lifecycle_policy"] = strconv.FormatBool(has)
			}
			assets = append(assets, asset.Asset{
				ID:           awssdk.ToString(r.RepositoryArn),
				Name:         name,
				Type:         "ecr_repository",
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Endpoint:     awssdk.ToString(r.RepositoryUri),
				Metadata:     am,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.NextToken == nil {
			return assets, nil
		}
		next = out.NextToken
	}
}

// repoHasLifecyclePolicy reads whether a repository has a lifecycle policy.
// ok is false when the read failed for any reason other than "no policy": an
// AccessDenied is unknown, not a repository that never expires images.
func repoHasLifecyclePolicy(ctx context.Context, client ecrAPI, repo *string) (has, ok bool) {
	out, err := client.GetLifecyclePolicy(ctx, &ecr.GetLifecyclePolicyInput{RepositoryName: repo})
	var notFound *ecrtypes.LifecyclePolicyNotFoundException
	switch {
	case err == nil:
		return awssdk.ToString(out.LifecyclePolicyText) != "", true
	case errors.As(err, &notFound):
		return false, true
	}
	log.FromContext(ctx).Warn().Err(err).Str("repository", awssdk.ToString(repo)).
		Msg("ecr: lifecycle policy unreadable (check ecr:GetLifecyclePolicy); lifecycle unknown this sweep")
	return false, false
}

// ── SQS ──────────────────────────────────────────────────────────────────────

type sqsAPI interface {
	ListQueues(context.Context, *sqs.ListQueuesInput, ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error)
	// GetQueueAttributes with AttributeNames=[Policy] returns the queue's
	// resource-based policy. A queue with no policy attached (the common
	// case) simply omits the "Policy" key from Attributes — no error.
	GetQueueAttributes(context.Context, *sqs.GetQueueAttributesInput, ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error)
}

func collectSQS(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectSQS: %w", err)
	}
	return collectSQSQueues(ctx, sqs.NewFromConfig(awsCfg), region, accountID, now)
}

func collectSQSQueues(ctx context.Context, client sqsAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		next   *string
	)
	for {
		out, err := client.ListQueues(ctx, &sqs.ListQueuesInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("collectSQSQueues: %w", err)
		}
		for _, url := range out.QueueUrls {
			am := map[string]string{}
			// Best-effort: most queues have no resource policy at all, in which
			// case Attributes simply lacks the "Policy" key (no error either way).
			// The encryption attributes ride on the same call.
			if attrs, err := client.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
				QueueUrl: awssdk.String(url),
				AttributeNames: []sqstypes.QueueAttributeName{
					sqstypes.QueueAttributeNamePolicy,
					sqstypes.QueueAttributeNameKmsMasterKeyId,
					sqstypes.QueueAttributeNameSqsManagedSseEnabled,
				},
			}); err == nil {
				if sse, ok := sqsEncryption(attrs.Attributes); ok {
					am["sse"] = sse
				}
				doc := attrs.Attributes["Policy"]
				name := url[strings.LastIndex(url, "/")+1:]
				pub, policies := resourcePolicyMetadata(doc, name+"-resource", sqsSensitiveActions)
				am["public_access"] = pub
				if policies != "" {
					am["policies"] = policies
				}
			}
			assets = append(assets, asset.Asset{
				ID:           url,
				Name:         url[strings.LastIndex(url, "/")+1:],
				Type:         "sqs_queue",
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Endpoint:     url,
				Metadata:     am,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.NextToken == nil {
			return assets, nil
		}
		next = out.NextToken
	}
}

// sqsEncryption reports how a queue is encrypted at rest: "kms" (SSE-KMS,
// a KmsMasterKeyId is set), "sqs" (SSE-SQS) or "none". The bool is false when
// the response carried neither attribute, which says nothing either way.
func sqsEncryption(attrs map[string]string) (string, bool) {
	if attrs["KmsMasterKeyId"] != "" {
		return "kms", true
	}
	v, ok := attrs["SqsManagedSseEnabled"]
	if !ok {
		return "", false
	}
	if strings.EqualFold(v, "true") {
		return "sqs", true
	}
	return "none", true
}

// ── SNS ──────────────────────────────────────────────────────────────────────

type snsAPI interface {
	ListTopics(context.Context, *sns.ListTopicsInput, ...func(*sns.Options)) (*sns.ListTopicsOutput, error)
	// GetTopicAttributes returns the topic's resource-based policy in its
	// Attributes["Policy"] entry (every SNS topic has SOME default-deny-less
	// policy AWS attaches implicitly, but a caller-authored public grant is
	// what this collector cares about).
	GetTopicAttributes(context.Context, *sns.GetTopicAttributesInput, ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error)
}

func collectSNS(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectSNS: %w", err)
	}
	return collectSNSTopics(ctx, sns.NewFromConfig(awsCfg), region, accountID, now)
}

func collectSNSTopics(ctx context.Context, client snsAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		next   *string
	)
	for {
		out, err := client.ListTopics(ctx, &sns.ListTopicsInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("collectSNSTopics: %w", err)
		}
		for _, tp := range out.Topics {
			arn := awssdk.ToString(tp.TopicArn)
			am := map[string]string{}
			if attrs, err := client.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{TopicArn: &arn}); err == nil {
				doc := attrs.Attributes["Policy"]
				name := arn[strings.LastIndex(arn, ":")+1:]
				pub, policies := resourcePolicyMetadata(doc, name+"-resource", snsSensitiveActions)
				am["public_access"] = pub
				if policies != "" {
					am["policies"] = policies
				}
			}
			assets = append(assets, asset.Asset{
				ID:           arn,
				Name:         arn[strings.LastIndex(arn, ":")+1:],
				Type:         "sns_topic",
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Metadata:     am,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.NextToken == nil {
			return assets, nil
		}
		next = out.NextToken
	}
}
