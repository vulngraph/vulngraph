package aws

import (
	"context"
	"errors"
	"fmt"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// AWS Glue posture: Spark job versions (FSBP Glue.4) and ML transform
// encryption at rest (Glue.3). Jobs and transforms are separate collectors so
// a role without glue:GetMLTransforms — which neither SecurityAudit nor
// ViewOnlyAccess grants — loses only the transforms; see gateGlueMLTransforms
// for how a denial is judged.

type glueAPI interface {
	GetJobs(context.Context, *glue.GetJobsInput, ...func(*glue.Options)) (*glue.GetJobsOutput, error)
	GetMLTransforms(context.Context, *glue.GetMLTransformsInput, ...func(*glue.Options)) (*glue.GetMLTransformsOutput, error)
}

func newGlueClient(ctx context.Context, cfg map[string]string) (glueAPI, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return glue.NewFromConfig(awsCfg), nil
}

func collectGlueJobs(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	client, err := newGlueClient(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectGlueJobs: %w", err)
	}
	return listGlueJobs(ctx, client, region, accountID, now)
}

// capabilityGlueMLTransforms is proven the first time glue:GetMLTransforms
// succeeds for a connector (collect.Result.MarkCapabilityProven).
const capabilityGlueMLTransforms = "glue_get_ml_transforms"

func collectGlueMLTransforms(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, bool, error) {
	client, err := newGlueClient(ctx, cfg)
	if err != nil {
		return nil, false, fmt.Errorf("collectGlueMLTransforms: %w", err)
	}
	return gateGlueMLTransforms(ctx, cfg, region)(listGlueMLTransforms(ctx, client, region, accountID, now))
}

// gateGlueMLTransforms judges a transform listing against the connector's
// proof of glue:GetMLTransforms, which is outside the managed read-only
// policies. Until the permission has worked once, a denial is the role not
// carrying the supplemental statement: this connector has never listed a
// transform, so there is nothing stored to mistake for deleted, and the
// sweep is not flagged partial on every run. Once proven, a denial is a
// regression and fails the listing like any other.
func gateGlueMLTransforms(ctx context.Context, cfg map[string]string, region string) func([]asset.Asset, error) ([]asset.Asset, bool, error) {
	return func(assets []asset.Asset, err error) ([]asset.Asset, bool, error) {
		if err != nil && isDenyErr(err) && !hasProvenCapability(cfg, capabilityGlueMLTransforms) {
			log.FromContext(ctx).Debug().Err(err).Str("region", region).
				Msg("glue:GetMLTransforms not granted (supplemental read-only statement); ML transform encryption not graded")
			return nil, false, errCapabilityUnproven
		}
		return assets, false, err
	}
}

// errCapabilityUnproven marks a denial before the permission was ever
// proven: the caller skips the task without flagging the sweep partial.
var errCapabilityUnproven = errors.New("glue:GetMLTransforms not yet proven for this connector")

func listGlueJobs(ctx context.Context, client glueAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		next   *string
	)
	for {
		out, err := client.GetJobs(ctx, &glue.GetJobsInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("listGlueJobs: %w", err)
		}
		for _, j := range out.Jobs {
			name := awssdk.ToString(j.Name)
			meta := map[string]string{
				// Unset means Glue's own default (0.9), which FSBP Glue.4 fails
				// explicitly; present-and-empty records that.
				"glue_version": awssdk.ToString(j.GlueVersion),
			}
			if j.Command != nil {
				meta["command"] = awssdk.ToString(j.Command.Name)
			}
			assets = append(assets, asset.Asset{
				ID:           fmt.Sprintf("arn:%s:glue:%s:%s:job/%s", partitionFor(region), region, accountID, name),
				Name:         name,
				Type:         "glue_job",
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return assets, nil
		}
		next = out.NextToken
	}
}

func listGlueMLTransforms(ctx context.Context, client glueAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		next   *string
	)
	for {
		out, err := client.GetMLTransforms(ctx, &glue.GetMLTransformsInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("listGlueMLTransforms: %w", err)
		}
		for _, t := range out.Transforms {
			id := awssdk.ToString(t.TransformId)
			assets = append(assets, asset.Asset{
				ID:        fmt.Sprintf("arn:%s:glue:%s:%s:mlTransform/%s", partitionFor(region), region, accountID, id),
				Name:      awssdk.ToString(t.Name),
				Type:      "glue_ml_transform",
				Provider:  asset.ProviderAWS,
				Region:    region,
				AccountID: accountID,
				Metadata: map[string]string{
					"user_data_encryption": glueMLUserDataEncryption(t.TransformEncryption),
				},
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return assets, nil
		}
		next = out.NextToken
	}
}

// glueMLUserDataEncryption is the transform's user-data encryption mode. A
// transform created without an encryption block stores its user data
// unencrypted, which the API reports by omitting the block: DISABLED.
func glueMLUserDataEncryption(e *gluetypes.TransformEncryption) string {
	if e == nil || e.MlUserDataEncryption == nil || e.MlUserDataEncryption.MlUserDataEncryptionMode == "" {
		return string(gluetypes.MLUserDataEncryptionModeStringDisabled)
	}
	return string(e.MlUserDataEncryption.MlUserDataEncryptionMode)
}
