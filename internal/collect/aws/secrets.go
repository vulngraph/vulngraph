package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// This file collects AWS Secrets Manager secrets and SSM Parameter Store
// SecureString parameters as graph assets. They become first-class nodes so:
//   - DSPM data classification can flag PII/credential-named secrets,
//   - the SecretAccess correlator can emit accesses_secret edges from IAM roles
//     whose policies grant secretsmanager:GetSecretValue / ssm:GetParameter on
//     the secret's ARN, and
//   - "what can read this secret" becomes a real Cypher query.
//
// GCP already has parity via collect/gcp/secrets.go; this closes the AWS gap.

// ── Secrets Manager ────────────────────────────────────────────────────────────

type secretsManagerAPI interface {
	ListSecrets(context.Context, *secretsmanager.ListSecretsInput, ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
	// GetResourcePolicy returns the secret's resource-based policy. A secret with
	// no resource policy (the large majority) answers with a SUCCESSFUL response
	// carrying a nil ResourcePolicy, not an error — see collectSecretsManagerSecrets.
	GetResourcePolicy(context.Context, *secretsmanager.GetResourcePolicyInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error)
}

// secretsManagerSensitiveActions is the action that actually discloses the
// secret's plaintext value. A public grant of e.g.
// secretsmanager:DescribeSecret is metadata disclosure, not credential
// exposure, and must not be graded the same.
var secretsManagerSensitiveActions = []string{"secretsmanager:getsecretvalue"}

func collectSecretsManager(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectSecretsManager: %w", err)
	}
	return collectSecretsManagerSecrets(ctx, secretsmanager.NewFromConfig(awsCfg), region, accountID, now)
}

func collectSecretsManagerSecrets(ctx context.Context, client secretsManagerAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		token  *string
	)
	for {
		out, err := client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("collectSecretsManagerSecrets: %w", err)
		}
		for _, s := range out.SecretList {
			arn := awssdk.ToString(s.ARN)
			if arn == "" {
				continue
			}
			rotation := "false"
			if s.RotationEnabled != nil && *s.RotationEnabled {
				rotation = "true"
			}
			lastRotated := ""
			if s.LastRotatedDate != nil {
				lastRotated = s.LastRotatedDate.Format(time.RFC3339)
			}
			meta := map[string]string{
				"rotation_enabled": rotation,
				"last_rotated":     lastRotated,
				"description":      awssdk.ToString(s.Description),
			}
			// Dates, not day counts: the rotation-age and unused checks read
			// the clock, so the asset does not change every day. ListSecrets
			// returns LastAccessedDate nil for a never-read secret, so "" is an
			// observation.
			if s.CreatedDate != nil {
				meta["created_at"] = s.CreatedDate.UTC().Format(time.RFC3339)
			}
			meta["last_accessed"] = ""
			if s.LastAccessedDate != nil {
				meta["last_accessed"] = s.LastAccessedDate.UTC().Format(time.RFC3339)
			}
			if days, ok := rotationIntervalDays(s.RotationRules); ok && rotation == "true" {
				meta["rotation_interval_days"] = strconv.Itoa(days)
			}
			// The date the schedule (rate or cron) next calls for a rotation;
			// a date in the past means the scheduled rotation did not happen.
			// Secrets Manager omits it only when no rotation is scheduled, so
			// for a rotating secret an omitted date is the observed "none".
			if rotation == "true" {
				meta["next_rotation"] = ""
				if s.NextRotationDate != nil {
					meta["next_rotation"] = s.NextRotationDate.UTC().Format(time.RFC3339)
				}
			}
			// GetResourcePolicy answers a secret with no resource policy (the
			// common case) with a SUCCESSFUL response whose ResourcePolicy is nil
			// — not a typed exception, confirmed against the SDK: secretsmanager
			// defines no NotFound-shaped error for this operation. So doc=="" here
			// is a real "asked, nothing to grant" observation and
			// resourcePolicyMetadata grades it PublicAccessNone rather than
			// leaving it absent. A genuine API failure (throttle, AccessDenied)
			// still skips this block entirely and leaves both keys unwritten.
			if pol, err := client.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{SecretId: &arn}); err == nil {
				doc := awssdk.ToString(pol.ResourcePolicy)
				pub, policies := resourcePolicyMetadata(doc, awssdk.ToString(s.Name)+"-resource", secretsManagerSensitiveActions)
				meta["public_access"] = pub
				if policies != "" {
					meta["policies"] = policies
				}
			}
			assets = append(assets, asset.Asset{
				ID:           arn,
				Name:         awssdk.ToString(s.Name),
				Type:         "secretsmanager_secret",
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Tags:         secretTags(s.Tags),
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.NextToken == nil {
			return assets, nil
		}
		token = out.NextToken
	}
}

// rotationIntervalDays is how often a rotating secret is due to rotate:
// AutomaticallyAfterDays, or a "rate(N days)" schedule. A cron schedule has no
// single interval and is unknown.
func rotationIntervalDays(r *smtypes.RotationRulesType) (int, bool) {
	if r == nil {
		return 0, false
	}
	if d := awssdk.ToInt64(r.AutomaticallyAfterDays); d > 0 {
		return int(d), true
	}
	expr := strings.TrimSpace(awssdk.ToString(r.ScheduleExpression))
	inner, ok := strings.CutPrefix(expr, "rate(")
	if !ok {
		return 0, false
	}
	inner, ok = strings.CutSuffix(inner, ")")
	if !ok {
		return 0, false
	}
	n, unit, ok := strings.Cut(strings.TrimSpace(inner), " ")
	if !ok || (unit != "days" && unit != "day") {
		return 0, false
	}
	d, err := strconv.Atoi(n)
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
}

// secretTags converts Secrets Manager tags to the asset tag map.
func secretTags(tags []smtypes.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]string, len(tags))
	for _, t := range tags {
		if k := awssdk.ToString(t.Key); k != "" {
			out[k] = awssdk.ToString(t.Value)
		}
	}
	return out
}

// ── SSM Parameter Store ────────────────────────────────────────────────────────

type ssmAPI interface {
	DescribeParameters(context.Context, *ssm.DescribeParametersInput, ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error)
}

func collectSSMParameters(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectSSMParameters: %w", err)
	}
	return collectSSMParams(ctx, ssm.NewFromConfig(awsCfg), region, accountID, now)
}

func collectSSMParams(ctx context.Context, client ssmAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		token  *string
	)
	for {
		out, err := client.DescribeParameters(ctx, &ssm.DescribeParametersInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("collectSSMParams: %w", err)
		}
		for _, p := range out.Parameters {
			name := awssdk.ToString(p.Name)
			if name == "" {
				continue
			}
			// Only SecureString params hold secrets worth tracking; String/StringList
			// are config values and would flood the graph.
			if p.Type != ssmtypes.ParameterTypeSecureString {
				continue
			}
			// Synthesize the ARN — DescribeParameters does not return it.
			id := fmt.Sprintf("arn:%s:ssm:%s:%s:parameter%s", partitionFor(region), region, accountID, normalizeParamName(name))
			assets = append(assets, asset.Asset{
				ID:        id,
				Name:      name,
				Type:      "ssm_parameter",
				Provider:  asset.ProviderAWS,
				Region:    region,
				AccountID: accountID,
				Metadata: map[string]string{
					"tier":        string(p.Tier),
					"description": awssdk.ToString(p.Description),
				},
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.NextToken == nil {
			return assets, nil
		}
		token = out.NextToken
	}
}

// normalizeParamName ensures the parameter name has a leading slash so the
// synthesized ARN matches the canonical arn:aws:ssm:...:parameter/foo form.
func normalizeParamName(name string) string {
	if len(name) > 0 && name[0] == '/' {
		return name
	}
	return "/" + name
}
