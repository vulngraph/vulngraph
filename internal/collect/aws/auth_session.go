package aws

import (
	"context"
	"fmt"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// MinSessionDuration is the shortest session STS issues.
const MinSessionDuration = 15 * time.Minute

// SessionCredentials returns credentials for roleARN assumed from the
// connector's identity through the same chain as BaseConfig (static keys or the
// default chain, then the hub hop), lasting d (clamped up to STS's minimum), and
// carrying an inline session policy when policy is not empty: the session can
// then do no more than the policy and the role both allow. The connector's
// external_id is presented.
//
// An empty roleARN returns the connector's own identity unchanged: with static
// keys and no role there is nothing to shorten, so the keys themselves come back.
func SessionCredentials(ctx context.Context, cfg map[string]string, roleARN string, d time.Duration, policy string) (awssdk.Credentials, error) {
	base, err := identityConfig(ctx, cfg)
	if err != nil {
		return awssdk.Credentials{}, err
	}
	if roleARN == "" {
		creds, err := base.Credentials.Retrieve(ctx)
		if err != nil {
			return awssdk.Credentials{}, fmt.Errorf("SessionCredentials: %w", err)
		}
		return creds, nil
	}
	d = max(d, MinSessionDuration)
	provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(base), roleARN, func(o *stscreds.AssumeRoleOptions) {
		o.Duration = d
		o.RoleSessionName = "graph-disk-scan"
		if ext := cfg["external_id"]; ext != "" {
			o.ExternalID = awssdk.String(ext)
		}
		if policy != "" {
			o.Policy = awssdk.String(policy)
		}
	})
	creds, err := provider.Retrieve(ctx)
	if err != nil {
		return awssdk.Credentials{}, fmt.Errorf("SessionCredentials: assume %s: %w", roleARN, err)
	}
	return creds, nil
}
