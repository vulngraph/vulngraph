package aws

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
)

// ecrAuthAPI is the slice of the ECR SDK the pull-credential path needs.
type ecrAuthAPI interface {
	GetAuthorizationToken(context.Context, *ecr.GetAuthorizationTokenInput, ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

// ECRAuthorizationToken mints a registry pull credential with the connector's
// credentials, for the imagevuln sweep to pull a private ECR image by digest.
// Needs ecr:GetAuthorizationToken (plus ecr:BatchGetImage and
// ecr:GetDownloadUrlForLayer for the pull itself) — none of which are in
// ViewOnlyAccess/SecurityAudit; see docs/iam/ecr-image-pull-permission.md.
func ECRAuthorizationToken(ctx context.Context, cfg map[string]string, region string) (user, pass string, expires time.Time, err error) {
	rcfg := withRegion(cfg, region)
	awsCfg, err := baseConfig(ctx, rcfg)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("ECRAuthorizationToken: %w", err)
	}
	return ecrToken(ctx, ecr.NewFromConfig(awsCfg))
}

// ecrToken calls GetAuthorizationToken and decodes the base64 "user:password"
// token it returns.
func ecrToken(ctx context.Context, client ecrAuthAPI) (user, pass string, expires time.Time, err error) {
	out, err := client.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("ecrToken: %w", err)
	}
	if len(out.AuthorizationData) == 0 {
		return "", "", time.Time{}, errors.New("ecrToken: no authorization data returned")
	}
	data := out.AuthorizationData[0]
	raw, err := base64.StdEncoding.DecodeString(awssdk.ToString(data.AuthorizationToken))
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("ecrToken: decode: %w", err)
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok || user == "" || pass == "" {
		return "", "", time.Time{}, errors.New("ecrToken: malformed authorization token")
	}
	if data.ExpiresAt == nil {
		return "", "", time.Time{}, errors.New("ecrToken: authorization token carries no expiry")
	}
	return user, pass, *data.ExpiresAt, nil
}
