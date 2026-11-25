package aws

import (
	"context"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
)

// s3ControlAPI is the account-level S3 call the collector makes (mockable).
type s3ControlAPI interface {
	GetPublicAccessBlock(context.Context, *s3control.GetPublicAccessBlockInput, ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error)
}

// accountBPA is the account-wide S3 Block Public Access setting. AWS applies
// the most restrictive combination of the account and bucket settings, so an
// account that ignores public ACLs and restricts public policies makes every
// bucket non-public whatever the bucket's own configuration says.
//
// observed is false when the setting could not be read (AccessDenied,
// throttle): the bucket is then graded on its own settings alone, which can
// only over-report exposure, never hide it. A NoSuchPublicAccessBlock answer is
// an observation — the account has no block — and leaves cfg nil.
type accountBPA struct {
	observed bool
	cfg      *s3types.PublicAccessBlockConfiguration
}

// fetchAccountBPA reads the account-level Block Public Access configuration.
// An unknown account ID cannot be queried, so it is unobserved.
func fetchAccountBPA(ctx context.Context, client s3ControlAPI, accountID string) accountBPA {
	if accountID == "" {
		return accountBPA{}
	}
	out, err := client.GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{AccountId: awssdk.String(accountID)})
	if err != nil {
		return accountBPA{observed: isNoPublicAccessBlockErr(err)}
	}
	if out == nil || out.PublicAccessBlockConfiguration == nil {
		return accountBPA{observed: true}
	}
	c := out.PublicAccessBlockConfiguration
	return accountBPA{observed: true, cfg: &s3types.PublicAccessBlockConfiguration{
		BlockPublicAcls:       c.BlockPublicAcls,
		IgnorePublicAcls:      c.IgnorePublicAcls,
		BlockPublicPolicy:     c.BlockPublicPolicy,
		RestrictPublicBuckets: c.RestrictPublicBuckets,
	}}
}

// effectiveBlock merges a bucket's block configuration with the account's:
// each flag is on when either level turns it on. Either input may be nil.
func effectiveBlock(bucket, account *s3types.PublicAccessBlockConfiguration) s3types.PublicAccessBlockConfiguration {
	on := func(get func(*s3types.PublicAccessBlockConfiguration) *bool) *bool {
		v := (bucket != nil && awssdk.ToBool(get(bucket))) || (account != nil && awssdk.ToBool(get(account)))
		return awssdk.Bool(v)
	}
	return s3types.PublicAccessBlockConfiguration{
		BlockPublicAcls:       on(func(c *s3types.PublicAccessBlockConfiguration) *bool { return c.BlockPublicAcls }),
		IgnorePublicAcls:      on(func(c *s3types.PublicAccessBlockConfiguration) *bool { return c.IgnorePublicAcls }),
		BlockPublicPolicy:     on(func(c *s3types.PublicAccessBlockConfiguration) *bool { return c.BlockPublicPolicy }),
		RestrictPublicBuckets: on(func(c *s3types.PublicAccessBlockConfiguration) *bool { return c.RestrictPublicBuckets }),
	}
}
