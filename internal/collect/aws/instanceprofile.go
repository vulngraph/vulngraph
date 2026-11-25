package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// instanceProfileAPI is the IAM slice needed to resolve an EC2 instance profile
// to the IAM role inside it.
type instanceProfileAPI interface {
	ListInstanceProfiles(context.Context, *iam.ListInstanceProfilesInput, ...func(*iam.Options)) (*iam.ListInstanceProfilesOutput, error)
}

// maxInstanceProfilePages bounds the walk. IAM caps instance profiles at 1000
// per account by default, so 20 pages of 100 is already double the ceiling —
// it exists only so a pagination bug cannot loop forever.
const maxInstanceProfilePages = 20

// collectInstanceProfileRoles builds the account's instance-profile-ARN → role-ARN
// map with one paginated IAM call. It exists because the profile name does NOT
// imply the role name: EKS managed node groups create profiles called
// eks-<uuid> wrapping roles called <cluster>-eks-node-group-<timestamp>, so a
// ":instance-profile/" → ":role/" string substitution
// resolves only a minority of instances — and fails on exactly the EKS worker nodes
// that are the highest-value blast-radius pivot in an account.
//
// One list call per account per sweep, not one GetInstanceProfile per instance.
func collectInstanceProfileRoles(ctx context.Context, cfg map[string]string) (map[string]string, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectInstanceProfileRoles: %w", err)
	}
	awsCfg.Region = globalRegionFor(awsCfg.Region) // IAM is global.
	return instanceProfileRoles(ctx, iam.NewFromConfig(awsCfg))
}

// instanceProfileRoles returns profileARN → roleARN for every instance profile
// in the account. A profile with no role is omitted (it grants nothing). An
// error returns nil so the caller writes no role at all rather than a wrong one.
func instanceProfileRoles(ctx context.Context, c instanceProfileAPI) (map[string]string, error) {
	out := map[string]string{}
	var marker *string
	for page := 0; page < maxInstanceProfilePages; page++ {
		resp, err := c.ListInstanceProfiles(ctx, &iam.ListInstanceProfilesInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("instanceProfileRoles: %w", err)
		}
		if resp == nil {
			return out, nil
		}
		for _, p := range resp.InstanceProfiles {
			profileARN := awssdk.ToString(p.Arn)
			if profileARN == "" || len(p.Roles) == 0 {
				continue
			}
			// An instance profile can hold at most one role (AWS enforces this);
			// the list shape is historical.
			if roleARN := awssdk.ToString(p.Roles[0].Arn); roleARN != "" {
				out[profileARN] = roleARN
			}
		}
		if !resp.IsTruncated || resp.Marker == nil {
			return out, nil
		}
		marker = resp.Marker
	}
	return out, nil
}

// instanceRoleARN resolves an instance's profile ARN through the account's
// profile→role map. The bool is false when the answer is UNKNOWN — the map
// could not be built, or the profile is not in it — so the caller omits the
// metadata key instead of writing a guess that correlate would join on.
func instanceRoleARN(profileRoles map[string]string, profileARN string) (string, bool) {
	if profileRoles == nil || profileARN == "" {
		return "", false
	}
	roleARN, ok := profileRoles[profileARN]
	return roleARN, ok
}
