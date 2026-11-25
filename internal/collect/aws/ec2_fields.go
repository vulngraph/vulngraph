package aws

import (
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// Small accessors over EC2 response fields shared by the EC2 collectors.

func tagMap(tags []ec2types.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		m[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return m
}

func nameTag(tags []ec2types.Tag, fallback string) string {
	for _, t := range tags {
		if awssdk.ToString(t.Key) == "Name" {
			return awssdk.ToString(t.Value)
		}
	}
	return fallback
}

// arnAccount extracts the account ID from an IAM role ARN.
// arn:aws:iam::<account>:role/<name>
func arnAccount(arn string) string {
	count := 0
	start := 0
	for i := 0; i < len(arn); i++ {
		if arn[i] == ':' {
			count++
			if count == 4 {
				start = i + 1
			}
			if count == 5 {
				return arn[start:i]
			}
		}
	}
	return ""
}

// launchTime returns inst.LaunchTime as a RFC3339 string, or "" when nil.
func launchTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// iamProfileARN extracts the ARN from an EC2 IamInstanceProfile reference, or
// returns "" when no profile is attached.
func iamProfileARN(p *ec2types.IamInstanceProfile) string {
	if p == nil {
		return ""
	}
	return awssdk.ToString(p.Arn)
}
