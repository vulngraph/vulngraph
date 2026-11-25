package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// connectorConfig is the narrow slice of connector.Service that live_aws needs.
// connector.Service.Get returns a Connector with a decrypted Config map — the
// ConnectorServiceAdapter below bridges the concrete type to this interface.
type connectorConfig interface {
	GetConfig(ctx context.Context, id string) (map[string]string, error)
}

// NewConnectorServiceAdapter wraps a *connector.Service (or any compatible
// implementation) as a connectorConfig.  The caller must pass a thin shim that
// returns connectorDomain, because we cannot import connector.Connector here
// without creating a circular dependency.  In practice, serve.go passes a closure.
func NewConnectorServiceAdapter(fn func(ctx context.Context, id string) (map[string]string, error)) connectorConfig {
	return &fnConnectorConfig{fn: fn}
}

// fnConnectorConfig implements connectorConfig via a plain function — avoids
// importing connector.Service in this file and keeps the adapter zero-alloc.
type fnConnectorConfig struct {
	fn func(ctx context.Context, id string) (map[string]string, error)
}

func (a *fnConnectorConfig) GetConfig(ctx context.Context, id string) (map[string]string, error) {
	return a.fn(ctx, id)
}

// LiveAWSCallerImpl implements LiveAWSCaller using real AWS SDK calls.
// It builds a fresh AWS config per call using the connector's stored credentials —
// the same baseConfig pattern used by internal/collect/aws/auth.go.
type LiveAWSCallerImpl struct {
	connectors connectorConfig
}

// NewLiveAWSCaller constructs a LiveAWSCallerImpl.
func NewLiveAWSCaller(connectors connectorConfig) *LiveAWSCallerImpl {
	return &LiveAWSCallerImpl{connectors: connectors}
}

// DescribeEC2Instance describes a single EC2 instance by instance ID.
func (c *LiveAWSCallerImpl) DescribeEC2Instance(ctx context.Context, connectorID, instanceID string) (map[string]any, error) {
	awsCfg, err := c.awsConfig(ctx, connectorID)
	if err != nil {
		return nil, fmt.Errorf("DescribeEC2Instance: %w", err)
	}
	client := ec2.NewFromConfig(awsCfg)
	out, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return nil, fmt.Errorf("DescribeEC2Instance: %w", err)
	}
	if len(out.Reservations) == 0 || len(out.Reservations[0].Instances) == 0 {
		return nil, fmt.Errorf("DescribeEC2Instance: instance %q not found", instanceID)
	}
	inst := out.Reservations[0].Instances[0]

	sgNames := make([]string, 0, len(inst.SecurityGroups))
	for _, sg := range inst.SecurityGroups {
		sgNames = append(sgNames, awssdk.ToString(sg.GroupId)+"/"+awssdk.ToString(sg.GroupName))
	}
	tags := make(map[string]string, len(inst.Tags))
	for _, t := range inst.Tags {
		tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}

	iamProfile := ""
	if inst.IamInstanceProfile != nil {
		iamProfile = awssdk.ToString(inst.IamInstanceProfile.Arn)
	}
	launchTime := ""
	if inst.LaunchTime != nil {
		launchTime = inst.LaunchTime.UTC().Format(time.RFC3339)
	}
	return map[string]any{
		"instance_id":          awssdk.ToString(inst.InstanceId),
		"state":                string(inst.State.Name),
		"instance_type":        string(inst.InstanceType),
		"public_ip":            awssdk.ToString(inst.PublicIpAddress),
		"private_ip":           awssdk.ToString(inst.PrivateIpAddress),
		"vpc_id":               awssdk.ToString(inst.VpcId),
		"subnet_id":            awssdk.ToString(inst.SubnetId),
		"image_id":             awssdk.ToString(inst.ImageId),
		"security_groups":      sgNames,
		"iam_instance_profile": iamProfile,
		"launch_time":          launchTime,
		"tags":                 tags,
	}, nil
}

// DescribeSecurityGroup returns the rules for one security group.
func (c *LiveAWSCallerImpl) DescribeSecurityGroup(ctx context.Context, connectorID, sgID string) (map[string]any, error) {
	awsCfg, err := c.awsConfig(ctx, connectorID)
	if err != nil {
		return nil, fmt.Errorf("DescribeSecurityGroup: %w", err)
	}
	client := ec2.NewFromConfig(awsCfg)
	out, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{sgID},
	})
	if err != nil {
		return nil, fmt.Errorf("DescribeSecurityGroup: %w", err)
	}
	if len(out.SecurityGroups) == 0 {
		return nil, fmt.Errorf("DescribeSecurityGroup: SG %q not found", sgID)
	}
	sg := out.SecurityGroups[0]

	serializeRules := func(perms []ec2types.IpPermission) []map[string]any {
		rules := make([]map[string]any, 0, len(perms))
		for _, p := range perms {
			ranges := make([]string, 0, len(p.IpRanges)+len(p.Ipv6Ranges))
			for _, r := range p.IpRanges {
				ranges = append(ranges, awssdk.ToString(r.CidrIp))
			}
			for _, r := range p.Ipv6Ranges {
				ranges = append(ranges, awssdk.ToString(r.CidrIpv6))
			}
			rules = append(rules, map[string]any{
				"protocol":  awssdk.ToString(p.IpProtocol),
				"from_port": p.FromPort,
				"to_port":   p.ToPort,
				"ranges":    ranges,
			})
		}
		return rules
	}

	return map[string]any{
		"group_id":      awssdk.ToString(sg.GroupId),
		"group_name":    awssdk.ToString(sg.GroupName),
		"description":   awssdk.ToString(sg.Description),
		"vpc_id":        awssdk.ToString(sg.VpcId),
		"ingress_rules": serializeRules(sg.IpPermissions),
		"egress_rules":  serializeRules(sg.IpPermissionsEgress),
	}, nil
}

// ListRolePolicies returns both inline and attached policies for an IAM role.
func (c *LiveAWSCallerImpl) ListRolePolicies(ctx context.Context, connectorID, roleName string) (map[string]any, error) {
	awsCfg, err := c.awsConfig(ctx, connectorID)
	if err != nil {
		return nil, fmt.Errorf("ListRolePolicies: %w", err)
	}
	client := iam.NewFromConfig(awsCfg)

	inlineOut, err := client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: awssdk.String(roleName),
	})
	if err != nil {
		return nil, fmt.Errorf("ListRolePolicies: inline: %w", err)
	}

	attachedOut, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: awssdk.String(roleName),
	})
	if err != nil {
		return nil, fmt.Errorf("ListRolePolicies: attached: %w", err)
	}

	attached := make([]map[string]string, 0, len(attachedOut.AttachedPolicies))
	for _, p := range attachedOut.AttachedPolicies {
		attached = append(attached, map[string]string{
			"name": awssdk.ToString(p.PolicyName),
			"arn":  awssdk.ToString(p.PolicyArn),
		})
	}
	return map[string]any{
		"role_name":         roleName,
		"inline_policies":   inlineOut.PolicyNames,
		"attached_policies": attached,
	}, nil
}

// GetRole fetches one IAM role by ARN using the connector's stored read-only
// credentials (GraphReadOnly in the role's account). The role name is
// the last path element of the ARN's resource. Mirrors DescribeSecurityGroup.
func (c *LiveAWSCallerImpl) GetRole(ctx context.Context, connectorID, roleARN string) (map[string]any, error) {
	awsCfg, err := c.awsConfig(ctx, connectorID)
	if err != nil {
		return nil, fmt.Errorf("GetRole: %w", err)
	}
	name := roleNameFromARN(roleARN)
	if name == "" {
		return nil, fmt.Errorf("GetRole: cannot parse role name from %q", roleARN)
	}
	client := iam.NewFromConfig(awsCfg)
	out, err := client.GetRole(ctx, &iam.GetRoleInput{RoleName: awssdk.String(name)})
	if err != nil {
		return nil, fmt.Errorf("GetRole: %w", err)
	}
	role := out.Role
	return map[string]any{
		"arn":                  awssdk.ToString(role.Arn),
		"role_name":            awssdk.ToString(role.RoleName),
		"path":                 awssdk.ToString(role.Path),
		"max_session_duration": awssdk.ToInt32(role.MaxSessionDuration),
	}, nil
}

// roleNameFromARN returns "deploy" from "arn:aws:iam::123:role/path/deploy".
func roleNameFromARN(arn string) string {
	i := strings.Index(arn, ":role/")
	if i < 0 {
		return ""
	}
	res := arn[i+len(":role/"):]
	if j := strings.LastIndex(res, "/"); j >= 0 {
		return res[j+1:]
	}
	return res
}

// DescribeBucket returns location and policy for an S3 bucket.
func (c *LiveAWSCallerImpl) DescribeBucket(ctx context.Context, connectorID, bucketName string) (map[string]any, error) {
	awsCfg, err := c.awsConfig(ctx, connectorID)
	if err != nil {
		return nil, fmt.Errorf("DescribeBucket: %w", err)
	}
	client := s3.NewFromConfig(awsCfg)

	locOut, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: awssdk.String(bucketName),
	})
	if err != nil {
		return nil, fmt.Errorf("DescribeBucket: location: %w", err)
	}

	region := string(locOut.LocationConstraint)
	if region == "" {
		region = "us-east-1" // SDK returns "" for us-east-1
	}

	result := map[string]any{
		"bucket_name": bucketName,
		"region":      region,
	}

	policyOut, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: awssdk.String(bucketName),
	})
	if err == nil && policyOut.Policy != nil {
		result["policy"] = awssdk.ToString(policyOut.Policy)
	} else {
		result["policy"] = nil
	}

	return result, nil
}

// s3GetObjectMaxBytes bounds GetObject reads (e.g. Terraform state blobs) so a
// single call can't exhaust worker memory on an unexpectedly large object.
const s3GetObjectMaxBytes = 32 << 20 // 32 MiB

// GetObject fetches an object's bytes from a connector-scoped S3 bucket,
// bounded by s3GetObjectMaxBytes. It never returns a silently truncated blob:
// an object over the cap is a hard error, not a partial read.
//
// UsePathStyle is gated on AWS_ENDPOINT_URL_S3 rather than hardcoded: AWS
// deprecated path-style addressing for buckets created after 2020-09-30, so
// forcing it on would break virtual-hosted-only buckets — exactly the
// Terraform state buckets this call targets. The env var is unset against
// real AWS (default virtual-hosted addressing) and set by tests/S3-compatible
// endpoints that only support path-style.
func (c *LiveAWSCallerImpl) GetObject(ctx context.Context, connectorID, bucket, key string) ([]byte, error) {
	awsCfg, err := c.awsConfig(ctx, connectorID)
	if err != nil {
		return nil, fmt.Errorf("GetObject: %w", err)
	}
	usePathStyle := os.Getenv("AWS_ENDPOINT_URL_S3") != ""

	region := c.resolveBucketRegion(ctx, awsCfg, usePathStyle, bucket, awsCfg.Region)

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.Region = region
		o.UsePathStyle = usePathStyle
	})

	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: awssdk.String(bucket),
		Key:    awssdk.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("GetObject: %w", err)
	}
	defer func() { _ = out.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(out.Body, s3GetObjectMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("GetObject: read %s/%s: %w", bucket, key, err)
	}
	if len(data) > s3GetObjectMaxBytes {
		return nil, fmt.Errorf("GetObject: %s/%s exceeds max size %d bytes", bucket, key, s3GetObjectMaxBytes)
	}
	return data, nil
}

// resolveBucketRegion looks up the bucket's actual region via GetBucketLocation
// so GetObject can target the right regional endpoint — cross-region Terraform
// state buckets otherwise fail with a 301 PermanentRedirect (the client built
// from the connector's config region doesn't match the bucket's region). Falls
// back to fallbackRegion (the connector's config region) on any lookup error:
// this is a best-effort optimization, never a hard dependency for the read.
func (c *LiveAWSCallerImpl) resolveBucketRegion(ctx context.Context, awsCfg awssdk.Config, usePathStyle bool, bucket, fallbackRegion string) string {
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = usePathStyle
	})
	out, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: awssdk.String(bucket),
	})
	if err != nil {
		log.FromContext(ctx).Debug().Err(err).Str("bucket", bucket).
			Msg("GetObject: GetBucketLocation failed, falling back to connector region")
		return fallbackRegion
	}
	region := string(out.LocationConstraint)
	switch region {
	case "":
		// AWS returns "" (not "us-east-1") for buckets in the US Standard region.
		return "us-east-1"
	case "EU":
		// Legacy constraint value for the original EU region.
		return "eu-west-1"
	default:
		return region
	}
}

// LookupCloudTrailEvents returns recent CloudTrail events for a resource or principal.
func (c *LiveAWSCallerImpl) LookupCloudTrailEvents(ctx context.Context, connectorID, resourceID string, hours, limit int) ([]map[string]any, error) {
	awsCfg, err := c.awsConfig(ctx, connectorID)
	if err != nil {
		return nil, fmt.Errorf("LookupCloudTrailEvents: %w", err)
	}
	client := cloudtrail.NewFromConfig(awsCfg)

	startTime := time.Now().Add(-time.Duration(hours) * time.Hour)
	maxResults := int32(limit)

	// LookupEvents accepts exactly ONE attribute per call, and which one matches
	// depends on the identifier: ResourceName hits resources named in the event,
	// Username hits the calling principal. A role name is a Username, an instance
	// ID or ARN is a ResourceName, and callers pass either — so try ResourceName
	// and fall back to Username rather than silently returning zero events.
	// Both attributes are queried and merged, NOT first-non-empty: for a role
	// name the ResourceName lookup returns the events naming the role as a
	// resource (CreateRole, AttachRolePolicy…), so stopping there would skip the
	// Username lookup that returns what the principal actually DID — the whole
	// question for a credential-exfiltration alert.
	attempts := []cloudtrailtypes.LookupAttributeKey{
		cloudtrailtypes.LookupAttributeKeyResourceName,
		cloudtrailtypes.LookupAttributeKeyUsername,
	}
	var raw []cloudtrailtypes.Event
	seenEvent := map[string]bool{}
	for _, key := range attempts {
		res, err := client.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
			LookupAttributes: []cloudtrailtypes.LookupAttribute{
				{AttributeKey: key, AttributeValue: awssdk.String(resourceID)},
			},
			StartTime:  awssdk.Time(startTime),
			MaxResults: awssdk.Int32(maxResults),
		})
		if err != nil {
			return nil, fmt.Errorf("LookupCloudTrailEvents: %w", err)
		}
		for _, ev := range res.Events {
			id := awssdk.ToString(ev.EventId)
			if seenEvent[id] {
				continue
			}
			seenEvent[id] = true
			raw = append(raw, ev)
			if len(raw) >= limit {
				break
			}
		}
		if len(raw) >= limit {
			break
		}
	}

	events := make([]map[string]any, 0, len(raw))
	for _, ev := range raw {
		resources := make([]map[string]string, 0, len(ev.Resources))
		for _, r := range ev.Resources {
			resources = append(resources, map[string]string{
				"name": awssdk.ToString(r.ResourceName),
				"type": awssdk.ToString(r.ResourceType),
			})
		}
		evTime := ""
		if ev.EventTime != nil {
			evTime = ev.EventTime.UTC().Format(time.RFC3339)
		}
		rec := map[string]any{
			"event_id":     awssdk.ToString(ev.EventId),
			"event_name":   awssdk.ToString(ev.EventName),
			"event_time":   evTime,
			"username":     awssdk.ToString(ev.Username),
			"event_source": awssdk.ToString(ev.EventSource),
			"resources":    resources,
		}
		// The caller IP and principal live only in the raw event JSON, and they
		// are the whole point for a credential-exfiltration alert: without
		// source_ip you cannot tell which of these calls came from the attacker.
		if detail := parseCloudTrailDetail(awssdk.ToString(ev.CloudTrailEvent)); detail != nil {
			maps.Copy(rec, detail)
		}
		events = append(events, rec)
	}
	return events, nil
}

// parseCloudTrailDetail pulls the caller IP, principal and error fields out of a
// raw CloudTrail event record. LookupEvents' typed fields omit all of them.
// Returns nil when the record is unparseable — a malformed record must not fail
// the whole lookup.
func parseCloudTrailDetail(raw string) map[string]any {
	if raw == "" {
		return nil
	}
	var rec struct {
		SourceIPAddress string `json:"sourceIPAddress"`
		UserAgent       string `json:"userAgent"`
		ErrorCode       string `json:"errorCode"`
		AWSRegion       string `json:"awsRegion"`
		UserIdentity    struct {
			Type           string `json:"type"`
			ARN            string `json:"arn"`
			PrincipalID    string `json:"principalId"`
			AccessKeyID    string `json:"accessKeyId"`
			InvokedBy      string `json:"invokedBy"`
			SessionContext struct {
				SessionIssuer struct {
					UserName string `json:"userName"`
					ARN      string `json:"arn"`
				} `json:"sessionIssuer"`
			} `json:"sessionContext"`
		} `json:"userIdentity"`
	}
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		return nil
	}
	// Every key is omitted when empty. An AWS-service-invoked event has no access
	// key and no principal ARN, and emitting those as "" reads like real data —
	// the difference between "called by nobody" and "not recorded" matters when
	// the question is which calls came from an attacker.
	detail := map[string]any{}
	for k, v := range map[string]string{
		"source_ip":        rec.SourceIPAddress,
		"user_agent":       rec.UserAgent,
		"aws_region":       rec.AWSRegion,
		"principal_type":   rec.UserIdentity.Type,
		"principal_arn":    rec.UserIdentity.ARN,
		"principal_id":     rec.UserIdentity.PrincipalID,
		"access_key_id":    rec.UserIdentity.AccessKeyID,
		"assumed_role_arn": rec.UserIdentity.SessionContext.SessionIssuer.ARN,
		"error_code":       rec.ErrorCode,
		"invoked_by":       rec.UserIdentity.InvokedBy,
	} {
		if v != "" {
			detail[k] = v
		}
	}
	if len(detail) == 0 {
		// A bare `null` record unmarshals without error into the zero value.
		return nil
	}
	return detail
}

// liveRole picks the role to assume for the live read path. A dedicated
// read-only role (readonly_role_arn) is preferred when the connector declares
// one: this path serves only chat/verify read tools (the collector authenticates
// separately in internal/collect/aws/auth.go), so assuming a
// ViewOnlyAccess/SecurityAudit-scoped role here makes the IAM ceiling itself
// read-only — defense in depth behind the read-only tool surface, so even a bug
// can't mutate. Falls back to the collector role_arn (or static keys, handled by
// the caller) when unset. external_id is shared unless a role-specific
// readonly_external_id is given.
func liveRole(cfg map[string]string) (roleARN, externalID string) {
	roleARN, externalID = cfg["role_arn"], cfg["external_id"]
	if ro := cfg["readonly_role_arn"]; ro != "" {
		roleARN = ro
		if roExt := cfg["readonly_external_id"]; roExt != "" {
			externalID = roExt
		}
	}
	return roleARN, externalID
}

// awsConfig builds an AWS SDK config from the connector's stored credentials.
// Mirrors the pattern in internal/collect/aws/auth.go.
func (c *LiveAWSCallerImpl) awsConfig(ctx context.Context, connectorID string) (awssdk.Config, error) {
	cfg, err := c.connectors.GetConfig(ctx, connectorID)
	if err != nil {
		return awssdk.Config{}, fmt.Errorf("awsConfig: get connector %q: %w", connectorID, err)
	}

	region := cfg["region"]
	if region == "" {
		return awssdk.Config{}, fmt.Errorf("awsConfig: connector %q has no region", connectorID)
	}

	opts := []func(*config.LoadOptions) error{config.WithRegion(region)}

	if keyID := cfg["aws_access_key_id"]; keyID != "" {
		secret := cfg["aws_secret_access_key"]
		if secret == "" {
			return awssdk.Config{}, fmt.Errorf("awsConfig: connector %q: aws_secret_access_key required with aws_access_key_id", connectorID)
		}
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(keyID, secret, cfg["aws_session_token"]),
		))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return awssdk.Config{}, fmt.Errorf("awsConfig: load: %w", err)
	}

	// An org child whose hub role trusts a principal assumes the hub role
	// first: the member roles trust only the hub.
	if hub := cfg["hub_role_arn"]; hub != "" {
		awsCfg.Credentials = awssdk.NewCredentialsCache(stscreds.NewAssumeRoleProvider(
			sts.NewFromConfig(awsCfg), hub, func(o *stscreds.AssumeRoleOptions) {
				o.RoleSessionName = "graph-hub"
			}))
	}

	roleARN, externalID := liveRole(cfg)

	if cfg["aws_access_key_id"] == "" && roleARN == "" {
		return awssdk.Config{}, fmt.Errorf("awsConfig: connector %q: role_arn, readonly_role_arn, or aws_access_key_id is required", connectorID)
	}

	if roleARN != "" {
		stsClient := sts.NewFromConfig(awsCfg)
		awsCfg.Credentials = awssdk.NewCredentialsCache(
			stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(o *stscreds.AssumeRoleOptions) {
				if externalID != "" {
					o.ExternalID = awssdk.String(externalID)
				}
			}),
		)
	}
	return awsCfg, nil
}
