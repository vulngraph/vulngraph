package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"

	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/diskscan"
	"github.com/vulngraph/vulngraph/internal/app/diskscan/envelope"
	collectaws "github.com/vulngraph/vulngraph/internal/collect/aws"
	"github.com/vulngraph/vulngraph/internal/jobs"
	engine "github.com/vulngraph/vulngraph/internal/scanner/diskscan"
	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/awsdisk"
	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/snapshotter"
)

// The session policies narrow what a minted session can do to the actions disk
// scanning uses. A session policy only ever intersects with the role's own
// permissions, so these cap the roles and never extend them.
const (
	// awsReadSessionPolicy: the snapshot reads of awsdisk, and kms:Decrypt for an
	// encrypted snapshot's blocks. The collection role's other read actions are
	// left out of the scanner's session.
	awsReadSessionPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":[` +
		`"ec2:DescribeSnapshots","ec2:DescribeRegions",` +
		`"ebs:ListSnapshotBlocks","ebs:GetSnapshotBlock","ebs:ListChangedBlocks",` +
		`"kms:Decrypt","kms:DescribeKey"],"Resource":"*"}]}`
	// awsWriteSessionPolicy: the snapshotter's three actions. The role's own
	// tag conditions still apply on top.
	awsWriteSessionPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":[` +
		`"ec2:CreateSnapshot","ec2:CreateTags","ec2:DeleteSnapshot"],"Resource":"*"}]}`

	// maxSessionLifetime is STS's ceiling for a chained role session.
	maxSessionLifetime = time.Hour
)

func credsOf(c awssdk.Credentials) *envelope.Credentials {
	return &envelope.Credentials{
		AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken,
		Expires: c.Expires,
	}
}

// sealAWSAccess replaces an AWS access's secrets with sessions minted for the
// run: one of the connector's collection role for reads and, only in
// create_snapshots mode with a distinct disk-scan role, one of that role for
// create and delete. Each lasts as long as the run's credentials may (STS's
// 15-minute floor to its one-hour chaining ceiling) and carries a session
// policy cutting it to the snapshot actions. The role identifiers stay in the
// access for the opt-in comparison; the config keeps only the region locators.
// A connector with static keys and no role has nothing to assume: its keys are
// carried as they are, the one long-lived AWS secret the scanner can hold.
func sealAWSAccess(ctx context.Context, c connector.Connector, a envelope.Access) (envelope.Access, error) {
	lifetime := min(max(time.Until(a.ExpiresAt), collectaws.MinSessionDuration), maxSessionLifetime)
	a.ExpiresAt = time.Now().Add(lifetime)

	read, err := collectaws.SessionCredentials(ctx, c.Config, c.Config["role_arn"], lifetime, awsReadSessionPolicy)
	if err != nil {
		return envelope.Access{}, fmt.Errorf("sealAWSAccess: read session: %w", err)
	}
	a.AWSRead = credsOf(read)
	if c.DiskScanMode == diskscan.DiskScanModeCreateSnapshots && a.Role != "" && !slices.Contains(a.OtherRoles, a.Role) {
		write, err := collectaws.SessionCredentials(ctx, c.Config, a.Role, lifetime, awsWriteSessionPolicy)
		if err != nil {
			return envelope.Access{}, fmt.Errorf("sealAWSAccess: disk-scan session: %w", err)
		}
		a.AWSWrite = credsOf(write)
	}
	a.Config = map[string]string{}
	for _, k := range []string{"region", "regions"} {
		if v := c.Config[k]; v != "" {
			a.Config[k] = v
		}
	}
	return a, nil
}

// newAWSCloudFor builds the AWS cloud for an access: from its sealed sessions
// when it carries them (the scanner), else from the connector's own credential
// chain (the worker's sweep).
func newAWSCloudFor(ctx context.Context, a envelope.Access, sweep bool) (*awsDiskCloud, error) {
	if a.AWSRead.Valid() {
		return newAWSSessionCloud(ctx, a)
	}
	return newAWSDiskCloud(ctx, a, sweep)
}

// awsDiskCloud holds the two credential sets disk scanning uses: the
// connector's collection role for every read, and, only for a connector that
// opted in, the separate disk-scan role for create and delete.
type awsDiskCloud struct {
	readCfg  awssdk.Config
	writeCfg func() (awssdk.Config, error)
	regions  []string
}

func csv(v string) []string {
	var out []string
	for r := range strings.SplitSeq(v, ",") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// sessionConfig is an AWS config that signs with exactly the sealed credentials.
func sessionConfig(ctx context.Context, region string, c *envelope.Credentials) (awssdk.Config, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, c.SessionToken)))
	if err != nil {
		return awssdk.Config{}, fmt.Errorf("sessionConfig: %w", err)
	}
	return cfg, nil
}

// newAWSSessionCloud builds the cloud the scanner pod uses. It assumes no role.
func newAWSSessionCloud(ctx context.Context, a envelope.Access) (*awsDiskCloud, error) {
	region := a.Config["region"]
	readCfg, err := sessionConfig(ctx, region, a.AWSRead)
	if err != nil {
		return nil, fmt.Errorf("newAWSSessionCloud: %w", err)
	}
	c := &awsDiskCloud{readCfg: readCfg}
	c.writeCfg = func() (awssdk.Config, error) {
		if !a.AWSWrite.Valid() {
			return awssdk.Config{}, fmt.Errorf("no disk-scan session was sealed for this run: %w", engine.ErrNotAuthorized)
		}
		return sessionConfig(ctx, region, a.AWSWrite)
	}
	return c, nil
}

func newAWSDiskCloud(ctx context.Context, a envelope.Access, sweep bool) (*awsDiskCloud, error) {
	readCfg, err := collectaws.BaseConfig(ctx, a.Config)
	if err != nil {
		return nil, fmt.Errorf("newAWSDiskCloud: %w", err)
	}
	c := &awsDiskCloud{readCfg: readCfg}
	// The write config assumes disk_scan_role_arn through the same STS path the
	// collectors use. It replaces role_arn and never falls back to it, to
	// execute_role_arn or to the read-only role.
	c.writeCfg = func() (awssdk.Config, error) {
		if a.Role == "" {
			return awssdk.Config{}, errors.New("no disk-scan role configured")
		}
		cfg := maps.Clone(a.Config)
		cfg["role_arn"] = a.Role
		return collectaws.BaseConfig(ctx, cfg)
	}
	if sweep {
		c.regions = csv(a.Config["regions"])
		if len(c.regions) == 0 {
			if c.regions, err = enabledRegions(ctx, readCfg); err != nil {
				return nil, fmt.Errorf("newAWSDiskCloud: %w", err)
			}
		}
	}
	return c, nil
}

func enabledRegions(ctx context.Context, cfg awssdk.Config) ([]string, error) {
	out, err := ec2.NewFromConfig(cfg).DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, fmt.Errorf("enabledRegions: %w", err)
	}
	regions := make([]string, 0, len(out.Regions))
	for _, r := range out.Regions {
		regions = append(regions, awssdk.ToString(r.RegionName))
	}
	return regions, nil
}

// isExpiredToken reports whether AWS refused a session that has run out.
func isExpiredToken(err error) bool {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode() {
	case "ExpiredToken", "ExpiredTokenException", "RequestExpired":
		return true
	}
	return false
}

func mapAWSErr(err error) error {
	switch {
	case err == nil:
		return nil
	case isExpiredToken(err):
		return fmt.Errorf("%w: %w", jobs.ErrDiskCredentialsExpired, err)
	case errors.Is(err, awsdisk.ErrPermissionDenied), errors.Is(err, snapshotter.ErrPermissionDenied):
		return fmt.Errorf("%w: %w", jobs.ErrDiskPermissionDenied, err)
	case errors.Is(err, awsdisk.ErrEncryptedNoKey):
		return fmt.Errorf("%w: %w", jobs.ErrDiskEncryptedNoKey, err)
	}
	return err
}

func (c *awsDiskCloud) Provider(jobs.DiskOptIns) engine.Provider {
	return mappedProvider{Provider: awsdisk.NewFromConfig(c.readCfg), mapErr: mapAWSErr}
}

func (c *awsDiskCloud) Snapshotter(optIn engine.OptIn) (engine.Snapshotter, error) {
	if !optIn.Valid() {
		return nil, fmt.Errorf("Snapshotter: %w", engine.ErrNotAuthorized)
	}
	writeCfg, err := c.writeCfg()
	if err != nil {
		return nil, fmt.Errorf("Snapshotter: %w", err)
	}
	sn, err := snapshotter.NewAWSFromConfig(optIn, c.regions, writeCfg, c.readCfg)
	if err != nil {
		return nil, fmt.Errorf("Snapshotter: %w", err)
	}
	return mappedSnapshotter{Snapshotter: sn, mapErr: mapAWSErr}, nil
}

const snapshotPollEvery = 15 * time.Second

// WaitCompleted polls the snapshot's state with the read-only role until it
// can be read from.
func (c *awsDiskCloud) WaitCompleted(ctx context.Context, snap engine.Snapshot) error {
	cfg := c.readCfg.Copy()
	cfg.Region = snap.Region
	client := ec2.NewFromConfig(cfg)
	for {
		out, err := client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{SnapshotIds: []string{snap.ID}})
		if err != nil {
			return fmt.Errorf("WaitCompleted: %w", mapAWSErr(err))
		}
		if len(out.Snapshots) > 0 {
			switch out.Snapshots[0].State {
			case ec2types.SnapshotStateCompleted:
				return nil
			case ec2types.SnapshotStateError:
				return fmt.Errorf("WaitCompleted: snapshot %s failed: %s", snap.ID, awssdk.ToString(out.Snapshots[0].StateMessage))
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("WaitCompleted: %w", ctx.Err())
		case <-time.After(snapshotPollEvery):
		}
	}
}

// Release is a no-op: EBS direct reads hold no access to give back.
func (c *awsDiskCloud) Release(context.Context, jobs.DiskOptIns, engine.Snapshot) error { return nil }
