package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeEFS struct {
	fss       []efstypes.FileSystemDescription
	fsPage2   error
	points    []efstypes.AccessPointDescription
	backup    map[string]efstypes.Status // absent ⇒ PolicyNotFound
	backupErr map[string]error
	policies  map[string]string // absent ⇒ PolicyNotFound
	policyErr map[string]error
}

func (f *fakeEFS) DescribeFileSystems(_ context.Context, in *efs.DescribeFileSystemsInput, _ ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
	i := fakePage(in.Marker)
	if i == 1 && f.fsPage2 != nil {
		return nil, f.fsPage2
	}
	if i >= len(f.fss) {
		return &efs.DescribeFileSystemsOutput{}, nil
	}
	return &efs.DescribeFileSystemsOutput{FileSystems: f.fss[i : i+1], NextMarker: fakeNextToken(i, len(f.fss))}, nil
}

func (f *fakeEFS) DescribeAccessPoints(context.Context, *efs.DescribeAccessPointsInput, ...func(*efs.Options)) (*efs.DescribeAccessPointsOutput, error) {
	return &efs.DescribeAccessPointsOutput{AccessPoints: f.points}, nil
}

func (f *fakeEFS) DescribeBackupPolicy(_ context.Context, in *efs.DescribeBackupPolicyInput, _ ...func(*efs.Options)) (*efs.DescribeBackupPolicyOutput, error) {
	id := awssdk.ToString(in.FileSystemId)
	if err := f.backupErr[id]; err != nil {
		return nil, err
	}
	s, ok := f.backup[id]
	if !ok {
		return nil, &efstypes.PolicyNotFound{}
	}
	return &efs.DescribeBackupPolicyOutput{BackupPolicy: &efstypes.BackupPolicy{Status: s}}, nil
}

func (f *fakeEFS) DescribeFileSystemPolicy(_ context.Context, in *efs.DescribeFileSystemPolicyInput, _ ...func(*efs.Options)) (*efs.DescribeFileSystemPolicyOutput, error) {
	id := awssdk.ToString(in.FileSystemId)
	if err := f.policyErr[id]; err != nil {
		return nil, err
	}
	doc, ok := f.policies[id]
	if !ok {
		return nil, &efstypes.PolicyNotFound{}
	}
	return &efs.DescribeFileSystemPolicyOutput{Policy: awssdk.String(doc)}, nil
}

var _ efsAPI = (*fakeEFS)(nil)

func efsFS(id string, encrypted *bool, tags ...efstypes.Tag) efstypes.FileSystemDescription {
	return efstypes.FileSystemDescription{
		FileSystemId: awssdk.String(id), FileSystemArn: awssdk.String("arn:aws:elasticfilesystem:us-east-1:111111111111:file-system/" + id),
		Encrypted: encrypted, Tags: tags, LifeCycleState: efstypes.LifeCycleStateAvailable,
	}
}

func TestCollectEFS(t *testing.T) {
	f := &fakeEFS{
		fss: []efstypes.FileSystemDescription{
			efsFS("fs-auto", awssdk.Bool(true)),
			efsFS("fs-tagged", awssdk.Bool(false), efstypes.Tag{Key: awssdk.String("backup"), Value: awssdk.String("daily")}),
			efsFS("fs-none", nil),
			efsFS("fs-unread", awssdk.Bool(true)),
		},
		backup:    map[string]efstypes.Status{"fs-auto": efstypes.StatusEnabled},
		backupErr: map[string]error{"fs-unread": errFakeDenied},
		policies: map[string]string{
			"fs-auto": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"elasticfilesystem:ClientMount"}]}`,
		},
		policyErr: map[string]error{"fs-unread": errFakeDenied},
		points: []efstypes.AccessPointDescription{
			{AccessPointArn: awssdk.String("arn:ap-root"), AccessPointId: awssdk.String("fsap-root"), FileSystemId: awssdk.String("fs-auto")},
			{
				AccessPointArn: awssdk.String("arn:ap-app"), AccessPointId: awssdk.String("fsap-app"), Name: awssdk.String("app"),
				RootDirectory: &efstypes.RootDirectory{Path: awssdk.String("/app")}, PosixUser: &efstypes.PosixUser{Uid: awssdk.Int64(1000), Gid: awssdk.Int64(1000)},
			},
		},
	}
	plans := &fakeBackup{
		plans: []backuptypes.BackupPlansListMember{{BackupPlanId: awssdk.String("p1")}},
		selections: map[string][]backuptypes.BackupSelection{"p1": {{
			Resources:  []string{"*"},
			Conditions: &backuptypes.Conditions{StringEquals: []backuptypes.ConditionParameter{{ConditionKey: awssdk.String("aws:ResourceTag/backup"), ConditionValue: awssdk.String("daily")}}},
		}}},
		optIn: map[string]bool{"EFS": true},
	}
	assets, err := collectEFSFileSystems(context.Background(), f, plans, "us-east-1", "111111111111", time.Now())
	require.NoError(t, err)
	fs := map[string]map[string]string{}
	aps := map[string]map[string]string{}
	for _, a := range assets {
		switch a.Type {
		case "efs_file_system":
			fs[a.Name] = a.Metadata
		case "efs_access_point":
			aps[a.Name] = a.Metadata
		}
	}
	require.Len(t, fs, 4, "every page is read")

	require.Equal(t, "true", fs["fs-auto"]["encrypted"])
	require.Equal(t, "ENABLED", fs["fs-auto"]["automatic_backups"])
	require.Equal(t, "true", fs["fs-auto"]["in_backup_plan"], "automatic backups are a backup plan")
	require.Equal(t, asset.PublicAccessConfirmed, fs["fs-auto"]["public_access"])

	require.Equal(t, "false", fs["fs-tagged"]["encrypted"])
	require.Equal(t, "DISABLED", fs["fs-tagged"]["automatic_backups"], "PolicyNotFound is automatic backups off")
	require.Equal(t, "true", fs["fs-tagged"]["in_backup_plan"], "selected by its tag")
	require.Equal(t, asset.PublicAccessNone, fs["fs-tagged"]["public_access"], "no policy is not an internet grant")

	_, ok := fs["fs-none"]["encrypted"]
	require.False(t, ok, "a nil Encrypted is unknown")
	require.Equal(t, "false", fs["fs-none"]["in_backup_plan"], "untagged: no assignment selects it")

	for _, k := range []string{"automatic_backups", "in_backup_plan", "public_access"} {
		_, ok := fs["fs-unread"][k]
		require.Falsef(t, ok, "%s must stay absent when its read was denied", k)
	}

	require.Equal(t, map[string]string{"file_system_id": "fs-auto", "root_directory": "/", "posix_user_enforced": "false"}, aps["fsap-root"])
	require.Equal(t, "/app", aps["app"]["root_directory"])
	require.Equal(t, "true", aps["app"]["posix_user_enforced"])
}

func TestCollectEFSDegradedReads(t *testing.T) {
	_, err := collectEFSFileSystems(context.Background(), &fakeEFS{
		fss: []efstypes.FileSystemDescription{efsFS("a", nil), efsFS("b", nil)}, fsPage2: errFakeDenied,
	}, &fakeBackup{}, "us-east-1", "111111111111", time.Now())
	require.Error(t, err, "a failed second page fails the listing")

	// Unreadable plans: only automatic backups decide coverage.
	assets, err := collectEFSFileSystems(context.Background(), &fakeEFS{
		fss:    []efstypes.FileSystemDescription{efsFS("on", nil), efsFS("off", nil)},
		backup: map[string]efstypes.Status{"on": efstypes.StatusEnabling},
	}, &fakeBackup{plansErr: errFakeDenied}, "us-east-1", "111111111111", time.Now())
	require.NoError(t, err)
	got := map[string]string{}
	for _, a := range assets {
		if v, ok := a.Metadata["in_backup_plan"]; ok {
			got[a.Name] = v
		}
	}
	require.Equal(t, map[string]string{"on": "true"}, got)
}

func TestBackupRuleAssigns(t *testing.T) {
	const arn = "arn:aws:elasticfilesystem:us-east-1:111111111111:file-system/fs-1"
	tag := func(k, v string) backuptypes.ConditionParameter {
		return backuptypes.ConditionParameter{ConditionKey: awssdk.String(k), ConditionValue: awssdk.String(v)}
	}
	tests := []struct {
		name  string
		sel   backuptypes.BackupSelection
		tags  map[string]string
		optIn map[string]bool
		want  tristate
	}{
		{"all resources, opted in", backuptypes.BackupSelection{Resources: []string{"*"}}, nil, map[string]bool{"EFS": true}, tristateYes},
		{"all resources, opted out", backuptypes.BackupSelection{Resources: []string{"*"}}, nil, map[string]bool{"EFS": false}, tristateNo},
		{"all resources, opt-in unknown", backuptypes.BackupSelection{Resources: []string{"*"}}, nil, nil, tristateUnknown},
		{"type pattern ignores opt-in", backuptypes.BackupSelection{Resources: []string{"arn:aws:elasticfilesystem:*:*:file-system/*"}}, nil, map[string]bool{"EFS": false}, tristateYes},
		{"other service", backuptypes.BackupSelection{Resources: []string{"arn:aws:ec2:*:*:volume/*"}}, nil, map[string]bool{"EFS": true}, tristateNo},
		{"excluded by NotResources", backuptypes.BackupSelection{Resources: []string{"*"}, NotResources: []string{"arn:aws:elasticfilesystem:*"}}, nil, map[string]bool{"EFS": true}, tristateNo},
		{"condition fails", backuptypes.BackupSelection{Resources: []string{"*"}, Conditions: &backuptypes.Conditions{StringEquals: []backuptypes.ConditionParameter{tag("aws:ResourceTag/backup", "true")}}}, nil, map[string]bool{"EFS": true}, tristateNo},
		{"not-equals on a missing tag holds", backuptypes.BackupSelection{Resources: []string{"*"}, Conditions: &backuptypes.Conditions{StringNotEquals: []backuptypes.ConditionParameter{tag("aws:ResourceTag/stage", "test")}}}, nil, map[string]bool{"EFS": true}, tristateYes},
		{"like wildcard", backuptypes.BackupSelection{Resources: []string{"*"}, Conditions: &backuptypes.Conditions{StringLike: []backuptypes.ConditionParameter{tag("aws:ResourceTag/env", "prod*")}}}, map[string]string{"env": "prod-eu"}, map[string]bool{"EFS": true}, tristateYes},
		{"wildcard stops at whitespace", backuptypes.BackupSelection{Resources: []string{"*"}, Conditions: &backuptypes.Conditions{StringLike: []backuptypes.ConditionParameter{tag("aws:ResourceTag/env", "prod*")}}}, map[string]string{"env": "prod eu"}, map[string]bool{"EFS": true}, tristateNo},
		{"list of tags, bare key", backuptypes.BackupSelection{ListOfTags: []backuptypes.Condition{{ConditionType: backuptypes.ConditionTypeStringequals, ConditionKey: awssdk.String("backup"), ConditionValue: awssdk.String("true")}}}, map[string]string{"backup": "true"}, map[string]bool{"EFS": true}, tristateYes},
		{"non-tag condition key", backuptypes.BackupSelection{Resources: []string{"*"}, Conditions: &backuptypes.Conditions{StringEquals: []backuptypes.ConditionParameter{tag("aws:RequestedRegion", "us-east-1")}}}, nil, map[string]bool{"EFS": true}, tristateUnknown},
		{"no resources at all", backuptypes.BackupSelection{}, nil, map[string]bool{"EFS": true}, tristateNo},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, backupRuleFrom(tt.sel).assigns(arn, tt.tags, tt.optIn, "EFS", "file-system/"))
		})
	}
}

func TestBackupPlanCoverageCombinesRules(t *testing.T) {
	const arn = "arn:aws:elasticfilesystem:us-east-1:111111111111:file-system/fs-1"
	undecided := backupRuleFrom(backuptypes.BackupSelection{Resources: []string{"*"}})
	no := backupRuleFrom(backuptypes.BackupSelection{Resources: []string{"arn:aws:ec2:*"}})
	yes := backupRuleFrom(backuptypes.BackupSelection{Resources: []string{arn}})

	covered, known := (&backupPlanCoverage{rules: []backupRule{undecided, yes}}).covers(arn, nil, "EFS", "file-system/")
	require.True(t, covered)
	require.True(t, known, "one decisive assignment settles it")

	covered, known = (&backupPlanCoverage{rules: []backupRule{no, undecided}}).covers(arn, nil, "EFS", "file-system/")
	require.False(t, covered)
	require.False(t, known, "an undecidable assignment leaves coverage unknown")

	covered, known = (&backupPlanCoverage{}).covers(arn, nil, "EFS", "file-system/")
	require.False(t, covered)
	require.True(t, known, "no plans at all is an observation")
}

func TestBackupGlobMatch(t *testing.T) {
	require.True(t, backupGlobMatch("*", "anything"))
	require.True(t, backupGlobMatch("arn:aws:rds:*:*:db:*", "arn:aws:rds:us-east-1:1:db:x"))
	require.False(t, backupGlobMatch("arn:aws:rds:*:*:db:*", "arn:aws:rds:us-east-1:1:cluster:x"))
	require.True(t, backupGlobMatch("*exclude*", "do-exclude-me"))
	require.False(t, backupGlobMatch("a*", "a b"))
	require.True(t, backupGlobMatch("exact", "exact"))
}
