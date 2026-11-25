package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	cbtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/stretchr/testify/require"
)

type fakeCodeBuild struct {
	pages    []*codebuild.ListProjectsOutput
	listErr  error
	projects map[string]cbtypes.Project
	batchErr error
	batches  int

	groupPages []*codebuild.ListReportGroupsOutput
	groups     map[string]cbtypes.ReportGroup
	groupErr   error
}

func (f *fakeCodeBuild) ListProjects(_ context.Context, in *codebuild.ListProjectsInput, _ ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error) {
	if f.listErr != nil && in.NextToken != nil {
		return nil, f.listErr
	}
	i := 0
	if in.NextToken != nil {
		i = 1
	}
	return f.pages[i], nil
}

func (f *fakeCodeBuild) BatchGetProjects(_ context.Context, in *codebuild.BatchGetProjectsInput, _ ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error) {
	f.batches++
	if f.batchErr != nil {
		return nil, f.batchErr
	}
	out := &codebuild.BatchGetProjectsOutput{}
	for _, n := range in.Names {
		if p, ok := f.projects[n]; ok {
			out.Projects = append(out.Projects, p)
		} else {
			out.ProjectsNotFound = append(out.ProjectsNotFound, n)
		}
	}
	return out, nil
}

func (f *fakeCodeBuild) ListReportGroups(_ context.Context, in *codebuild.ListReportGroupsInput, _ ...func(*codebuild.Options)) (*codebuild.ListReportGroupsOutput, error) {
	if f.groupErr != nil {
		return nil, f.groupErr
	}
	if in.NextToken != nil {
		return f.groupPages[1], nil
	}
	return f.groupPages[0], nil
}

func (f *fakeCodeBuild) BatchGetReportGroups(_ context.Context, in *codebuild.BatchGetReportGroupsInput, _ ...func(*codebuild.Options)) (*codebuild.BatchGetReportGroupsOutput, error) {
	out := &codebuild.BatchGetReportGroupsOutput{}
	for _, a := range in.ReportGroupArns {
		if g, ok := f.groups[a]; ok {
			out.ReportGroups = append(out.ReportGroups, g)
		}
	}
	return out, nil
}

func TestReadCodeBuildProjects(t *testing.T) {
	leaky := cbtypes.Project{
		Name: awssdk.String("leaky"), Arn: awssdk.String("arn:aws:codebuild:eu-west-1:1:project/leaky"),
		Source: &cbtypes.ProjectSource{Type: cbtypes.SourceTypeBitbucket, Location: awssdk.String("https://bob:hunter2@bitbucket.org/acme/app.git")},
		SecondarySources: []cbtypes.ProjectSource{
			{Type: cbtypes.SourceTypeGithub, Location: awssdk.String("https://ghp_token@github.com/acme/lib.git"), SourceIdentifier: awssdk.String("lib")},
			{Type: cbtypes.SourceTypeS3, Location: awssdk.String("bucket/key.zip"), SourceIdentifier: awssdk.String("assets")},
		},
		Environment: &cbtypes.ProjectEnvironment{EnvironmentVariables: []cbtypes.EnvironmentVariable{
			{Name: awssdk.String("AWS_ACCESS_KEY_ID"), Value: awssdk.String("AKIA...")}, // type omitted = PLAINTEXT
			{Name: awssdk.String("AWS_SECRET_ACCESS_KEY"), Value: awssdk.String("/ci/secret"), Type: cbtypes.EnvironmentVariableTypeParameterStore},
			{Name: awssdk.String("STAGE"), Value: awssdk.String("prod"), Type: cbtypes.EnvironmentVariableTypePlaintext},
		}},
		LogsConfig: &cbtypes.LogsConfig{
			CloudWatchLogs: &cbtypes.CloudWatchLogsConfig{Status: cbtypes.LogsConfigStatusTypeDisabled},
			S3Logs:         &cbtypes.S3LogsConfig{Status: cbtypes.LogsConfigStatusTypeEnabled, EncryptionDisabled: awssdk.Bool(true)},
		},
	}
	clean := cbtypes.Project{
		Name:        awssdk.String("clean"),
		Arn:         awssdk.String("arn:aws:codebuild:eu-west-1:1:project/clean"),
		Source:      &cbtypes.ProjectSource{Type: cbtypes.SourceTypeCodecommit, Location: awssdk.String("https://git-codecommit.eu-west-1.amazonaws.com/v1/repos/app")},
		Environment: &cbtypes.ProjectEnvironment{},
		LogsConfig: &cbtypes.LogsConfig{
			CloudWatchLogs: &cbtypes.CloudWatchLogsConfig{Status: cbtypes.LogsConfigStatusTypeEnabled},
			S3Logs:         &cbtypes.S3LogsConfig{Status: cbtypes.LogsConfigStatusTypeEnabled}, // EncryptionDisabled omitted = encrypted
		},
	}
	f := &fakeCodeBuild{
		pages: []*codebuild.ListProjectsOutput{
			{Projects: []string{"leaky"}, NextToken: awssdk.String("p2")},
			{Projects: []string{"clean", "gone"}},
		},
		projects: map[string]cbtypes.Project{"leaky": leaky, "clean": clean},
	}
	got, err := readCodeBuildProjects(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 3, "every listed project is emitted, across pages")
	byName := map[string]map[string]string{}
	for _, a := range got {
		require.Equal(t, "codebuild_project", a.Type)
		byName[a.Name] = a.Metadata
	}
	require.Equal(t, "primary,lib", byName["leaky"]["source_url_credentials"])
	require.Equal(t, "AWS_ACCESS_KEY_ID", byName["leaky"]["plaintext_aws_credential_env"], "only PLAINTEXT credential names, never values")
	require.NotContains(t, byName["leaky"]["plaintext_aws_credential_env"], "AKIA")
	require.Equal(t, "DISABLED", byName["leaky"]["cloudwatch_logs_status"])
	require.Equal(t, "true", byName["leaky"]["s3_logs_encryption_disabled"])
	require.Equal(t, "", byName["clean"]["source_url_credentials"])
	require.Equal(t, "", byName["clean"]["plaintext_aws_credential_env"])
	require.Equal(t, "false", byName["clean"]["s3_logs_encryption_disabled"])
	require.Empty(t, byName["gone"], "a project the batch did not return carries no posture keys")

	f.batchErr = errors.New("throttled")
	got, err = readCodeBuildProjects(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err, "a failed describe does not fail the listing")
	require.Len(t, got, 3)
	for _, a := range got {
		require.Empty(t, a.Metadata, "an undescribed project is unknown, not clean")
	}

	f.batchErr, f.listErr = nil, errors.New("page 2 failed")
	_, err = readCodeBuildProjects(context.Background(), f, "eu-west-1", "1", time.Now())
	require.Error(t, err, "a failed page fails the call rather than returning a short list")
}

func TestReadCodeBuildProjectsEmpty(t *testing.T) {
	f := &fakeCodeBuild{pages: []*codebuild.ListProjectsOutput{{}}}
	got, err := readCodeBuildProjects(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Empty(t, got)
	require.Zero(t, f.batches, "no projects, no describe call")
}

func TestSourceURLHasCredentials(t *testing.T) {
	for loc, want := range map[string]bool{
		"https://user:pass@bitbucket.org/a/b.git": true,
		"https://x-token-auth@bitbucket.org/a/b":  true,
		"https://bitbucket.org/a/b.git":           false,
		"bucket/prefix/source.zip":                false,
		"":                                        false,
		"https://github.com/a/b":                  false,
	} {
		require.Equal(t, want, sourceURLHasCredentials(loc), loc)
	}
}

func TestReadCodeBuildReportGroups(t *testing.T) {
	a1, a2, a3 := "arn:aws:codebuild:eu-west-1:1:report-group/plain", "arn:aws:codebuild:eu-west-1:1:report-group/enc", "arn:aws:codebuild:eu-west-1:1:report-group/none"
	f := &fakeCodeBuild{
		groupPages: []*codebuild.ListReportGroupsOutput{{ReportGroups: []string{a1}, NextToken: awssdk.String("n")}, {ReportGroups: []string{a2, a3}}},
		groups: map[string]cbtypes.ReportGroup{
			a1: {Arn: &a1, Name: awssdk.String("plain"), ExportConfig: &cbtypes.ReportExportConfig{ExportConfigType: cbtypes.ReportExportConfigTypeS3, S3Destination: &cbtypes.S3ReportExportConfig{EncryptionDisabled: awssdk.Bool(true)}}},
			a2: {Arn: &a2, Name: awssdk.String("enc"), ExportConfig: &cbtypes.ReportExportConfig{ExportConfigType: cbtypes.ReportExportConfigTypeS3, S3Destination: &cbtypes.S3ReportExportConfig{}}},
			a3: {Arn: &a3, Name: awssdk.String("none"), ExportConfig: &cbtypes.ReportExportConfig{ExportConfigType: cbtypes.ReportExportConfigTypeNoExport}},
		},
	}
	got, err := readCodeBuildReportGroups(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 3)
	require.Equal(t, "true", got[0].Metadata["export_encryption_disabled"])
	require.Equal(t, "false", got[1].Metadata["export_encryption_disabled"])
	require.Equal(t, "NO_EXPORT", got[2].Metadata["export_type"])
	require.NotContains(t, got[2].Metadata, "export_encryption_disabled")

	f.groupErr = errors.New("AccessDenied")
	_, err = readCodeBuildReportGroups(context.Background(), f, "eu-west-1", "1", time.Now())
	require.Error(t, err)
}
