package aws

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	cbtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// codebuildBatchSize is BatchGetProjects' / BatchGetReportGroups' per-call cap.
const codebuildBatchSize = 100

// codebuildCredentialEnvNames are the variable names FSBP CodeBuild.2
// (codebuild-project-envvar-awscred-check) treats as a static AWS credential.
var codebuildCredentialEnvNames = []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}

type codebuildAPI interface {
	ListProjects(context.Context, *codebuild.ListProjectsInput, ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error)
	BatchGetProjects(context.Context, *codebuild.BatchGetProjectsInput, ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error)
}

type codebuildReportAPI interface {
	ListReportGroups(context.Context, *codebuild.ListReportGroupsInput, ...func(*codebuild.Options)) (*codebuild.ListReportGroupsOutput, error)
	BatchGetReportGroups(context.Context, *codebuild.BatchGetReportGroupsInput, ...func(*codebuild.Options)) (*codebuild.BatchGetReportGroupsOutput, error)
}

func collectCodeBuild(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectCodeBuild: %w", err)
	}
	return readCodeBuildProjects(ctx, codebuild.NewFromConfig(awsCfg), region, accountID, now)
}

func collectCodeBuildReportGroups(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectCodeBuildReportGroups: %w", err)
	}
	return readCodeBuildReportGroups(ctx, codebuild.NewFromConfig(awsCfg), region, accountID, now)
}

// readCodeBuildProjects lists every project and describes them in batches. A
// failed batch leaves its projects emitted with no posture keys.
func readCodeBuildProjects(ctx context.Context, client codebuildAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var names []string
	var next *string
	for {
		out, err := client.ListProjects(ctx, &codebuild.ListProjectsInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("readCodeBuildProjects: ListProjects: %w", err)
		}
		names = append(names, out.Projects...)
		if out.NextToken == nil {
			break
		}
		next = out.NextToken
	}
	var assets []asset.Asset
	for start := 0; start < len(names); start += codebuildBatchSize {
		batch := names[start:min(start+codebuildBatchSize, len(names))]
		described := map[string]cbtypes.Project{}
		out, err := client.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{Names: batch})
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("region", region).
				Msg("codebuild: BatchGetProjects failed (check codebuild:BatchGetProjects); project posture unknown this sweep")
		} else {
			for _, p := range out.Projects {
				described[awssdk.ToString(p.Name)] = p
			}
		}
		for _, name := range batch {
			p, ok := described[name]
			id := awssdk.ToString(p.Arn)
			if id == "" {
				id = fmt.Sprintf("arn:%s:codebuild:%s:%s:project/%s", partitionFor(region), region, accountID, name)
			}
			meta := map[string]string{}
			if ok {
				meta = codebuildProjectMetadata(p)
			}
			assets = append(assets, asset.Asset{
				ID: id, Name: name, Type: "codebuild_project", Provider: asset.ProviderAWS,
				Region: region, AccountID: accountID, Metadata: meta, DiscoveredAt: now, LastSeen: now,
			})
		}
	}
	return assets, nil
}

func codebuildProjectMetadata(p cbtypes.Project) map[string]string {
	meta := map[string]string{}
	var credSources []string
	if p.Source != nil && sourceURLHasCredentials(awssdk.ToString(p.Source.Location)) {
		credSources = append(credSources, "primary")
	}
	for i, s := range p.SecondarySources {
		if sourceURLHasCredentials(awssdk.ToString(s.Location)) {
			id := awssdk.ToString(s.SourceIdentifier)
			if id == "" {
				id = "secondary-" + strconv.Itoa(i)
			}
			credSources = append(credSources, id)
		}
	}
	// The sources arrive with the project, so this is always an observation:
	// "" means no source URL carries credentials.
	meta["source_url_credentials"] = strings.Join(credSources, ",")
	if p.Environment != nil {
		var envNames []string
		for _, v := range p.Environment.EnvironmentVariables {
			// An omitted type is PLAINTEXT (the API default).
			if v.Type != "" && v.Type != cbtypes.EnvironmentVariableTypePlaintext {
				continue
			}
			for _, n := range codebuildCredentialEnvNames {
				if strings.EqualFold(awssdk.ToString(v.Name), n) {
					envNames = append(envNames, awssdk.ToString(v.Name))
				}
			}
		}
		meta["plaintext_aws_credential_env"] = strings.Join(envNames, ",")
	}
	if lc := p.LogsConfig; lc != nil {
		if lc.CloudWatchLogs != nil && lc.CloudWatchLogs.Status != "" {
			meta["cloudwatch_logs_status"] = string(lc.CloudWatchLogs.Status)
		}
		if lc.S3Logs != nil && lc.S3Logs.Status != "" {
			meta["s3_logs_status"] = string(lc.S3Logs.Status)
			// EncryptionDisabled defaults to false: S3 build logs are encrypted
			// unless the project opts out.
			meta["s3_logs_encryption_disabled"] = strconv.FormatBool(awssdk.ToBool(lc.S3Logs.EncryptionDisabled))
		}
	}
	return meta
}

// sourceURLHasCredentials reports a source location carrying userinfo
// (user:password@ or token@) — FSBP CodeBuild.1. S3 and CodeCommit
// locations without userinfo, and non-URL locations, are clean.
func sourceURLHasCredentials(location string) bool {
	if !strings.Contains(location, "://") {
		return false
	}
	u, err := url.Parse(location)
	if err != nil {
		// An unparseable URL that still has user info before the host.
		rest := location[strings.Index(location, "://")+3:]
		host, _, _ := strings.Cut(rest, "/")
		return strings.Contains(host, "@")
	}
	return u.User != nil && u.User.String() != ""
}

// readCodeBuildReportGroups lists report groups (FSBP CodeBuild.7). Neither
// SecurityAudit nor ViewOnlyAccess grants these two calls; a deny fails the
// listing, which the region loop records as a skipped collector.
func readCodeBuildReportGroups(ctx context.Context, client codebuildReportAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var arns []string
	var next *string
	for {
		out, err := client.ListReportGroups(ctx, &codebuild.ListReportGroupsInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("readCodeBuildReportGroups: ListReportGroups: %w", err)
		}
		arns = append(arns, out.ReportGroups...)
		if out.NextToken == nil {
			break
		}
		next = out.NextToken
	}
	var assets []asset.Asset
	for start := 0; start < len(arns); start += codebuildBatchSize {
		batch := arns[start:min(start+codebuildBatchSize, len(arns))]
		described := map[string]cbtypes.ReportGroup{}
		out, err := client.BatchGetReportGroups(ctx, &codebuild.BatchGetReportGroupsInput{ReportGroupArns: batch})
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("region", region).
				Msg("codebuild: BatchGetReportGroups failed (check codebuild:BatchGetReportGroups); report export encryption unknown this sweep")
		} else {
			for _, g := range out.ReportGroups {
				described[awssdk.ToString(g.Arn)] = g
			}
		}
		for _, arn := range batch {
			g, ok := described[arn]
			meta := map[string]string{}
			name := arn[strings.LastIndex(arn, "/")+1:]
			if ok {
				name = awssdk.ToString(g.Name)
				if ec := g.ExportConfig; ec != nil && ec.ExportConfigType != "" {
					meta["export_type"] = string(ec.ExportConfigType)
					if ec.ExportConfigType == cbtypes.ReportExportConfigTypeS3 && ec.S3Destination != nil {
						// EncryptionDisabled defaults to false (exports encrypted).
						meta["export_encryption_disabled"] = strconv.FormatBool(awssdk.ToBool(ec.S3Destination.EncryptionDisabled))
					}
				}
			}
			assets = append(assets, asset.Asset{
				ID: arn, Name: name, Type: "codebuild_report_group", Provider: asset.ProviderAWS,
				Region: region, AccountID: accountID, Metadata: meta, DiscoveredAt: now, LastSeen: now,
			})
		}
	}
	return assets, nil
}
