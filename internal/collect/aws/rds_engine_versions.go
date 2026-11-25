package aws

import (
	"context"
	"fmt"
	"strconv"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// stampRDSEngineVersionFacts writes engine_version_available onto each
// instance: "true" when its engine version is in the list RDS still offers
// for new databases of that engine in the region, "false" when it has been
// retired from it. DescribeDBEngineVersions is read once per engine in use.
// An engine whose listing failed or came back empty leaves the key absent
// (unknown) for its instances: a retired version is the claim, and an
// unreadable catalogue cannot support it.
func stampRDSEngineVersionFacts(ctx context.Context, client rdsPostureAPI, region string, instances []asset.Asset) {
	catalogues := map[string]map[string]bool{}
	for _, a := range instances {
		engine := a.Metadata["engine"]
		if engine == "" || a.Metadata["engine_version"] == "" {
			continue
		}
		if _, read := catalogues[engine]; read {
			continue
		}
		versions, err := listRDSEngineVersions(ctx, client, engine)
		if err != nil || len(versions) == 0 {
			log.FromContext(ctx).Warn().Err(err).Str("region", region).Str("engine", engine).
				Msg("rds engine versions unreadable (check rds:DescribeDBEngineVersions); deprecated-version status unknown for its instances")
			versions = nil
		}
		catalogues[engine] = versions
	}
	for _, a := range instances {
		if versions := catalogues[a.Metadata["engine"]]; versions != nil && a.Metadata["engine_version"] != "" {
			a.Metadata["engine_version_available"] = strconv.FormatBool(versions[a.Metadata["engine_version"]])
		}
	}
}

func listRDSEngineVersions(ctx context.Context, client rdsPostureAPI, engine string) (map[string]bool, error) {
	versions := map[string]bool{}
	var marker *string
	for {
		page, err := client.DescribeDBEngineVersions(ctx, &rds.DescribeDBEngineVersionsInput{Engine: awssdk.String(engine), Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("listRDSEngineVersions: %w", err)
		}
		for _, v := range page.DBEngineVersions {
			versions[awssdk.ToString(v.EngineVersion)] = true
		}
		if page.Marker == nil {
			return versions, nil
		}
		marker = page.Marker
	}
}
