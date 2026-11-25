package aws

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshiftserverless"
	rsstypes "github.com/aws/aws-sdk-go-v2/service/redshiftserverless/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Redshift Serverless posture (FSBP RedshiftServerless.1/2/3 on workgroups,
// .5/.6 on namespaces). Namespaces are read with GetNamespace from each
// workgroup's namespaceName rather than ListNamespaces, which neither
// SecurityAudit nor ViewOnlyAccess grants. A namespace no workgroup uses
// holds no running compute and is not reached; every workgroup has one.

type redshiftServerlessAPI interface {
	ListWorkgroups(context.Context, *redshiftserverless.ListWorkgroupsInput, ...func(*redshiftserverless.Options)) (*redshiftserverless.ListWorkgroupsOutput, error)
	GetNamespace(context.Context, *redshiftserverless.GetNamespaceInput, ...func(*redshiftserverless.Options)) (*redshiftserverless.GetNamespaceOutput, error)
}

// collectRedshiftServerless returns the region's workgroups and their
// namespaces. partial is true when a namespace could not be read: it is not
// emitted (its ARN carries an ID the workgroup listing does not give), so the
// sweep must say its absence is not a deletion.
func collectRedshiftServerless(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, bool, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, false, fmt.Errorf("collectRedshiftServerless: %w", err)
	}
	return collectRedshiftServerlessResources(ctx, redshiftserverless.NewFromConfig(awsCfg), region, accountID, now)
}

func collectRedshiftServerlessResources(ctx context.Context, client redshiftServerlessAPI, region, accountID string, now time.Time) ([]asset.Asset, bool, error) {
	var (
		workgroups []rsstypes.Workgroup
		next       *string
	)
	for {
		out, err := client.ListWorkgroups(ctx, &redshiftserverless.ListWorkgroupsInput{NextToken: next})
		if err != nil {
			return nil, false, fmt.Errorf("collectRedshiftServerlessResources: %w", err)
		}
		workgroups = append(workgroups, out.Workgroups...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		next = out.NextToken
	}

	assets := make([]asset.Asset, 0, len(workgroups))
	var names []string
	for _, w := range workgroups {
		assets = append(assets, asset.Asset{
			ID:           awssdk.ToString(w.WorkgroupArn),
			Name:         awssdk.ToString(w.WorkgroupName),
			Type:         "redshift_serverless_workgroup",
			Provider:     asset.ProviderAWS,
			Region:       region,
			AccountID:    accountID,
			Metadata:     redshiftWorkgroupFacts(w),
			DiscoveredAt: now,
			LastSeen:     now,
		})
		if n := awssdk.ToString(w.NamespaceName); n != "" && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}

	namespaces := make([]*rsstypes.Namespace, len(names))
	eachBounded(ctx, len(names), redshiftCallTimeout, "redshift-serverless:GetNamespace", func(ctx context.Context, i int) {
		out, err := client.GetNamespace(ctx, &redshiftserverless.GetNamespaceInput{NamespaceName: awssdk.String(names[i])})
		if err == nil && out != nil {
			namespaces[i] = out.Namespace
		}
	})
	unread := 0
	for i, ns := range namespaces {
		if ns == nil {
			unread++
			continue
		}
		assets = append(assets, asset.Asset{
			ID:           awssdk.ToString(ns.NamespaceArn),
			Name:         names[i],
			Type:         "redshift_serverless_namespace",
			Provider:     asset.ProviderAWS,
			Region:       region,
			AccountID:    accountID,
			Metadata:     redshiftNamespaceFacts(ns),
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	if unread > 0 {
		log.FromContext(ctx).Warn().Str("region", region).Int("namespaces", len(names)).Int("unread", unread).
			Msg("redshift-serverless: GetNamespace failed for some namespaces (check redshift-serverless:GetNamespace); their admin username and log exports are unknown this sweep, sweep flagged partial")
	}
	return assets, unread > 0, nil
}

// redshiftWorkgroupFacts are a workgroup's network and TLS settings. A nil
// pointer leaves its key absent; require_ssl is written only when the
// workgroup's configParameters carry it.
func redshiftWorkgroupFacts(w rsstypes.Workgroup) map[string]string {
	meta := map[string]string{"namespace": awssdk.ToString(w.NamespaceName)}
	if w.EnhancedVpcRouting != nil {
		meta["enhanced_vpc_routing"] = strconv.FormatBool(*w.EnhancedVpcRouting)
	}
	if w.PubliclyAccessible != nil {
		meta["publicly_accessible"] = strconv.FormatBool(*w.PubliclyAccessible)
		if *w.PubliclyAccessible {
			// Reachable from the internet but still credential-gated: the
			// possible tier, as for a publicly accessible RDS instance.
			meta["public_access"] = asset.PublicAccessPossible
		}
	}
	for _, p := range w.ConfigParameters {
		if awssdk.ToString(p.ParameterKey) == "require_ssl" && p.ParameterValue != nil {
			meta["require_ssl"] = strings.ToLower(strings.TrimSpace(*p.ParameterValue))
		}
	}
	if w.Port != nil {
		meta["port"] = strconv.Itoa(int(*w.Port))
	}
	return meta
}

// redshiftNamespaceFacts are a namespace's admin user name (never a
// credential) and the log types it exports to CloudWatch, written
// present-and-empty when it exports none.
func redshiftNamespaceFacts(ns *rsstypes.Namespace) map[string]string {
	exports := make([]string, 0, len(ns.LogExports))
	for _, e := range ns.LogExports {
		exports = append(exports, string(e))
	}
	slices.Sort(exports)
	meta := map[string]string{"log_exports": strings.Join(exports, ",")}
	if u := awssdk.ToString(ns.AdminUsername); u != "" {
		meta["admin_username"] = u
	}
	return meta
}
