package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	ostypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// OpenSearch Service domains, both engines: the opensearch API lists and
// describes legacy Elasticsearch domains too (EngineVersion
// "Elasticsearch_7.10" vs "OpenSearch_2.11"), so one collector and one asset
// type cover AWS FSBP's ES.n and Opensearch.n controls without describing a
// domain twice.

// openSearchDescribeBatch is DescribeDomains' documented limit on domain
// names per call.
const openSearchDescribeBatch = 5

// openSearchDataActions are the data-plane actions a domain access policy can
// grant: every HTTP verb against the domain's indices. es:* and es:ESHttp*
// cover them; a public grant of a configuration read (es:DescribeDomain) is
// not data access and is not graded public.
var openSearchDataActions = []string{
	"es:eshttpget", "es:eshttphead", "es:eshttppost",
	"es:eshttpput", "es:eshttppatch", "es:eshttpdelete",
}

type openSearchAPI interface {
	ListDomainNames(context.Context, *opensearch.ListDomainNamesInput, ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error)
	DescribeDomains(context.Context, *opensearch.DescribeDomainsInput, ...func(*opensearch.Options)) (*opensearch.DescribeDomainsOutput, error)
}

func collectOpenSearch(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectOpenSearch: %w", err)
	}
	return collectOpenSearchDomains(ctx, opensearch.NewFromConfig(awsCfg), region, accountID, now)
}

// collectOpenSearchDomains lists the region's domains (ListDomainNames is not
// paginated: it returns every domain) and describes them in batches. A failed
// batch fails the listing, so a nil error means every listed domain was
// described.
func collectOpenSearchDomains(ctx context.Context, client openSearchAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	list, err := client.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("collectOpenSearchDomains: list: %w", err)
	}
	names := make([]string, 0, len(list.DomainNames))
	for _, d := range list.DomainNames {
		if n := awssdk.ToString(d.DomainName); n != "" {
			names = append(names, n)
		}
	}
	var assets []asset.Asset
	for start := 0; start < len(names); start += openSearchDescribeBatch {
		batch := names[start:min(start+openSearchDescribeBatch, len(names))]
		out, err := client.DescribeDomains(ctx, &opensearch.DescribeDomainsInput{DomainNames: batch})
		if err != nil {
			return nil, fmt.Errorf("collectOpenSearchDomains: describe: %w", err)
		}
		for _, d := range out.DomainStatusList {
			if awssdk.ToBool(d.Deleted) {
				continue
			}
			assets = append(assets, asset.Asset{
				ID:           awssdk.ToString(d.ARN),
				Name:         awssdk.ToString(d.DomainName),
				Type:         "opensearch_domain",
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Endpoint:     openSearchEndpoint(d),
				Metadata:     openSearchDomainMetadata(d),
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
	}
	return assets, nil
}

func openSearchEndpoint(d ostypes.DomainStatus) string {
	if e := awssdk.ToString(d.Endpoint); e != "" {
		return e
	}
	return d.Endpoints["vpc"]
}

// openSearchDomainMetadata maps a described domain onto posture keys. An
// option block the response omits leaves its keys absent (unknown), except
// where the omission IS the API's answer: no VPCOptions means a public
// endpoint, no log publishing entry means the log type is not published, and
// no AdvancedSecurityOptions means fine-grained access control is off.
func openSearchDomainMetadata(d ostypes.DomainStatus) map[string]string {
	version := awssdk.ToString(d.EngineVersion)
	meta := map[string]string{
		"engine":         openSearchEngine(version),
		"engine_version": version,
		"in_vpc":         strconv.FormatBool(d.VPCOptions != nil && len(d.VPCOptions.SubnetIds) > 0),
	}
	if v := d.VPCOptions; v != nil && awssdk.ToString(v.VPCId) != "" {
		meta["vpc_id"] = awssdk.ToString(v.VPCId)
	}
	if e := d.EncryptionAtRestOptions; e != nil {
		meta["encryption_at_rest"] = strconv.FormatBool(awssdk.ToBool(e.Enabled))
	}
	if n := d.NodeToNodeEncryptionOptions; n != nil {
		meta["node_to_node_encryption"] = strconv.FormatBool(awssdk.ToBool(n.Enabled))
	}
	if e := d.DomainEndpointOptions; e != nil {
		meta["enforce_https"] = strconv.FormatBool(awssdk.ToBool(e.EnforceHTTPS))
		meta["tls_security_policy"] = string(e.TLSSecurityPolicy)
	}
	meta["error_logs_enabled"] = strconv.FormatBool(openSearchLogPublished(d.LogPublishingOptions, ostypes.LogTypeEsApplicationLogs))
	meta["audit_logs_enabled"] = strconv.FormatBool(openSearchLogPublished(d.LogPublishingOptions, ostypes.LogTypeAuditLogs))
	meta["search_slow_logs_enabled"] = strconv.FormatBool(openSearchLogPublished(d.LogPublishingOptions, ostypes.LogTypeSearchSlowLogs))
	meta["index_slow_logs_enabled"] = strconv.FormatBool(openSearchLogPublished(d.LogPublishingOptions, ostypes.LogTypeIndexSlowLogs))
	if c := d.ClusterConfig; c != nil {
		if c.InstanceCount != nil {
			meta["instance_count"] = strconv.Itoa(int(awssdk.ToInt32(c.InstanceCount)))
		}
		meta["zone_awareness"] = strconv.FormatBool(awssdk.ToBool(c.ZoneAwarenessEnabled))
		meta["dedicated_master_enabled"] = strconv.FormatBool(awssdk.ToBool(c.DedicatedMasterEnabled))
		meta["dedicated_master_count"] = strconv.Itoa(int(awssdk.ToInt32(c.DedicatedMasterCount)))
	}
	fgac := d.AdvancedSecurityOptions != nil && awssdk.ToBool(d.AdvancedSecurityOptions.Enabled)
	meta["fine_grained_access_control"] = strconv.FormatBool(fgac)
	// Anonymous auth (a migration aid) lets unauthenticated requests through
	// fine-grained access control, so it does not gate an open policy.
	fgacGates := fgac && !awssdk.ToBool(d.AdvancedSecurityOptions.AnonymousAuthEnabled)
	if s := d.ServiceSoftwareOptions; s != nil && s.UpdateAvailable != nil {
		meta["service_software_update_available"] = strconv.FormatBool(awssdk.ToBool(s.UpdateAvailable))
	}

	policyPublic, policies := resourcePolicyMetadata(awssdk.ToString(d.AccessPolicies), awssdk.ToString(d.DomainName)+"-resource", openSearchDataActions)
	meta["access_policy_public"] = strconv.FormatBool(policyPublic == asset.PublicAccessConfirmed)
	if policies != "" {
		meta["policies"] = policies
	}
	meta["public_access"] = openSearchExposure(meta["in_vpc"] == "true", policyPublic == asset.PublicAccessConfirmed, fgacGates)
	return meta
}

// openSearchExposure grades internet exposure. A VPC domain has no public
// endpoint whatever its policy says. A public endpoint whose policy opens the
// data actions to everyone, with nothing else authenticating the caller, is
// confirmed; one still gated by a restricted policy (IAM-signed requests, an
// IP condition) or by fine-grained access control is reachable but
// credential-gated — the possible tier.
func openSearchExposure(inVPC, policyOpen, fgacGates bool) string {
	switch {
	case inVPC:
		return asset.PublicAccessNone
	case policyOpen && !fgacGates:
		return asset.PublicAccessConfirmed
	default:
		return asset.PublicAccessPossible
	}
}

// openSearchEngine names the engine from the EngineVersion prefix.
func openSearchEngine(version string) string {
	switch {
	case strings.HasPrefix(version, "Elasticsearch_"):
		return "Elasticsearch"
	case strings.HasPrefix(version, "OpenSearch_"):
		return "OpenSearch"
	}
	return ""
}

// openSearchLogPublished reports whether a log type is published to a
// CloudWatch Logs group.
func openSearchLogPublished(opts map[string]ostypes.LogPublishingOption, logType ostypes.LogType) bool {
	o, ok := opts[string(logType)]
	return ok && awssdk.ToBool(o.Enabled) && awssdk.ToString(o.CloudWatchLogsLogGroupArn) != ""
}
