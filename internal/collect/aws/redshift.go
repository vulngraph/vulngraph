package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Amazon Redshift provisioned-cluster posture (FSBP Redshift.1/2/3/4/6/7/8/
// 10/15/18). DescribeClusters carries most settings; audit logging and the
// require_ssl parameter need one more read each — DescribeLoggingStatus per
// cluster and DescribeClusterParameters per distinct parameter group — both
// fanned out under a bound. Redshift.15 (cluster port world-open) is a join
// against the collected security groups (stampRedshiftPortWorldOpen).

// redshiftCallTimeout bounds one per-cluster / per-group read, so a hung call
// costs one cluster's key rather than the region's whole budget.
const redshiftCallTimeout = 15 * time.Second

type redshiftAPI interface {
	DescribeClusters(context.Context, *redshift.DescribeClustersInput, ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error)
	DescribeLoggingStatus(context.Context, *redshift.DescribeLoggingStatusInput, ...func(*redshift.Options)) (*redshift.DescribeLoggingStatusOutput, error)
	DescribeClusterParameters(context.Context, *redshift.DescribeClusterParametersInput, ...func(*redshift.Options)) (*redshift.DescribeClusterParametersOutput, error)
}

func collectRedshift(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectRedshift: %w", err)
	}
	return collectRedshiftClusters(ctx, redshift.NewFromConfig(awsCfg), region, accountID, now)
}

func collectRedshiftClusters(ctx context.Context, client redshiftAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		clusters []redshifttypes.Cluster
		marker   *string
	)
	for {
		out, err := client.DescribeClusters(ctx, &redshift.DescribeClustersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("collectRedshiftClusters: %w", err)
		}
		clusters = append(clusters, out.Clusters...)
		if out.Marker == nil || *out.Marker == "" {
			break
		}
		marker = out.Marker
	}

	logging := make([]string, len(clusters))
	eachBounded(ctx, len(clusters), redshiftCallTimeout, "redshift:DescribeLoggingStatus", func(ctx context.Context, i int) {
		out, err := client.DescribeLoggingStatus(ctx, &redshift.DescribeLoggingStatusInput{ClusterIdentifier: clusters[i].ClusterIdentifier})
		if err == nil && out != nil && out.LoggingEnabled != nil {
			logging[i] = strconv.FormatBool(*out.LoggingEnabled)
		}
	})

	requireSSL := redshiftRequireSSLByGroup(ctx, client, clusters)

	assets := make([]asset.Asset, 0, len(clusters))
	unreadLogging, unreadSSL := 0, 0
	for i, c := range clusters {
		meta := redshiftClusterFacts(c)
		if logging[i] != "" {
			meta["audit_logging_enabled"] = logging[i]
		} else {
			unreadLogging++
		}
		if v, ok := requireSSL[meta["parameter_group"]]; ok {
			meta["require_ssl"] = v
		} else {
			unreadSSL++
		}
		id := awssdk.ToString(c.ClusterIdentifier)
		assets = append(assets, asset.Asset{
			ID:           fmt.Sprintf("arn:%s:redshift:%s:%s:cluster:%s", partitionFor(region), region, accountID, id),
			Name:         id,
			Type:         "redshift_cluster",
			Provider:     asset.ProviderAWS,
			Region:       region,
			AccountID:    accountID,
			Endpoint:     meta["endpoint"],
			Metadata:     meta,
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	if unreadLogging > 0 {
		log.FromContext(ctx).Warn().Str("region", region).Int("clusters", len(clusters)).Int("unread", unreadLogging).
			Msg("redshift: DescribeLoggingStatus failed for some clusters (check redshift:DescribeLoggingStatus); their audit logging is unknown this sweep")
	}
	if unreadSSL > 0 {
		log.FromContext(ctx).Warn().Str("region", region).Int("clusters", len(clusters)).Int("unread", unreadSSL).
			Msg("redshift: require_ssl unread for some clusters (check redshift:DescribeClusterParameters); their TLS enforcement is unknown this sweep")
	}
	return assets, nil
}

// redshiftClusterFacts are the posture fields DescribeClusters returns. A
// pointer the response left nil leaves its key absent: the SDK zero value
// (false, 0) is not an observation.
func redshiftClusterFacts(c redshifttypes.Cluster) map[string]string {
	meta := map[string]string{}
	setBool := func(k string, v *bool) {
		if v != nil {
			meta[k] = strconv.FormatBool(*v)
		}
	}
	setBool("publicly_accessible", c.PubliclyAccessible)
	if awssdk.ToBool(c.PubliclyAccessible) {
		// Internet-resolvable but credential-gated: the possible tier, as for a
		// publicly accessible RDS instance.
		meta["public_access"] = asset.PublicAccessPossible
	}
	setBool("encrypted", c.Encrypted)
	setBool("allow_version_upgrade", c.AllowVersionUpgrade)
	setBool("enhanced_vpc_routing", c.EnhancedVpcRouting)
	if c.AutomatedSnapshotRetentionPeriod != nil {
		meta["automated_snapshot_retention"] = strconv.Itoa(int(*c.AutomatedSnapshotRetentionPeriod))
	}
	// MultiAZ is a string enum ("Enabled"/"Disabled"); anything else is not
	// a verdict.
	switch strings.ToLower(awssdk.ToString(c.MultiAZ)) {
	case "enabled":
		meta["multi_az"] = "true"
	case "disabled":
		meta["multi_az"] = "false"
	}
	// The administrator user NAME, never a credential: FSBP Redshift.8 fails
	// the console default awsuser.
	if u := awssdk.ToString(c.MasterUsername); u != "" {
		meta["master_username"] = u
	}
	if c.Endpoint != nil {
		meta["endpoint"] = awssdk.ToString(c.Endpoint.Address)
		if c.Endpoint.Port != nil {
			meta["port"] = strconv.Itoa(int(*c.Endpoint.Port))
		}
	}
	// A cluster has exactly one parameter group.
	if len(c.ClusterParameterGroups) > 0 {
		meta["parameter_group"] = awssdk.ToString(c.ClusterParameterGroups[0].ParameterGroupName)
	}
	// Same CSV shape ec2_instance / rds_instance use for security_groups.
	ids := make([]string, 0, len(c.VpcSecurityGroups))
	for _, g := range c.VpcSecurityGroups {
		if id := awssdk.ToString(g.VpcSecurityGroupId); id != "" {
			ids = append(ids, id)
		}
	}
	meta["security_groups"] = strings.Join(ids, ",")
	if v := awssdk.ToString(c.VpcId); v != "" {
		meta["vpc_id"] = v
	}
	return meta
}

// redshiftRequireSSLByGroup reads require_ssl once per distinct parameter
// group the clusters use. A group whose read failed, or whose listing carried
// no require_ssl value, is absent from the map (unknown). Every group —
// default.redshift-1.0 included — answers with an explicit value: AWS
// reports the engine default as the parameter's value (Source engine-default),
// historically "false" and "true" for default groups created since January
// 2025, so no default is assumed here.
func redshiftRequireSSLByGroup(ctx context.Context, client redshiftAPI, clusters []redshifttypes.Cluster) map[string]string {
	seen := map[string]bool{}
	var groups []string
	for _, c := range clusters {
		if len(c.ClusterParameterGroups) == 0 {
			continue
		}
		if g := awssdk.ToString(c.ClusterParameterGroups[0].ParameterGroupName); g != "" && !seen[g] {
			seen[g] = true
			groups = append(groups, g)
		}
	}
	values := make([]string, len(groups))
	eachBounded(ctx, len(groups), redshiftCallTimeout, "redshift:DescribeClusterParameters", func(ctx context.Context, i int) {
		v, err := redshiftParameterValue(ctx, client, groups[i], "require_ssl")
		if err == nil {
			values[i] = v
		}
	})
	out := map[string]string{}
	for i, g := range groups {
		if values[i] != "" {
			out[g] = values[i]
		}
	}
	return out
}

// redshiftParameterValue pages a parameter group to the named parameter and
// returns its value lowercased, "" when the group does not carry it. Any page
// error fails the read: a parameter that may sit on an unread page is unknown.
func redshiftParameterValue(ctx context.Context, client redshiftAPI, group, name string) (string, error) {
	var marker *string
	for {
		out, err := client.DescribeClusterParameters(ctx, &redshift.DescribeClusterParametersInput{
			ParameterGroupName: awssdk.String(group), Marker: marker,
		})
		if err != nil {
			return "", fmt.Errorf("redshiftParameterValue %s: %w", group, err)
		}
		for _, p := range out.Parameters {
			if awssdk.ToString(p.ParameterName) == name {
				return strings.ToLower(strings.TrimSpace(awssdk.ToString(p.ParameterValue))), nil
			}
		}
		if out.Marker == nil || *out.Marker == "" {
			return "", nil
		}
		marker = out.Marker
	}
}

// stampRedshiftPortWorldOpen joins each Redshift cluster to the security
// groups collected in the same sweep (FSBP Redshift.15): port_world_open is
// "true" when any attached group admits 0.0.0.0/0 or ::/0 on the cluster's
// port, "false" when every attached group was collected and none does, and
// absent when the port or any group is unknown — a group the sweep did not
// read, or whose ingress could not be parsed, could be the open one.
func stampRedshiftPortWorldOpen(assets []asset.Asset) {
	groups := map[string]asset.Asset{}
	for _, a := range assets {
		if a.Type == "security_group" && a.Provider == asset.ProviderAWS {
			groups[a.ID] = a
		}
	}
	for i := range assets {
		a := &assets[i]
		if a.Type != "redshift_cluster" || a.Metadata == nil {
			continue
		}
		port, err := strconv.ParseInt(a.Metadata["port"], 10, 32)
		groupsCSV, ok := a.Metadata["security_groups"]
		if err != nil || !ok {
			continue
		}
		var open []string
		known := true
		for _, g := range splitCSV(groupsCSV) {
			sg, collected := groups[g]
			if !collected {
				known = false
				continue
			}
			worldOpen, parsed := redshiftIngressWorldOpenOn(sg.Metadata, int32(port))
			if !parsed {
				known = false
				continue
			}
			if worldOpen {
				open = append(open, g)
			}
		}
		switch {
		case len(open) > 0:
			a.Metadata["port_world_open"] = "true"
			a.Metadata["world_open_security_groups"] = strings.Join(open, ",")
		case known:
			a.Metadata["port_world_open"] = "false"
		}
	}
}

// redshiftIngressWorldOpenOn reports whether a security group's serialized
// ingress (secgroups.go sgIngressRule JSON) admits the whole internet on
// port. parsed is false when the rules cannot be read: the ingress key is
// absent without an observed zero rule count (secgroups.go omits it only for
// a group with no rules), or its document does not parse.
func redshiftIngressWorldOpenOn(meta map[string]string, port int32) (open, parsed bool) {
	ingress, ok := meta["ingress"]
	if !ok {
		return false, meta["ingress_rules"] == "0"
	}
	var rules []sgIngressRule
	if err := json.Unmarshal([]byte(ingress), &rules); err != nil {
		return false, false
	}
	for _, r := range rules {
		portMatch := r.Protocol == "-1" || ((strings.EqualFold(r.Protocol, "tcp") || r.Protocol == "6") && r.FromPort <= port && port <= r.ToPort)
		if !portMatch {
			continue
		}
		for _, c := range r.CIDRs {
			if c == "0.0.0.0/0" || c == "::/0" {
				return true, true
			}
		}
	}
	return false, true
}
