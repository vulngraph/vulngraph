package aws

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

type eksAPI interface {
	ListClusters(context.Context, *eks.ListClustersInput, ...func(*eks.Options)) (*eks.ListClustersOutput, error)
	DescribeCluster(context.Context, *eks.DescribeClusterInput, ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
}

// collectEKS lists the region's EKS clusters and their managed node groups.
// Regional service. partial is true when a listed cluster could not be
// emitted (see collectEKSClusters); nodegroupsPartial when a cluster's node
// groups could not be listed — the clusters themselves are still complete.
func collectEKS(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) (assets []asset.Asset, partial, nodegroupsPartial bool, err error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, false, false, fmt.Errorf("collectEKS: %w", err)
	}
	client := eks.NewFromConfig(awsCfg)
	clusters, partial, err := collectEKSClusters(ctx, client, region, accountID, now)
	if err != nil {
		return nil, false, false, err
	}
	nodegroups, nodegroupsPartial := collectEKSNodegroups(ctx, client, clusters, region, accountID, now)
	return append(clusters, nodegroups...), partial, nodegroupsPartial, nil
}

// collectEKSClusters returns the region's clusters. partial reports a listed
// cluster that could not be emitted because it has no usable ID: no ARN came
// back AND the account is unknown, so the documented ARN cannot be built. An
// asset with an empty ID would collide with every other such cluster, so it is
// dropped — and the drop flags the sweep partial, or the missing cluster would
// read as deleted.
func collectEKSClusters(ctx context.Context, client eksAPI, region, accountID string, now time.Time) ([]asset.Asset, bool, error) {
	var (
		assets  []asset.Asset
		next    *string
		partial bool
	)
	for {
		lo, err := client.ListClusters(ctx, &eks.ListClustersInput{NextToken: next})
		if err != nil {
			return nil, false, fmt.Errorf("collectEKSClusters: %w", err)
		}
		for _, name := range lo.Clusters {
			d, err := client.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: awssdk.String(name)})
			if err != nil || d == nil || d.Cluster == nil {
				// ListClusters already OBSERVED that this cluster exists. Dropping it
				// because the describe failed would make a throttle or a transient 5xx
				// look like a deletion to sync's reconciliation, silently erasing a
				// live cluster from inventory. Emit what we observed — the name — with
				// every describe-derived key omitted (omitted = unknown).
				id := eksClusterARN(region, accountID, name)
				if id == "" {
					log.FromContext(ctx).Warn().Err(err).
						Str("cluster", name).Str("region", region).
						Msg("eks describe cluster failed and the account is unknown; cluster omitted, sweep flagged partial")
					partial = true
					continue
				}
				log.FromContext(ctx).Warn().Err(err).
					Str("cluster", name).Str("region", region).
					Msg("eks describe cluster skipped; emitting name-only asset")
				assets = append(assets, asset.Asset{
					ID:           id,
					Name:         name,
					Type:         "eks_cluster",
					Provider:     asset.ProviderAWS,
					Region:       region,
					AccountID:    accountID,
					Metadata:     map[string]string{"describe_failed": "true"},
					DiscoveredAt: now,
					LastSeen:     now,
				})
				continue
			}
			a := eksClusterAsset(d.Cluster, name, region, accountID, now)
			if a.ID == "" {
				log.FromContext(ctx).Warn().Str("cluster", name).Str("region", region).
					Msg("eks cluster has no ARN and the account is unknown; cluster omitted, sweep flagged partial")
				partial = true
				continue
			}
			assets = append(assets, a)
		}
		if lo.NextToken == nil {
			return assets, partial, nil
		}
		next = lo.NextToken
	}
}

// eksClusterAsset maps a described EKS cluster onto an asset. Every key is
// emitted only when the API actually reported the underlying field: an absent
// key means "not observed", never "false" or "none".
func eksClusterAsset(c *ekstypes.Cluster, name, region, accountID string, now time.Time) asset.Asset {
	meta := map[string]string{}
	if v := awssdk.ToString(c.Version); v != "" {
		meta["version"] = v
	}
	if v := awssdk.ToString(c.PlatformVersion); v != "" {
		meta["platform_version"] = v
	}
	// Status separates "cluster has no workload inventory because collection is
	// blind" from "cluster is being torn down" — the reconciliation signal must
	// not page on a DELETING cluster.
	if c.Status != "" {
		meta["status"] = string(c.Status)
	}

	// The OIDC issuer is the join key to IRSA. An IAM role that trusts this
	// cluster carries the provider ARN verbatim in its `federated_provider`
	// metadata, so we emit that exact string alongside the raw issuer URL —
	// the correlator gets a string equality, not a parse.
	if c.Identity != nil && c.Identity.Oidc != nil {
		if issuer := awssdk.ToString(c.Identity.Oidc.Issuer); issuer != "" {
			meta["oidc_issuer"] = issuer
			if arn := oidcProviderARN(region, accountID, issuer); arn != "" {
				meta["oidc_provider_arn"] = arn
			}
		}
	}

	if vpc := c.ResourcesVpcConfig; vpc != nil {
		meta["endpoint_public_access"] = fmt.Sprintf("%t", vpc.EndpointPublicAccess)
		meta["endpoint_private_access"] = fmt.Sprintf("%t", vpc.EndpointPrivateAccess)
		if len(vpc.PublicAccessCidrs) > 0 {
			meta["public_access_cidrs"] = strings.Join(vpc.PublicAccessCidrs, ",")
		}
		// A public API server endpoint whose allowlist is the whole internet is
		// the `possible` tier (a kubeconfig credential is still required),
		// matching the GKE collector's convention. When the endpoint is public
		// but the CIDR list came back empty the allowlist is UNKNOWN, so
		// public_access is omitted rather than guessed either way.
		if vpc.EndpointPublicAccess && anyOpenCIDR(vpc.PublicAccessCidrs) {
			meta["public_access"] = asset.PublicAccessPossible
		}
	}

	// Authentication mode decides whether cluster authorization lives in EKS
	// access entries, the aws-auth ConfigMap, or both — i.e. which of the two
	// IAM-principal-to-Kubernetes-group paths can even be read.
	if ac := c.AccessConfig; ac != nil {
		if ac.AuthenticationMode != "" {
			meta["authentication_mode"] = string(ac.AuthenticationMode)
		}
		if ac.BootstrapClusterCreatorAdminPermissions != nil {
			meta["bootstrap_cluster_creator_admin"] = fmt.Sprintf("%t", *ac.BootstrapClusterCreatorAdminPermissions)
		}
	}

	// EncryptionConfig is simply absent from a described cluster that has no
	// envelope encryption, so a described cluster always answers this.
	meta["secrets_encryption"] = strconv.FormatBool(eksSecretsEncrypted(c.EncryptionConfig))
	// Logging is a struct the API returns on every described cluster; when it
	// is missing the control-plane log setting was not observed.
	if c.Logging != nil {
		meta["audit_logging"] = strconv.FormatBool(eksLogTypeEnabled(c.Logging, ekstypes.LogTypeAudit))
		// CIS EKS 2.1.1 wants all five control-plane log types; "" is the
		// observed state of every type shipping.
		meta["logging_disabled_types"] = strings.Join(eksDisabledLogTypes(c.Logging), ",")
	}

	id := awssdk.ToString(c.Arn)
	if id == "" {
		id = eksClusterARN(region, accountID, name)
	}
	return asset.Asset{
		ID:           id,
		Name:         name,
		Type:         "eks_cluster",
		Provider:     asset.ProviderAWS,
		Region:       region,
		AccountID:    accountID,
		Endpoint:     awssdk.ToString(c.Endpoint),
		Metadata:     meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}
}

// eksClusterARN builds the documented EKS cluster ARN from values we already
// observed. Returns "" when the account is unknown, so we never mint an ID
// containing a placeholder.
func eksClusterARN(region, accountID, name string) string {
	if region == "" || accountID == "" || name == "" {
		return ""
	}
	return fmt.Sprintf("arn:%s:eks:%s:%s:cluster/%s", partitionFor(region), region, accountID, name)
}

// oidcProviderARN converts an EKS OIDC issuer URL into the IAM OIDC provider ARN
// that a trusting role's `federated_provider` metadata holds verbatim:
//
//	https://oidc.eks.eu-west-1.amazonaws.com/id/ABC
//	arn:aws:iam::111:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/ABC
//
// The IAM provider is a separate resource that may not exist; this is the ARN it
// WOULD have, which is exactly what makes it the join key. Returns "" when the
// account is unknown.
func oidcProviderARN(region, accountID, issuer string) string {
	host := strings.TrimPrefix(strings.TrimPrefix(issuer, "https://"), "http://")
	host = strings.TrimSuffix(host, "/")
	if accountID == "" || host == "" {
		return ""
	}
	return fmt.Sprintf("arn:%s:iam::%s:oidc-provider/%s", partitionFor(region), accountID, host)
}

// anyOpenCIDR reports whether an allowlist entry covers the entire internet.
func anyOpenCIDR(cidrs []string) bool {
	for _, c := range cidrs {
		switch strings.TrimSpace(c) {
		case "0.0.0.0/0", "::/0":
			return true
		}
	}
	return false
}

// eksSecretsEncrypted reports whether a KMS key envelope-encrypts the
// cluster's Kubernetes secrets.
func eksSecretsEncrypted(cfgs []ekstypes.EncryptionConfig) bool {
	for _, ec := range cfgs {
		if ec.Provider == nil || awssdk.ToString(ec.Provider.KeyArn) == "" {
			continue
		}
		if slices.Contains(ec.Resources, "secrets") {
			return true
		}
	}
	return false
}

// eksLogTypeEnabled reports whether a control-plane log type is shipped.
// eksDisabledLogTypes lists the control-plane log types (api, audit,
// authenticator, controllerManager, scheduler) the cluster does not ship.
func eksDisabledLogTypes(l *ekstypes.Logging) []string {
	var out []string
	for _, t := range ekstypes.LogType("").Values() {
		if !eksLogTypeEnabled(l, t) {
			out = append(out, string(t))
		}
	}
	return out
}

func eksLogTypeEnabled(l *ekstypes.Logging, want ekstypes.LogType) bool {
	for _, setup := range l.ClusterLogging {
		if awssdk.ToBool(setup.Enabled) && slices.Contains(setup.Types, want) {
			return true
		}
	}
	return false
}
