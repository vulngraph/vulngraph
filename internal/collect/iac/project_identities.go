package iac

import (
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// ProjectDeclaredIdentities turns identities harvested from one repo file into
// declared_cloud_identity assets. Emits NO edges: the join to the live
// iam_role / iam_user / gcp_service_account happens in the declared_identity
// correlate rule, mirroring the collector-supplies / correlate-joins split every
// other IaC slice uses.
//
// The asset ID includes the path so two files naming the same role each keep
// their own evidence row — "which file grants this" is the question the ownership
// edge is for.
func ProjectDeclaredIdentities(ids []DeclaredIdentity, repo, path string, now time.Time) []asset.Asset {
	assets := make([]asset.Asset, 0, len(ids))
	for _, d := range ids {
		assets = append(assets, asset.Asset{
			ID:           "declared_cloud_identity:" + repo + ":" + path + ":" + d.Value,
			Name:         d.Raw,
			Type:         "declared_cloud_identity",
			DiscoveredAt: now,
			LastSeen:     now,
			Metadata: map[string]string{
				"repo":  repo,
				"path":  path,
				"kind":  d.Kind,
				"value": d.Value,
			},
		})
	}
	return assets
}
