package iac

import (
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// ProjectDeclaredTF turns Terraform-state resources that were address-confirmed
// against a repo's .tf (the caller already filtered resources down to those
// whose Address is declared in the repo — see tfstate_ingest.go) into
// declared_tf_resource assets. Emits NO edges: the join to a live asset
// (iam_role by ARN, others by id) happens in the tf_ownership correlate rule,
// mirroring the DeploysTo / CI-access collector-supplies, correlate-joins split.
//
// Only address/arn/id ever flow through here — ParseTFState already guarantees
// a StateResource carries nothing else, so there is no secret-leak surface in
// this function to guard.
func ProjectDeclaredTF(resources []StateResource, repo string, now time.Time) []asset.Asset {
	assets := make([]asset.Asset, 0, len(resources))
	for _, r := range resources {
		target := r.ARN
		if target == "" {
			target = r.ID
		}
		if target == "" {
			// Neither arn nor id present in state — nothing to join a live asset
			// on, so the resource carries no correlation value.
			continue
		}
		meta := map[string]string{
			"repo":    repo,
			"address": r.Address,
		}
		if r.ARN != "" {
			meta["target_arn"] = r.ARN
			meta["account_id"] = accountFromARN(r.ARN)
		} else {
			meta["target_id"] = r.ID
		}
		assets = append(assets, asset.Asset{
			ID:           "declared_tf_resource:" + repo + ":" + r.Address,
			Name:         r.Address,
			Type:         "declared_tf_resource",
			DiscoveredAt: now,
			LastSeen:     now,
			Metadata:     meta,
		})
	}
	return assets
}
