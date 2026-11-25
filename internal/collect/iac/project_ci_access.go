package iac

import (
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// ProjectDeclaredCIAccess turns resolved workflow intents from one repo into
// declared_ci_access assets. Unresolved intents are dropped here (kept only for
// parser-level coverage logging). Emits NO edges: the join to a live iam_role /
// gcp_service_account happens in the ci_access correlate rule (mirroring the
// DeploysTo collector-supplies, correlate-joins split).
func ProjectDeclaredCIAccess(decls []DeclaredCIAccess, repo string, now time.Time) []asset.Asset {
	assets := make([]asset.Asset, 0, len(decls))
	for _, d := range decls {
		if !d.Resolved {
			continue
		}
		target := d.TargetARN
		if target == "" {
			target = d.TargetSA
		}
		meta := map[string]string{
			"repo":          repo,
			"provider":      d.Provider,
			"workflow_path": d.WorkflowPath,
		}
		if d.TargetARN != "" {
			meta["target_arn"] = d.TargetARN
			meta["account_id"] = accountFromARN(d.TargetARN)
		}
		if d.TargetSA != "" {
			meta["target_sa"] = d.TargetSA
		}
		assets = append(assets, asset.Asset{
			ID:           "declared_ci_access:" + repo + ":" + d.WorkflowPath + ":" + target,
			Name:         target,
			Type:         "declared_ci_access",
			DiscoveredAt: now,
			LastSeen:     now,
			Metadata:     meta,
		})
	}
	return assets
}

// accountFromARN pulls the 12-digit account id out of arn:aws:iam::<acct>:role/…
func accountFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
