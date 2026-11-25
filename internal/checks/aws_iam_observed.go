package checks

import (
	"maps"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// Unknown organization or permission evidence cannot make a silent privilege
// check a clean observation. Removing the tier lets the existing probes ask
// whether independent facts, such as recent use, still prove the check clean.
func awsIAMObservedMetadata(a asset.Asset) asset.Asset {
	if a.Provider != asset.ProviderAWS || (a.Type != "iam_role" && a.Type != "iam_user") {
		return a
	}
	if a.Metadata["organization_policy_complete"] == "true" && a.Metadata["privilege_tier"] != "unknown" {
		return a
	}
	a.Metadata = maps.Clone(a.Metadata)
	if a.Metadata["organization_policy_complete"] != "true" {
		delete(a.Metadata, "organization_policy_complete")
	}
	delete(a.Metadata, "privilege_tier")
	delete(a.Metadata, "privilege_tier_source")
	return a
}
