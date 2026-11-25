package aws

import (
	"context"
	"strconv"
)

// withPermissionBoundary retains an unread restriction as typed evidence. It
// preserves candidate grants, but prevents missing evidence from proving admin.
func withPermissionBoundary(ctx context.Context, cache *managedPolicyCache, policies []policyDoc, meta map[string]string, arn string, observed bool) []policyDoc {
	if observed && arn == "" {
		meta["permission_boundary_complete"] = "true"
		return policies
	}
	p := policyDoc{Name: "permission-boundary", Type: "boundary", Incomplete: true}
	if arn != "" {
		meta["permission_boundary_arn"] = arn
		p.Name, p.Managed = policyNameFromARN(arn), true
		if doc, ok := cache.document(ctx, arn); ok && doc != "" {
			p.Document, p.Incomplete = doc, false
		}
	}
	meta["permission_boundary_complete"] = strconv.FormatBool(!p.Incomplete)
	return append(policies, p)
}
