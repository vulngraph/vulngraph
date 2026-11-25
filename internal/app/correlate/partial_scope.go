package correlate

import "github.com/vulngraph/vulngraph/internal/app/asset"

// NeedsRecompute reports whether asset id could have changed THIS run: always
// true for a full sweep (changedIDs nil, which must stay exhaustive), true
// for a partial only if id itself is in the changed set. Safe on its own only
// for a rule with no OTHER independently-changing side — see
// OtherSideUnchanged for one that matches against a second accessor.
func (g Graph) NeedsRecompute(id string) bool {
	return g.changedIDs == nil || g.changedIDs[id]
}

// NeedsPermissionRecompute is NeedsRecompute plus the SCP exception: an SCP
// caps every principal in its account, not just the aws_scp_set asset itself,
// so an account whose SCP changed needs every principal in it recomputed too.
func (g Graph) NeedsPermissionRecompute(p asset.Asset) bool {
	return g.NeedsRecompute(p.ID) || g.changedSCPAccounts[p.AccountID]
}

// OtherSideUnchanged reports whether it is safe to skip an asset not itself
// in the changed set. A rule matching one accessor's static content (a role's
// trust policy) against a SECOND, independently-changing accessor (repos,
// secrets, human identities) must NOT skip the first side's unchanged members
// when the second side changed — a brand-new repo/secret can still match an
// existing, untouched role, and skipping it would silently drop that edge.
// Always false for a full sweep, where nothing should be skipped anyway.
func (g Graph) OtherSideUnchanged(otherSideTypes ...string) bool {
	if g.changedIDs == nil {
		return false
	}
	for _, t := range otherSideTypes {
		if g.changedTypes[t] {
			return false
		}
	}
	return true
}
