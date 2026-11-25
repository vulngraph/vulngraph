package enrich

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// SSOInfo is the resolved SSO grounding for an IAM role that is an SSO
// (AWSReservedSSO_*) permission-set role.
type SSOInfo struct {
	PermissionSet string
	GrantsAdmin   bool
}

// SSOResolver answers whether an IAM role is an SSO permission-set role and, if
// its permission set is present in the graph, whether that permission set grants
// admin. It replaces the naming-substring heuristic with the SSO graph:
// an SSO permission set that grants admin is a real admin path, so SSO gating
// must NOT neutralize a privilege-escalation finding on it.
type SSOResolver interface {
	// ResolveRole reports the role's SSO grounding and whether it was resolved
	// (the role is an SSO role AND its permission set was found in the graph).
	// A non-SSO role, or an SSO role whose permission set is absent (collector
	// stale), returns ok=false so callers fall back to metadata behaviour.
	ResolveRole(ctx context.Context, role asset.Asset) (SSOInfo, bool)
}

// SSOPermSetLister lists sso_permission_set assets. asset.Service implements it.
type SSOPermSetLister interface {
	ListByType(ctx context.Context, assetType string, limit int) ([]asset.Asset, error)
}

const ssoPermSetListLimit = 5000

// AssetSSOResolver resolves SSO permission sets from the graph via a periodic,
// process-cached listing. Permission sets number in the dozens and change
// rarely, so a short TTL keeps the per-finding path off ClickHouse without
// serving stale grants for long.
type AssetSSOResolver struct {
	Lister SSOPermSetLister
	TTL    time.Duration
	Now    func() time.Time

	mu       sync.Mutex
	byName   map[string]bool // lowercased permission-set name → grants_admin
	loadedAt time.Time
}

// ResolveRole implements SSOResolver.
func (r *AssetSSOResolver) ResolveRole(ctx context.Context, role asset.Asset) (SSOInfo, bool) {
	name, isSSO := ssoPermSetName(role)
	if !isSSO {
		return SSOInfo{}, false
	}
	grantsAdmin, found := r.lookup(ctx, name)
	if !found {
		return SSOInfo{}, false // permission set not in the graph — fall back to metadata
	}
	return SSOInfo{PermissionSet: name, GrantsAdmin: grantsAdmin}, true
}

func (r *AssetSSOResolver) lookup(ctx context.Context, permSetName string) (grantsAdmin, found bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	ttl := r.TTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if r.byName == nil || now().Sub(r.loadedAt) > ttl {
		sets, err := r.Lister.ListByType(ctx, "sso_permission_set", ssoPermSetListLimit)
		if err != nil {
			// Keep any prior cache on a transient error; if none, report unresolved.
			if r.byName == nil {
				return false, false
			}
		} else {
			m := make(map[string]bool, len(sets))
			for _, s := range sets {
				// Key by the permission-set name: nodes are keyed by ARN with
				// Name set.
				if s.Name != "" {
					m[strings.ToLower(s.Name)] = s.Metadata["grants_admin"] == "true"
				}
			}
			r.byName = m
			r.loadedAt = now()
		}
	}
	grantsAdmin, found = r.byName[strings.ToLower(permSetName)]
	return grantsAdmin, found
}

// ssoPermSetName derives an SSO role's permission-set name from the AWS-managed
// AWSReservedSSO_<PermissionSetName>_<16-hex-role-id> naming (the role also lives
// under the /aws-reserved/sso.amazonaws.com/ path). Returns ok=false for a
// non-SSO role.
func ssoPermSetName(role asset.Asset) (string, bool) {
	name := role.Name
	if name == "" {
		name = roleNameFromID(role.ID)
	}
	path := strings.ToLower(role.Metadata["path"])
	isSSO := strings.HasPrefix(strings.ToLower(name), "awsreservedsso_") ||
		strings.Contains(path, "aws-reserved/sso")
	if !isSSO {
		return "", false
	}
	// Strip the "AWSReservedSSO_" prefix (case-insensitively) and the trailing
	// "_<hex>" role-id suffix.
	trimmed := name
	if i := strings.Index(strings.ToLower(trimmed), "awsreservedsso_"); i >= 0 {
		trimmed = trimmed[i+len("awsreservedsso_"):]
	}
	if j := strings.LastIndex(trimmed, "_"); j >= 0 && isHex(trimmed[j+1:]) {
		trimmed = trimmed[:j]
	}
	if trimmed == "" {
		return "", false
	}
	return trimmed, true
}

// roleNameFromID returns the trailing name segment of an IAM role ARN.
func roleNameFromID(id string) string {
	if i := strings.LastIndex(id, "/"); i >= 0 && i+1 < len(id) {
		return id[i+1:]
	}
	return id
}

// isHex reports whether s is a non-empty run of hex digits (the SSO role-id suffix).
func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
