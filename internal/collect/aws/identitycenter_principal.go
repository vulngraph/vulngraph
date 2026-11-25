package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	identitystoretypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	ssoadmintypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
)

// principalResolver maps Identity Center principal GUIDs to human labels
// ("user:alice", "group:platform-admins"), caching each unique principal so a
// group assigned across many permission sets/accounts costs ONE identity-store
// call rather than hundreds — per-assignment lookups throw enough
// DescribeGroup/DescribeUser calls at identitystore to get throttled, and every
// name then silently falls back to its GUID. It records the first failure and a
// fallback count so the caller can log WHY resolution failed instead of the
// collector swallowing it.
type principalResolver struct {
	ids        identityStoreAPI
	storeID    string
	cache      map[string]string
	userEmails map[string]string
	// groupIDs maps a resolved group label ("group:platform-admins") back to its
	// identity-store GUID, which is what ListGroupMemberships needs. Without
	// keeping the GUID the resolved display name is a dead end and the people
	// inside the group stay uncollected.
	groupIDs map[string]string
	resolved int
	fails    int
	firstErr error
}

func newPrincipalResolver(ids identityStoreAPI, storeID string) *principalResolver {
	return &principalResolver{
		ids: ids, storeID: storeID,
		cache:      map[string]string{},
		userEmails: map[string]string{},
		groupIDs:   map[string]string{},
	}
}

// groupMemberIDs lists the user GUIDs in one group. Best-effort: a failure is
// recorded on the resolver (so the caller's WARN line explains an empty result)
// rather than returned, because one inaccessible group must not lose the rest.
func (r *principalResolver) groupMemberIDs(ctx context.Context, groupID string) []string {
	if groupID == "" {
		return nil
	}
	var out []string
	var token *string
	for {
		page, err := r.ids.ListGroupMemberships(ctx, &identitystore.ListGroupMembershipsInput{
			IdentityStoreId: &r.storeID, GroupId: &groupID, NextToken: token,
		})
		if err != nil {
			r.note(fmt.Errorf("ListGroupMemberships %s: %w", groupID, err))
			return out
		}
		for _, m := range page.GroupMemberships {
			// MemberId is a union; only the UserId member exists today, and a
			// nested-group member (if AWS ever adds one) is not a person.
			if u, ok := m.MemberId.(*identitystoretypes.MemberIdMemberUserId); ok && u != nil && u.Value != "" {
				out = append(out, u.Value)
			}
		}
		if page.NextToken == nil || *page.NextToken == "" {
			return out
		}
		token = page.NextToken
	}
}

func (r *principalResolver) resolve(ctx context.Context, ptype ssoadmintypes.PrincipalType, principalID string) string {
	if principalID == "" {
		return ""
	}
	if v, ok := r.cache[principalID]; ok {
		return v
	}
	label := r.lookup(ctx, ptype, principalID)
	r.cache[principalID] = label
	return label
}

// primaryEmail picks the email to key a resolved user's human_identity node
// on: the address flagged Primary, or the first one if none is, or "" if the
// user has none set in Identity Center.
func primaryEmail(emails []identitystoretypes.Email) string {
	var first string
	for _, e := range emails {
		v := awssdk.ToString(e.Value)
		if v == "" {
			continue
		}
		if e.Primary {
			return v
		}
		if first == "" {
			first = v
		}
	}
	return first
}

func (r *principalResolver) note(err error) {
	r.fails++
	if r.firstErr == nil {
		r.firstErr = err
	}
}

func (r *principalResolver) lookup(ctx context.Context, ptype ssoadmintypes.PrincipalType, principalID string) string {
	switch ptype {
	case ssoadmintypes.PrincipalTypeUser:
		u, err := r.ids.DescribeUser(ctx, &identitystore.DescribeUserInput{
			IdentityStoreId: &r.storeID, UserId: &principalID,
		})
		if err != nil {
			r.note(fmt.Errorf("DescribeUser %s: %w", principalID, err))
			return "user:" + principalID
		}
		if n := awssdk.ToString(u.UserName); n != "" {
			r.resolved++
			label := "user:" + n
			if email := primaryEmail(u.Emails); email != "" {
				r.userEmails[label] = email
			}
			return label
		}
		r.note(fmt.Errorf("DescribeUser %s: empty UserName", principalID))
		return "user:" + principalID
	case ssoadmintypes.PrincipalTypeGroup:
		g, err := r.ids.DescribeGroup(ctx, &identitystore.DescribeGroupInput{
			IdentityStoreId: &r.storeID, GroupId: &principalID,
		})
		if err != nil {
			r.note(fmt.Errorf("DescribeGroup %s: %w", principalID, err))
			return "group:" + principalID
		}
		if n := awssdk.ToString(g.DisplayName); n != "" {
			r.resolved++
			label := "group:" + n
			// Keep the GUID: it is the only handle ListGroupMemberships accepts,
			// and the members are the federated humans.
			r.groupIDs[label] = principalID
			return label
		}
		r.note(fmt.Errorf("DescribeGroup %s: empty DisplayName", principalID))
		return "group:" + principalID
	default:
		return principalID
	}
}
