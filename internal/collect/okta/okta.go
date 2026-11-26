// Package okta collects human identities from an Okta org. Each active user
// becomes an Asset of type "human_identity" with provider "okta", each group
// becomes an "sso_group", and group memberships become member_of edges
// (user → group). These nodes are the foundation of the unified identity graph:
// correlators link them to cloud IAM roles via FederatedAccess and to repos via
// Owns, and the group nodes hang off the AWS Identity Center sso_group nodes so
// the chain human → IdP group → SSO group → permission set → account resolves.
//
// The platform demotes privilege-escalation findings whose entry path is
// SSO-gated, on the rationale that entry is "gated by the IdP (Okta/MFA)" — a
// claim that requires actually observing MFA state, not assuming it. Factor
// enrollment is therefore collected as a first-class output here, and stays
// ABSENT, never "false", whenever it could not be read.
package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/pkg/log"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

const (
	httpTimeout = 30 * time.Second
	pageLimit   = 200

	// ssoGroupPrefix is the node-ID convention AWS Identity Center
	// (collect/aws/identitycenter.go) uses for an SSO group. Okta deliberately
	// does NOT write those nodes — a second producer of the same ID with a
	// different Provider would flip the field on every sweep and churn
	// asset_change_log — it links to them instead, by SCIM-synced display name.
	ssoGroupPrefix = "sso_group:"
)

// maxPages bounds every paginated Okta list in this package at 10,000 items
// (pageLimit * maxPages) — generous, but a hard ceiling: an org larger than
// that fails explicitly. OKTA_MAX_PAGES overrides.
var maxPages = envIntOr("OKTA_MAX_PAGES", 50)

func envIntOr(key string, fallback int) int {
	if n, err := strconv.Atoi(os.Getenv(key)); err == nil && n > 0 {
		return n
	}
	return fallback
}

// Collector implements collect.Collector for Okta.
// Config keys: "domain" (e.g. "dev-123.okta.com"), "api_token" (SSWS token).
type Collector struct {
	client *http.Client
}

func New() *Collector {
	// safenet.New (SSRF-blocking) — never NewInternal: the Okta domain is
	// connector-supplied, so a malicious connector
	// could point requests at an internal host. New still reaches the public
	// Okta tenant while blocking private/link-local ranges at dial time.
	return &Collector{client: safenet.New(httpTimeout)}
}

func (c *Collector) Collect(ctx context.Context, cfg map[string]string) (collect.Result, error) {
	domain := cfg["domain"]
	token := cfg["api_token"]
	if domain == "" || token == "" {
		return collect.Result{}, fmt.Errorf("okta: domain and api_token are required")
	}
	domain, err := orgURL(domain)
	if err != nil {
		return collect.Result{}, fmt.Errorf("okta.Collect: %w", err)
	}

	users, err := c.listUsers(ctx, domain, token)
	if err != nil {
		return collect.Result{}, fmt.Errorf("okta.Collect: %w", err)
	}

	groups, err := c.listGroups(ctx, domain, token)
	if err != nil {
		return collect.Result{}, fmt.Errorf("okta.Collect: list groups: %w", err)
	}

	// MFA factor enrollment, one call per user, bounded fan-out. Users whose
	// lookup failed are absent from the map and get NO mfa_enabled key.
	userIDs := make([]string, 0, len(users))
	for _, u := range users {
		userIDs = append(userIDs, u.ID)
	}
	factors, factorFailures := c.userFactors(ctx, domain, token, userIDs)

	// Org enrollment + sign-on policy, resolved per group. Unusable unless every
	// listing succeeded.
	policy, policyKnown := c.readOrgMFAPolicy(ctx, domain, token)

	partial := factorFailures > 0 || !policyKnown
	if partial {
		log.FromContext(ctx).Warn().
			Int("factor_failures", factorFailures).
			Int("users", len(users)).
			Bool("policy_known", policyKnown).
			Msg("okta: MFA state incomplete — affected identities carry no MFA claim")
	}

	now := time.Now()
	assets := make([]asset.Asset, 0, len(users)+len(groups))
	var edges []asset.Edge

	// Group membership edges. A failed member listing makes the sweep partial:
	// silently continuing would drop the memberships of a whole group while
	// still reporting a complete result, which lets deletion reconciliation
	// resolve findings on evidence that was never fetched.
	for _, grp := range groups {
		members, err := c.groupMembers(ctx, domain, token, grp.ID)
		if err != nil {
			partial = true
			log.FromContext(ctx).Warn().Err(err).Str("group", grp.ID).
				Msg("okta: group membership unreadable — memberships omitted this sweep")
			continue
		}
		for _, uid := range members {
			edges = append(edges, asset.Edge{
				SrcID:    "okta:" + uid,
				SrcType:  "human_identity",
				DstID:    groupID(grp.ID),
				DstType:  "sso_group",
				EdgeType: "member_of",
				Properties: map[string]string{
					"group_name": grp.Profile.Name,
					"provenance": "okta",
				},
			})
		}
	}

	for _, grp := range groups {
		a, e := groupNode(grp, policy, policyKnown, now)
		assets = append(assets, a)
		edges = append(edges, e...)
	}

	for _, u := range users {
		assets = append(assets, userNode(u, factors, now))
	}

	return collect.Result{Assets: assets, Edges: edges, Partial: partial}, nil
}

// groupID is the node ID for an Okta group. It is namespaced to okta rather than
// reusing "sso_group:<name>": the AWS collectors own that ID, and a second
// producer writing it with Provider "okta" would rewrite the provider on every
// sweep. The join to the AWS node is an edge, not a shared row.
func groupID(oktaGroupID string) string { return "okta:group:" + oktaGroupID }

// groupNode builds the group asset and its link into the AWS SSO group of the
// same name — the join that puts a person on the other end of otherwise-orphaned
// sso_group and sso_permission_set nodes.
//
// The name match is the SCIM convention: Identity Center groups are provisioned
// FROM Okta, so DisplayName equals the Okta group profile name. It is a
// heuristic, recorded as one in the edge's basis property. Where no AWS group of
// that name exists the edge simply has no destination node and is dropped at
// graph load, which costs nothing.
func groupNode(grp oktaGroup, policy orgMFAPolicy, policyKnown bool, now time.Time) (asset.Asset, []asset.Edge) {
	name := grp.Profile.Name
	if name == "" {
		name = grp.ID
	}
	meta := map[string]string{
		"okta_id":         grp.ID,
		"identity_kind":   "group",
		"okta_group_name": name,
		"source":          "okta",
	}
	// Policy keys are published ONLY on a complete policy read. A partial read
	// answers "is there an MFA gap for this group?" in the reassuring direction,
	// which is the exact failure this connector exists to prevent.
	if policyKnown {
		meta["mfa_enroll_required"] = boolStr(policy.enrollRequiredFor(grp.ID))
		meta["single_factor_access_allowed"] = boolStr(policy.singleFactorFor(grp.ID))
	}

	a := asset.Asset{
		ID:           groupID(grp.ID),
		Name:         name,
		Type:         "sso_group",
		Provider:     "okta",
		Region:       "global",
		Metadata:     meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}

	if grp.Profile.Name == "" {
		return a, nil
	}
	return a, []asset.Edge{{
		SrcID:    a.ID,
		SrcType:  "sso_group",
		DstID:    ssoGroupPrefix + grp.Profile.Name,
		DstType:  "sso_group",
		EdgeType: "member_of",
		Properties: map[string]string{
			"provenance": "okta",
			"basis":      "scim_display_name",
		},
	}}
}

// userNode builds one human_identity asset. The MFA keys appear only for a user
// whose factor listing succeeded — see factorState's doc comment for why absence
// must never be rendered as "false".
func userNode(u oktaUser, factors map[string]factorState, now time.Time) asset.Asset {
	meta := map[string]string{
		"okta_id": u.ID,
		"login":   u.Profile.Login,
		"status":  u.Status,
		// credential_provider is the PASSWORD provider (OKTA / ACTIVE_DIRECTORY /
		// LDAP / FEDERATION). It must not feed mfa_enabled, because it is wrong in
		// both directions there: an AD-sourced user with no second factor would
		// read as MFA-protected and an Okta-sourced user with two enrolled factors
		// as unprotected. It answers a different question — where the password
		// lives, not whether a second factor exists.
		"credential_provider": u.Credentials.Provider.Type,
		"last_login":          u.LastLogin,
		"identity_kind":       "user",
		"first_name":          u.Profile.FirstName,
		"last_name":           u.Profile.LastName,
	}
	if st, ok := factors[u.ID]; ok {
		meta["mfa_enabled"] = boolStr(st.enrolled())
		meta["mfa_active_factor_count"] = strconv.Itoa(len(st.ActiveTypes))
		if len(st.ActiveTypes) > 0 {
			meta["mfa_factor_types"] = strings.Join(st.ActiveTypes, ",")
		}
	}

	return asset.Asset{
		ID:       "okta:" + u.ID,
		Name:     u.Profile.Email,
		Type:     "human_identity",
		Provider: "okta",
		Region:   "global",
		Domain:   u.Profile.Email,
		Tags: map[string]string{
			"department": u.Profile.Department,
			"title":      u.Profile.Title,
			"status":     u.Status,
		},
		Metadata:     meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// listUsers fetches all active Okta users, paging via Link headers.
func (c *Collector) listUsers(ctx context.Context, domain, token string) ([]oktaUser, error) {
	pageURL := fmt.Sprintf("%s/api/v1/users?limit=%d&filter=status+eq+%q", domain, pageLimit, "ACTIVE")
	var all []oktaUser
	for page := 0; page < maxPages; page++ {
		var batch []oktaUser
		next, err := c.doJSON(ctx, pageURL, token, &batch)
		if err != nil {
			return nil, fmt.Errorf("listUsers page %d: %w", page, err)
		}
		all = append(all, batch...)
		if next == "" {
			return all, nil
		}
		pageURL = next
	}
	return nil, fmt.Errorf("listUsers: page limit %d reached with more data unread", maxPages)
}

type oktaGroup struct {
	ID      string `json:"id"`
	Profile struct {
		Name string `json:"name"`
	} `json:"profile"`
}

func (c *Collector) listGroups(ctx context.Context, domain, token string) ([]oktaGroup, error) {
	pageURL := fmt.Sprintf("%s/api/v1/groups?limit=%d", domain, pageLimit)
	var all []oktaGroup
	for page := 0; page < maxPages; page++ {
		var batch []oktaGroup
		next, err := c.doJSON(ctx, pageURL, token, &batch)
		if err != nil {
			return nil, fmt.Errorf("listGroups page %d: %w", page, err)
		}
		all = append(all, batch...)
		if next == "" {
			return all, nil
		}
		pageURL = next
	}
	return nil, fmt.Errorf("listGroups: page limit %d reached with more data unread", maxPages)
}

// groupMembers returns the user IDs of all members of a group.
func (c *Collector) groupMembers(ctx context.Context, domain, token, gid string) ([]string, error) {
	pageURL := fmt.Sprintf("%s/api/v1/groups/%s/users?limit=%d", domain, gid, pageLimit)
	var ids []string
	for page := 0; page < maxPages; page++ {
		var batch []struct {
			ID string `json:"id"`
		}
		next, err := c.doJSON(ctx, pageURL, token, &batch)
		if err != nil {
			return nil, err
		}
		for _, u := range batch {
			ids = append(ids, u.ID)
		}
		if next == "" {
			return ids, nil
		}
		pageURL = next
	}
	return nil, fmt.Errorf("groupMembers: page limit %d reached with more data unread", maxPages)
}

// orgURL turns the configured domain ("dev-123.okta.com" or a full URL) into
// the org's origin. The SSWS token rides every request, so plain http is
// refused except to a loopback host (local testing).
func orgURL(domain string) (string, error) {
	if !strings.Contains(domain, "://") {
		domain = "https://" + domain
	}
	u, err := url.Parse(domain)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("okta: invalid domain %q", domain)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && isLoopback(u.Hostname()):
	default:
		return "", fmt.Errorf("okta: domain %q must use https", domain)
	}
	return strings.TrimRight(domain, "/"), nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// sameOrigin reports whether next has the scheme and host of base. A Link
// header names the next page, and following it to another host would hand
// that host the SSWS token.
func sameOrigin(base *url.URL, next string) bool {
	u, err := url.Parse(next)
	return err == nil && u.Scheme == base.Scheme && strings.EqualFold(u.Host, base.Host)
}

// doJSON sends a GET request with SSWS auth, decodes into out, and returns the
// next-page URL from the Link header (empty when no next page).
func (c *Collector) doJSON(ctx context.Context, pageURL, token string, out any) (nextURL string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return "", fmt.Errorf("doJSON: build request: %w", err)
	}
	req.Header.Set("Authorization", "SSWS "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("doJSON: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("%w: okta returned %d", collect.ErrPermanent, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("doJSON: unexpected status %d for %s", resp.StatusCode, pageURL)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return "", fmt.Errorf("doJSON: decode: %w", err)
	}

	// Okta pagination: Link: <url>; rel="next"
	for _, link := range resp.Header["Link"] {
		for _, part := range strings.Split(link, ",") {
			part = strings.TrimSpace(part)
			if strings.HasSuffix(part, `rel="next"`) {
				u := strings.TrimSpace(strings.Split(part, ";")[0])
				u = strings.Trim(u, "<>")
				// An error, not an early stop: a truncated listing would
				// read as the whole org.
				if !sameOrigin(req.URL, u) {
					return "", fmt.Errorf("doJSON: next page %q is not on the Okta org origin", u)
				}
				return u, nil
			}
		}
	}
	return "", nil
}

type oktaUser struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	LastLogin string `json:"lastLogin"`
	Profile   struct {
		Login      string `json:"login"`
		Email      string `json:"email"`
		FirstName  string `json:"firstName"`
		LastName   string `json:"lastName"`
		Department string `json:"department"`
		Title      string `json:"title"`
	} `json:"profile"`
	Credentials struct {
		Provider struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"provider"`
	} `json:"credentials"`
}
