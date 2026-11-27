package github

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type appAccount struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}
type appIdentity struct {
	ID       int64      `json:"id"`
	ClientID string     `json:"client_id"`
	Slug     string     `json:"slug"`
	Name     string     `json:"name"`
	Owner    appAccount `json:"owner"`
}
type appInstallation struct {
	SuspensionKnown bool              `json:"-"`
	ID              int64             `json:"id"`
	AppID           int64             `json:"app_id"`
	AppSlug         string            `json:"app_slug"`
	Account         appAccount        `json:"account"`
	Selection       string            `json:"repository_selection"`
	Permissions     map[string]string `json:"permissions"`
	SuspendedAt     *string           `json:"suspended_at"`
	// Coverage is our observation state, never an API-supplied field.
	Coverage   string   `json:"coverage,omitempty"`
	Members    []string `json:"observed_members,omitempty"`
	Membership string   `json:"membership_coverage,omitempty"`
}

// Missing suspension is not equivalent to an observed null suspended_at.
func (i *appInstallation) UnmarshalJSON(data []byte) error {
	type wire appInstallation
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("installation fields: %w", err)
	}
	var value wire
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("installation value: %w", err)
	}
	*i = appInstallation(value)
	_, i.SuspensionKnown = fields["suspended_at"]
	return nil
}

type appSnapshot struct {
	Apps          []appIdentity     `json:"apps"`
	Installations []appInstallation `json:"installations"`
	Coverage      string            `json:"coverage"`
}

type appInventory struct {
	Snapshot appSnapshot
	Assets   []asset.Asset
	Edges    []asset.Edge
	ID       string
}

func visibilityID(baseURL, kind, id string) string {
	return "github:" + strings.TrimRight(baseURL, "/") + ":" + kind + ":" + id
}

func (c *Collector) appGET(ctx context.Context, baseURL, token, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("app inventory request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	return c.doJSON(req, http.StatusOK, out)
}

// collectAppInventory never mints a token for another installation. The org
// listing reveals grants, but selected membership of other Apps stays unknown.
func (c *Collector) collectAppInventory(ctx context.Context, baseURL, jwtToken, token, installationID string, repos []repo, reposPartial bool, prior map[string]string) appInventory {
	out := appInventory{ID: visibilityID(baseURL, "inventory", installationID)}
	var previous appSnapshot
	_ = json.Unmarshal([]byte(prior["snapshot"]), &previous)
	var own appIdentity
	if c.appGET(ctx, baseURL, jwtToken, "/app", &own) != nil || own.ID == 0 {
		out.Snapshot.Apps = previous.Apps
	} else {
		out.Snapshot.Apps = []appIdentity{own}
	}
	installations, complete := c.listAppInstallations(ctx, baseURL, jwtToken, "/app/installations", false)
	if own.ID == 0 {
		complete = false
	}
	// Include old observations only when an authoritative source cannot replace
	// them. They remain unknown and must never prove a current path.
	byID := map[int64]appInstallation{}
	for _, i := range previous.Installations {
		i.Coverage = "unknown"
		i.Membership = "unknown"
		byID[i.ID] = i
	}
	if complete {
		for id, i := range byID {
			if i.AppID == own.ID {
				delete(byID, id)
			}
		}
	}
	for _, i := range installations {
		i.Coverage = "observed"
		for _, old := range previous.Installations {
			if old.ID == i.ID {
				i.Members = old.Members
				break
			}
		}
		byID[i.ID] = i
	}
	organizations := map[string]bool{}
	for _, i := range installations {
		if strconv.FormatInt(i.ID, 10) == installationID && i.Account.Type == "Organization" {
			organizations[i.Account.Login] = true
		}
	}
	for _, r := range repos {
		if r.Owner.Type == "Organization" {
			organizations[r.Owner.Login] = true
		}
	}
	for org := range organizations {
		rows, ok := c.listAppInstallations(ctx, baseURL, token, "/orgs/"+url.PathEscape(org)+"/installations", true)
		if !ok {
			complete = false
		} else {
			for id, i := range byID {
				if strings.EqualFold(i.Account.Login, org) {
					delete(byID, id)
				}
			}
		}
		for _, i := range rows {
			i.Coverage = "observed"
			for _, old := range previous.Installations {
				if old.ID == i.ID {
					i.Members = old.Members
					break
				}
			}
			byID[i.ID] = i
		}
	}
	// Fetch public App descriptions only for returned slugs. Failure does not
	// establish that the App is private. One call per distinct App, not repo.
	apps := map[int64]bool{}
	for _, a := range out.Snapshot.Apps {
		apps[a.ID] = true
	}
	for _, i := range byID {
		if apps[i.AppID] || i.AppSlug == "" {
			continue
		}
		apps[i.AppID] = true
		var a appIdentity
		if c.appGET(ctx, baseURL, token, "/apps/"+url.PathEscape(i.AppSlug), &a) == nil && a.ID == i.AppID {
			out.Snapshot.Apps = append(out.Snapshot.Apps, a)
		}
	}
	for _, i := range byID {
		i.Membership = "unknown"
		if i.Coverage == "observed" && strconv.FormatInt(i.ID, 10) == installationID {
			i.Membership = "complete"
			if reposPartial {
				i.Membership = "partial"
			}
			oldMembers := i.Members
			i.Members = nil
			for _, r := range repos {
				i.Members = append(i.Members, r.FullName)
			}
			if reposPartial {
				i.Members = append(i.Members, oldMembers...)
			}
			sort.Strings(i.Members)
			i.Members = uniqueStrings(i.Members)
		} else if i.Coverage == "observed" && i.Selection == "all" {
			// Known repository intersections, not a claim to enumerate all org repos.
			i.Membership = "observed_intersection"
			i.Members = nil
			for _, r := range repos {
				owner, _, _ := strings.Cut(r.FullName, "/")
				if strings.EqualFold(owner, i.Account.Login) {
					i.Members = append(i.Members, r.FullName)
				}
			}
		}
		sort.Strings(i.Members)
		out.Snapshot.Installations = append(out.Snapshot.Installations, i)
	}
	sort.Slice(out.Snapshot.Installations, func(i, j int) bool { return out.Snapshot.Installations[i].ID < out.Snapshot.Installations[j].ID })
	sort.Slice(out.Snapshot.Apps, func(i, j int) bool { return out.Snapshot.Apps[i].ID < out.Snapshot.Apps[j].ID })
	out.Snapshot.Coverage = "complete"
	if !complete || reposPartial {
		out.Snapshot.Coverage = "unknown"
	}
	out.project(baseURL)
	return out
}

func (c *Collector) listAppInstallations(ctx context.Context, baseURL, token, path string, wrapped bool) ([]appInstallation, bool) {
	var all []appInstallation
	expected := -1
	seen := map[int64]bool{}
	for page := 1; page <= maxPages; page++ {
		var rows []appInstallation
		endpoint := fmt.Sprintf("%s?per_page=%d&page=%d", path, perPage, page)
		if wrapped {
			var body struct {
				Installations *[]appInstallation `json:"installations"`
				TotalCount    *int               `json:"total_count"`
			}
			if c.appGET(ctx, baseURL, token, endpoint, &body) != nil || body.Installations == nil {
				return all, false
			}
			rows = *body.Installations
			if body.TotalCount != nil {
				if *body.TotalCount < 0 || (expected >= 0 && expected != *body.TotalCount) {
					return all, false
				}
				expected = *body.TotalCount
			}
		} else {
			if c.appGET(ctx, baseURL, token, endpoint, &rows) != nil || rows == nil {
				return all, false
			}
		}
		for _, i := range rows {
			if i.ID <= 0 || i.AppID <= 0 || i.Account.Login == "" || i.Permissions == nil || !i.SuspensionKnown || (i.Selection != "all" && i.Selection != "selected") || seen[i.ID] {
				return all, false
			}
			seen[i.ID] = true
			all = append(all, i)
		}
		if len(rows) < perPage {
			return all, expected < 0 || expected == len(all)
		}
	}
	return all, false
}

func (in *appInventory) project(baseURL string) {
	now := time.Now()
	identities := map[int64]appIdentity{}
	for _, a := range in.Snapshot.Apps {
		identities[a.ID] = a
	}
	for _, i := range in.Snapshot.Installations {
		if _, ok := identities[i.AppID]; !ok {
			identities[i.AppID] = appIdentity{ID: i.AppID, Slug: i.AppSlug}
		}
	}
	for _, a := range identities {
		meta := map[string]string{"app_id": strconv.FormatInt(a.ID, 10), "client_id": a.ClientID, "slug": a.Slug, "owner": a.Owner.Login, "app_visibility": "unknown"}
		in.Assets = append(in.Assets, visibilityAsset(visibilityID(baseURL, "app", meta["app_id"]), "github_app", a.Slug, meta, now))
	}
	for _, i := range in.Snapshot.Installations {
		id := visibilityID(baseURL, "installation", strconv.FormatInt(i.ID, 10))
		meta := map[string]string{"installation_id": strconv.FormatInt(i.ID, 10), "app_id": strconv.FormatInt(i.AppID, 10), "account": i.Account.Login, "repository_selection": i.Selection, "permissions": jsonString(i.Permissions), "coverage": i.Coverage, "membership_coverage": i.Membership, "suspended": "false"}
		if i.SuspendedAt != nil {
			meta["suspended"] = "true"
		}
		in.Assets = append(in.Assets, visibilityAsset(id, "github_app_installation", i.AppSlug+"@"+i.Account.Login, meta, now))
		in.Edges = append(in.Edges, visibilityEdge(visibilityID(baseURL, "app", meta["app_id"]), "github_app", id, "github_app_installation", "github_app_installation", "observed_grant", i.Coverage))
		// A separate versioned grant node preserves installation identity while a
		// permission/membership/suspension change retires the old grant topology.
		grant := installationGrantID(baseURL, i)
		in.Assets = append(in.Assets, visibilityAsset(grant, "github_app_grant", i.AppSlug+" grant", meta, now))
		in.Edges = append(in.Edges, visibilityEdge(id, "github_app_installation", grant, "github_app_grant", "github_installation_grant", "observed_grant", i.Coverage))
		if i.SuspendedAt != nil {
			continue
		}
		for _, r := range i.Members {
			in.Edges = append(in.Edges, visibilityEdge(grant, "github_app_grant", r, "github_repo", "github_grant_repository", "observed_grant", i.Membership))
		}
	}
	in.Assets = append(in.Assets, visibilityAsset(in.ID, "github_visibility_snapshot", "GitHub App coverage", map[string]string{"coverage": in.Snapshot.Coverage, "snapshot": jsonString(in.Snapshot)}, now))
}

func installationGrantID(baseURL string, i appInstallation) string {
	return visibilityID(baseURL, "grant", installationGrantKey(i))
}

func installationGrantKey(i appInstallation) string {
	// Observation coverage must not change the identity of a retained grant.
	i.Coverage = ""
	i.Membership = ""
	i.SuspensionKnown = false
	return strconv.FormatInt(i.ID, 10) + ":" + digest(jsonString(i))
}
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:12])
}
func jsonString(v any) string { b, _ := json.Marshal(v); return string(b) }
func visibilityAsset(id, typ, name string, meta map[string]string, now time.Time) asset.Asset {
	return asset.Asset{ID: id, Type: typ, Name: name, Provider: asset.ProviderGitHub, Region: "global", Metadata: meta, DiscoveredAt: now, LastSeen: now}
}
func visibilityEdge(src, srcType, dst, dstType, typ, evidence, coverage string) asset.Edge {
	return asset.Edge{SrcID: src, SrcType: srcType, DstID: dst, DstType: dstType, EdgeType: typ, Properties: map[string]string{"evidence": evidence, "coverage": coverage, "execution": "unverified"}}
}
func uniqueStrings(in []string) []string {
	out := in[:0]
	for _, s := range in {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}
