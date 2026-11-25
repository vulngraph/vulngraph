package gcp

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	apikeys "google.golang.org/api/apikeys/v2"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// apiKeysAPI lists the project's API keys (API Keys API v2). The list
// response never carries the key string, and none is requested.
type apiKeysAPI interface {
	ListKeys(ctx context.Context, projectID string) ([]*apikeys.V2Key, error)
}

// wildcardReferrer matches the browser referrers CIS GCP 1.14 rejects as no
// restriction at all: "*", "*.<tld>" and "*.<tld>/*".
var wildcardReferrer = regexp.MustCompile(`^\*(\.[a-z]+)?(/\*)?$`)

// collectAPIKeys inventories API keys (CIS GCP 1.13-1.16): whether each is
// restricted to applications and to APIs, and its age.
func collectAPIKeys(ctx context.Context, client apiKeysAPI, projectID string, now time.Time) ([]asset.Asset, error) {
	keys, err := client.ListKeys(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("collectAPIKeys: %w", err)
	}
	var out []asset.Asset
	for _, k := range keys {
		if k == nil || k.Name == "" || k.DeleteTime != "" {
			continue
		}
		name := k.DisplayName
		if name == "" {
			name = lastSegment(k.Name)
		}
		out = append(out, asset.Asset{
			ID: k.Name, Name: name, Type: "gcp_api_key", Provider: asset.ProviderGCP, Region: "global",
			AccountID: projectID, Metadata: apiKeyMetadata(k, now), DiscoveredAt: now, LastSeen: now,
		})
	}
	return out, nil
}

func apiKeyMetadata(k *apikeys.V2Key, now time.Time) map[string]string {
	md := map[string]string{
		"app_restriction": appRestriction(k.Restrictions),
		"api_restricted":  strconv.FormatBool(apiRestricted(k.Restrictions)),
	}
	if t, err := time.Parse(time.RFC3339, k.CreateTime); err == nil {
		md["age_days"] = strconv.Itoa(daysSince(now, t))
	}
	return md
}

// appRestriction names the application restriction a key carries, or ""
// when it has none that restricts anything: no restriction, a wildcard
// referrer, or a server key admitting every address.
func appRestriction(r *apikeys.V2Restrictions) string {
	if r == nil {
		return ""
	}
	switch {
	case r.BrowserKeyRestrictions != nil:
		refs := r.BrowserKeyRestrictions.AllowedReferrers
		if len(refs) == 0 || slices.ContainsFunc(refs, func(s string) bool { return wildcardReferrer.MatchString(strings.ToLower(s)) }) {
			return ""
		}
		return "browser"
	case r.ServerKeyRestrictions != nil:
		ips := r.ServerKeyRestrictions.AllowedIps
		if len(ips) == 0 || slices.ContainsFunc(ips, func(s string) bool {
			return s == "0.0.0.0" || s == "0.0.0.0/0" || s == "::/0" || s == "::0"
		}) {
			return ""
		}
		return "server"
	case r.AndroidKeyRestrictions != nil && len(r.AndroidKeyRestrictions.AllowedApplications) > 0:
		return "android"
	case r.IosKeyRestrictions != nil && len(r.IosKeyRestrictions.AllowedBundleIds) > 0:
		return "ios"
	}
	return ""
}

// apiRestricted reports whether the key may call only named APIs. A target
// of cloudapis.googleapis.com admits every Google Cloud API.
func apiRestricted(r *apikeys.V2Restrictions) bool {
	if r == nil || len(r.ApiTargets) == 0 {
		return false
	}
	for _, t := range r.ApiTargets {
		if t == nil || t.Service == "" || t.Service == "cloudapis.googleapis.com" {
			return false
		}
	}
	return true
}

// newAPIKeysClient builds the real API Keys-backed apiKeysAPI via ADC.
func newAPIKeysClient(ctx context.Context) (apiKeysAPI, error) {
	svc, err := apikeys.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newAPIKeysClient: %w", err)
	}
	return &realAPIKeys{svc: svc}, nil
}

type realAPIKeys struct{ svc *apikeys.Service }

func (r *realAPIKeys) ListKeys(ctx context.Context, projectID string) ([]*apikeys.V2Key, error) {
	var out []*apikeys.V2Key
	if err := r.svc.Projects.Locations.Keys.List("projects/"+projectID+"/locations/global").
		Pages(ctx, func(p *apikeys.V2ListKeysResponse) error {
			out = append(out, p.Keys...)
			return nil
		}); err != nil {
		return nil, fmt.Errorf("ListKeys: %w", err)
	}
	return out, nil
}
