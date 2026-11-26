// Package google collects human identities from Google Workspace via the Admin
// SDK Directory API. Each user becomes an Asset of type "human_identity" with
// provider "google". Auth uses a service account with domain-wide delegation:
// the SA impersonates the delegated admin to read the user directory.
package google

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

const (
	adminScope      = "https://www.googleapis.com/auth/admin.directory.user.readonly"
	directoryAPIURL = "https://admin.googleapis.com/admin/directory/v1/users"
	tokenURL        = "https://oauth2.googleapis.com/token"
	httpTimeout     = 30 * time.Second
	maxResults      = 500
)

// maxPages bounds the paginated Workspace user list at 10,000 users
// (maxResults * maxPages) — generous, but a hard ceiling: a domain larger
// than that fails explicitly. GOOGLE_MAX_PAGES overrides.
var maxPages = envIntOr("GOOGLE_MAX_PAGES", 20)

func envIntOr(key string, fallback int) int {
	if n, err := strconv.Atoi(os.Getenv(key)); err == nil && n > 0 {
		return n
	}
	return fallback
}

// Collector implements collect.Collector for Google Workspace.
// Config keys:
//   - "service_account_json": base64-encoded service account key JSON
//   - "admin_email": the delegated admin whose identity is impersonated
type Collector struct {
	client *http.Client
}

func New() *Collector {
	// safenet.New (SSRF-blocking) — never NewInternal: the OAuth2 token_uri is
	// parsed from connector-supplied service-account JSON, so a malicious
	// connector could point it at an internal/metadata host and exfiltrate the
	// signed domain-wide-delegation assertion. New still reaches public Google
	// endpoints while blocking private/link-local ranges at dial time.
	return &Collector{client: safenet.New(httpTimeout)}
}

func (c *Collector) Collect(ctx context.Context, cfg map[string]string) (collect.Result, error) {
	saJSON := cfg["service_account_json"]
	adminEmail := cfg["admin_email"]
	if saJSON == "" || adminEmail == "" {
		return collect.Result{}, fmt.Errorf("google: service_account_json and admin_email are required")
	}

	saBytes, err := base64.StdEncoding.DecodeString(saJSON)
	if err != nil {
		// Try raw JSON in case it wasn't base64-encoded.
		saBytes = []byte(saJSON)
	}

	token, err := c.serviceAccountToken(ctx, saBytes, adminEmail)
	if err != nil {
		return collect.Result{}, fmt.Errorf("google.Collect: get token: %w", err)
	}

	users, err := c.listUsers(ctx, token)
	if err != nil {
		return collect.Result{}, fmt.Errorf("google.Collect: %w", err)
	}

	now := time.Now()
	assets := make([]asset.Asset, 0, len(users))
	for _, u := range users {
		suspended := "false"
		if u.Suspended {
			suspended = "true"
		}
		isAdmin := "false"
		if u.IsAdmin {
			isAdmin = "true"
		}
		md := userMetadata(u, suspended, isAdmin)
		assets = append(assets, asset.Asset{
			ID:       "google:" + u.PrimaryEmail,
			Name:     u.PrimaryEmail,
			Type:     "human_identity",
			Provider: "google",
			Region:   "global",
			Domain:   u.PrimaryEmail,
			Tags: map[string]string{
				"org_unit": u.OrgUnitPath,
				"is_admin": isAdmin,
			},
			Metadata:     md,
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}

	return collect.Result{Assets: assets}, nil
}

// userMetadata maps one directory user. The 2-Step Verification keys (CIS
// GCP 1.3) are written only when the response carried the field.
func userMetadata(u wsUser, suspended, isAdmin string) map[string]string {
	md := map[string]string{
		"google_id":  u.ID,
		"full_name":  u.Name.FullName,
		"last_login": u.LastLoginTime,
		"suspended":  suspended,
		"is_admin":   isAdmin,
		"org_unit":   u.OrgUnitPath,
	}
	if u.IsEnrolledIn2Sv != nil {
		md["two_step_enrolled"] = strconv.FormatBool(*u.IsEnrolledIn2Sv)
	}
	if u.IsEnforcedIn2Sv != nil {
		md["two_step_enforced"] = strconv.FormatBool(*u.IsEnforcedIn2Sv)
	}
	return md
}

// listUsers fetches all users from the Workspace directory, paging via nextPageToken.
func (c *Collector) listUsers(ctx context.Context, bearerToken string) ([]wsUser, error) {
	var all []wsUser
	pageToken := ""
	for page := 0; page < maxPages; page++ {
		params := url.Values{}
		params.Set("customer", "my_customer")
		params.Set("maxResults", fmt.Sprintf("%d", maxResults))
		params.Set("orderBy", "email")
		if pageToken != "" {
			params.Set("pageToken", pageToken)
		}
		apiURL := directoryAPIURL + "?" + params.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			return nil, fmt.Errorf("listUsers: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+bearerToken)

		resp, err := c.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("listUsers: %w", err)
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("listUsers: read: %w", readErr)
		}

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf("%w: google returned %d: %s", collect.ErrPermanent, resp.StatusCode, string(body))
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("listUsers: unexpected status %d: %s", resp.StatusCode, string(body))
		}

		var page struct {
			Users         []wsUser `json:"users"`
			NextPageToken string   `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("listUsers: decode: %w", err)
		}
		all = append(all, page.Users...)
		if page.NextPageToken == "" {
			return all, nil
		}
		pageToken = page.NextPageToken
	}
	return nil, fmt.Errorf("listUsers: page limit %d reached with more users unread", maxPages)
}

// serviceAccountToken exchanges a service account key for an OAuth2 access
// token with domain-wide delegation — impersonating adminEmail.
func (c *Collector) serviceAccountToken(ctx context.Context, saKeyJSON []byte, adminEmail string) (string, error) {
	var key struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	}
	if err := json.Unmarshal(saKeyJSON, &key); err != nil {
		return "", fmt.Errorf("serviceAccountToken: parse key: %w", err)
	}
	if key.ClientEmail == "" || key.PrivateKey == "" {
		return "", fmt.Errorf("serviceAccountToken: invalid service account JSON")
	}
	tURI := key.TokenURI
	if tURI == "" {
		tURI = tokenURL
	}

	// Build JWT assertion for OAuth2 service account flow.
	now := time.Now().Unix()
	claimSet := map[string]any{
		"iss":   key.ClientEmail,
		"sub":   adminEmail, // domain-wide delegation: impersonate this admin
		"scope": adminScope,
		"aud":   tURI,
		"iat":   now,
		"exp":   now + 3600,
	}
	assertion, err := signJWT(claimSet, key.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("serviceAccountToken: sign JWT: %w", err)
	}

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth2:grant-type:jwt-bearer")
	data.Set("assertion", assertion)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tURI, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("serviceAccountToken: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("serviceAccountToken: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("serviceAccountToken: decode: %w", err)
	}
	if tok.Error != "" {
		return "", fmt.Errorf("%w: token exchange: %s", collect.ErrPermanent, tok.Error)
	}
	return tok.AccessToken, nil
}

// signJWT creates a signed RS256 JWT for the service account OAuth2 flow using
// only the standard library — no external JWT dependency needed.
func signJWT(claims map[string]any, privateKeyPEM string) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := header + "." + payload

	sig, err := rsaSign([]byte(signingInput), privateKeyPEM)
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

type wsUser struct {
	ID            string `json:"id"`
	PrimaryEmail  string `json:"primaryEmail"`
	OrgUnitPath   string `json:"orgUnitPath"`
	LastLoginTime string `json:"lastLoginTime"`
	IsAdmin       bool   `json:"isAdmin"`
	Suspended     bool   `json:"suspended"`
	// 2-Step Verification state. Pointers: a response without the field is
	// unknown, never "not enrolled".
	IsEnrolledIn2Sv *bool `json:"isEnrolledIn2Sv"`
	IsEnforcedIn2Sv *bool `json:"isEnforcedIn2Sv"`
	Name            struct {
		FullName string `json:"fullName"`
	} `json:"name"`
}
