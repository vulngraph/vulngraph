package github

import (
	"context"
	"fmt"
	"net/http"
)

// ResolveInstallationID returns the GitHub App installation ID for an org by
// authenticating as the App (JWT) and calling GET /orgs/{org}/installation.
// Installation IDs are stable per app+org, so this is typically run once at
// bootstrap and the result stored on the connector — the collector itself only
// needs the stored installation_id.
//
// baseURL defaults to the public API when empty.
func ResolveInstallationID(ctx context.Context, baseURL, appID, privateKeyPEM, org string) (string, error) {
	if org == "" {
		return "", fmt.Errorf("ResolveInstallationID: org is required")
	}
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	jwtToken, err := appJWT(appID, privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("ResolveInstallationID: %w", err)
	}

	c := New()
	url := fmt.Sprintf("%s/orgs/%s/installation", baseURL, org)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("ResolveInstallationID: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	var body struct {
		ID int64 `json:"id"`
	}
	if err := c.doJSON(req, http.StatusOK, &body); err != nil {
		return "", fmt.Errorf("ResolveInstallationID: org %s: %w", org, err)
	}
	if body.ID == 0 {
		return "", fmt.Errorf("ResolveInstallationID: org %s: no installation found", org)
	}
	return fmt.Sprintf("%d", body.ID), nil
}
