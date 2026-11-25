package github

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckBaseURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://ghes.corp.example/api/v3": true,
		"http://127.0.0.1:8080":            true,
		"http://localhost:8080":            true,
		"http://[::1]:8080":                true,
		"http://ghes.corp.example/api/v3":  false,
		"http://10.0.0.5/api/v3":           false,
		"ftp://ghes.corp.example":          false,
		"ghes.corp.example":                false,
		"https://":                         false,
	} {
		err := checkBaseURL(raw)
		if ok {
			require.NoError(t, err, raw)
		} else {
			require.Error(t, err, raw)
		}
	}
}

func TestCollect_RefusesPlainHTTPBaseURL(t *testing.T) {
	cfg := map[string]string{"app_id": "1", "installation_id": "2", "private_key_pem": "x", "base_url": "http://ghes.corp.example"}
	_, err := New().Collect(context.Background(), cfg)
	require.ErrorContains(t, err, "must use https")
}
