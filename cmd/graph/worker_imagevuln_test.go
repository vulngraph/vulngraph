package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/jobs"
)

// The pod's docker config is never presented to a registry unless the operator
// opts in: image refs come from connector data, and an ambient credential is
// whatever happens to be mounted.
func TestRegistryKeychain_DockerConfigIsOptIn(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"),
		[]byte(`{"auths":{"registry.example.com":{"auth":"dXNlcjpwYXNz"}}}`), 0o600))
	t.Setenv("DOCKER_CONFIG", dir)
	reg, err := name.NewRegistry("registry.example.com")
	require.NoError(t, err)

	resolve := func(env map[string]string) authn.AuthConfig {
		auth, err := authn.Resolve(t.Context(), registryKeychain(func(k string) string { return env[k] }, nil), reg)
		require.NoError(t, err)
		cfg, err := auth.Authorization()
		require.NoError(t, err)
		return *cfg
	}
	assert.Empty(t, resolve(nil).Username, "no opt-in: anonymous")
	assert.Equal(t, "user", resolve(map[string]string{"IMAGE_REGISTRY_DOCKER_KEYCHAIN": "true"}).Username)
}

func TestImageScanMaxStream(t *testing.T) {
	for raw, want := range map[string]int64{"": 0, "8": 8 << 30, " 16 ": 16 << 30} {
		got, err := imageScanMaxStream(func(string) string { return raw })
		require.NoError(t, err, raw)
		assert.Equal(t, want, got, raw)
	}
	for _, bad := range []string{"0", "-1", "4GiB", "1.5"} {
		_, err := imageScanMaxStream(func(string) string { return bad })
		require.Error(t, err, bad)
	}
}

// An allow list that would open the metadata range stops the worker rather
// than quietly scanning with a weaker guard.
func TestImageVulnSource_InvalidAllowListStopsTheWorker(t *testing.T) {
	env := map[string]string{"IMAGE_REGISTRY_ALLOW_PRIVATE": "10.0.0.0/8, 0.0.0.0/0"}
	getenv := func(k string) string { return env[k] }
	feeds, err := jobs.FeedsFromEnv(getenv)
	require.NoError(t, err)
	_, err = imageVulnSource(t.Context(), getenv, feeds, nil)
	require.ErrorContains(t, err, "IMAGE_REGISTRY_ALLOW_PRIVATE")

	env["IMAGE_REGISTRY_ALLOW_PRIVATE"] = "10.20.0.0/16"
	scanner, err := imageVulnSource(t.Context(), getenv, feeds, nil)
	require.NoError(t, err)
	require.NotNil(t, scanner)
}
