package imagevuln

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var catalogueNow = time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)

func TestRuntimeOf(t *testing.T) {
	tests := []struct {
		name  string
		purls []string
		want  Runtime
	}{
		{"python app on debian", []string{"pkg:deb/debian/openssl@3.0.11-1", "pkg:pypi/requests@2.31.0", "pkg:pypi/flask@3.0.0"}, RuntimePython},
		{"node app", []string{"pkg:apk/alpine/musl@1.2.5-r0", "pkg:npm/express@4.19.2"}, RuntimeNode},
		{"java app", []string{"pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"}, RuntimeJava},
		{"ruby app", []string{"pkg:gem/rails@7.1.0"}, RuntimeRuby},
		{"go binary alone is static", []string{"pkg:golang/github.com/spf13/cobra@v1.8.0"}, RuntimeStatic},
		{"rust binary alone is static", []string{"pkg:cargo/serde@1.0.0"}, RuntimeStatic},
		{"a go helper beside python is still python", []string{"pkg:golang/x@v1", "pkg:pypi/requests@2"}, RuntimePython},
		{"two interpreters: generic glibc", []string{"pkg:pypi/requests@2", "pkg:npm/express@4"}, RuntimeGlibc},
		{"OS packages only: native code", []string{"pkg:deb/debian/nginx@1.22.1-9"}, RuntimeGlibc},
		{"nothing", nil, RuntimeGlibc},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, RuntimeOf(tt.purls), tt.name)
	}
}

func TestRecommend_DefaultCatalogue(t *testing.T) {
	recs := DefaultCatalogue().Recommend(RuntimePython, "Debian:11", catalogueNow)
	var images []string
	for _, r := range recs {
		images = append(images, r.Image)
		require.NotEmpty(t, r.Reason)
	}
	require.Equal(t, []string{
		"gcr.io/distroless/python3-debian13",
		"cgr.dev/chainguard/python",
		"ubuntu/python:3.12-24.04_stable",
		"debian:13-slim", // newest supported Debian, from the lifecycle table
		"alpine:3.24",    // newest supported Alpine branch
	}, images)

	// An image already on the newest release of its family gets no same-family
	// proposal, and an Alpine image is not told to move to Alpine.
	recs = DefaultCatalogue().Recommend(RuntimeStatic, "Alpine:v3.24", catalogueNow)
	for _, r := range recs {
		require.NotContains(t, r.Image, "alpine:", "already on the newest Alpine")
	}
	require.Equal(t, "gcr.io/distroless/static-debian13", recs[0].Image)

	// An unknown OS still gets the runtime proposals, and nothing derived from it.
	recs = DefaultCatalogue().Recommend(RuntimeGlibc, "", catalogueNow)
	require.Equal(t, "gcr.io/distroless/base-debian13", recs[0].Image)
	require.Equal(t, "Ubuntu Chiseled", recs[2].Name)
	require.Empty(t, recs[2].Image, "a recipe, not a FROM reference")
	require.NotEmpty(t, recs[2].Note)
}

func TestRecommend_SameFamilyImages(t *testing.T) {
	tests := map[string]string{
		"Ubuntu:20.04:LTS": "ubuntu:26.04",
		"Red Hat:8":        "registry.access.redhat.com/ubi10/ubi-minimal",
		"Amazon Linux:2":   "amazonlinux:2023",
		"CentOS:7":         "quay.io/centos/centos:stream10",
		"SUSE:15.5":        "registry.suse.com/bci/bci-minimal:15.7",
		"Alpine:v3.18":     "alpine:3.24",
	}
	for baseOS, want := range tests {
		r, ok := sameFamilyUpgrade(baseOS, catalogueNow)
		require.True(t, ok, baseOS)
		require.Equal(t, want, r.Image, baseOS)
	}
	_, ok := sameFamilyUpgrade("Debian:13", catalogueNow)
	require.False(t, ok, "already on the newest Debian")
}

func writeCatalogue(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "catalogue.json")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

// An operator's own bases are proposed first; with replace_defaults they are
// the only catalogue proposals. No vendor is privileged by the code.
func TestLoadCatalogue_OperatorEntriesLead(t *testing.T) {
	p := writeCatalogue(t, `{"entries": [
		{"name": "Docker Hardened Images", "image": "dhi.io/python:3.13", "runtime": "python"},
		{"name": "Golden base", "image": "registry.internal/golden/base:2026.10", "runtime": "any"}
	]}`)
	c, err := LoadCatalogue(p)
	require.NoError(t, err)
	recs := c.Recommend(RuntimePython, "Debian:12", catalogueNow)
	require.Equal(t, "dhi.io/python:3.13", recs[0].Image)
	require.Equal(t, "registry.internal/golden/base:2026.10", recs[1].Image)
	require.Equal(t, "gcr.io/distroless/python3-debian13", recs[2].Image, "defaults follow")

	p = writeCatalogue(t, `{"replace_defaults": true, "entries": [
		{"name": "WizOS", "image": "registry.example/wizos/python:3.13", "runtime": "python"}
	]}`)
	c, err = LoadCatalogue(p)
	require.NoError(t, err)
	recs = c.Recommend(RuntimePython, "Debian:12", catalogueNow)
	require.Equal(t, "registry.example/wizos/python:3.13", recs[0].Image)
	for _, r := range recs[1:] {
		require.NotContains(t, r.Image, "distroless", "defaults dropped")
	}
}

func TestLoadCatalogue_Errors(t *testing.T) {
	c, err := LoadCatalogue("")
	require.NoError(t, err)
	require.Equal(t, DefaultCatalogue(), c, "no file configured: the defaults")

	_, err = LoadCatalogue(filepath.Join(t.TempDir(), "missing.json"))
	require.Error(t, err, "a configured file that is missing is an error, not the defaults")

	for name, body := range map[string]string{
		"not json":           `{`,
		"no name":            `{"entries": [{"image": "x", "runtime": "python"}]}`,
		"bad runtime":        `{"entries": [{"name": "x", "image": "x", "runtime": "cobol"}]}`,
		"no image nor note":  `{"entries": [{"name": "x", "runtime": "python"}]}`,
		"image with spaces":  `{"entries": [{"name": "x", "image": "a b", "runtime": "python"}]}`,
		"replaces with none": `{"replace_defaults": true, "entries": []}`,
	} {
		_, err := LoadCatalogue(writeCatalogue(t, body))
		require.ErrorIs(t, err, ErrBadCatalogue, name)
	}
}

func TestFromPatch(t *testing.T) {
	require.Equal(t,
		"acme/api — final stage of the image's Dockerfile (the image is declared in deploy/values.yaml):\n-FROM debian:11-slim\n+FROM gcr.io/distroless/base-debian13",
		FromPatch("acme/api", "deploy/values.yaml", "debian:11-slim", "Debian:11", "gcr.io/distroless/base-debian13"))
	require.Equal(t,
		"acme/api — final stage of the image's Dockerfile:\n-FROM <current Debian:11 base>\n+FROM debian:13-slim",
		FromPatch("acme/api", "", "", "Debian:11", "debian:13-slim"))
}
