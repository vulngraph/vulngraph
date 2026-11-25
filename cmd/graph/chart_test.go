package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const chartDir = "../../deploy/helm-chart/graph/"

// chartValues decodes the chart's default values.yaml.
func chartValues(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(chartDir + "values.yaml")
	require.NoError(t, err)
	var v map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &v))
	return v
}

// helmDefine returns the body of one named template in _helpers.tpl: up to the
// {{- end -}} that a blank line, the next comment or the next define follows.
func helmDefine(t *testing.T, name string) string {
	t.Helper()
	helpers, err := os.ReadFile(chartDir + "templates/_helpers.tpl")
	require.NoError(t, err)
	body := regexp.MustCompile(`(?s)\{\{- define "` + regexp.QuoteMeta(name) + `" -\}\}(.*?)\n\{\{- end -\}\}\n(?:\n|\{\{/\*|\{\{- define|\z)`).FindSubmatch(helpers)
	require.NotNil(t, body, "%s not found", name)
	return string(body[1])
}

// The worker is the only process that calls the Kubernetes API (it alone
// builds the collector registry), so the chart's Kubernetes RBAC is bound to
// the worker's ServiceAccount alone and serve mounts no API token, even when
// it shares that ServiceAccount.
func TestOnlyTheWorkerHoldsKubernetesAPIAccess(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "worker.go" || f == "collect_registry.go" {
			continue
		}
		src, err := os.ReadFile(f)
		require.NoError(t, err)
		require.NotContains(t, string(src), "newCollectRegistry(",
			"%s builds the collector registry; the chart binds the Kubernetes RBAC to the worker only", f)
	}

	subjects := helmDefine(t, "graph.workerServiceAccountSubjects")
	require.Contains(t, subjects, ".Values.serviceAccount.name")
	require.NotContains(t, subjects, "serveName")
	require.NotContains(t, subjects, "scanner")
	for _, f := range []string{"kubernetes-collector-rbac.yaml", "policy-engine-rbac.yaml", "node-posture.yaml"} {
		body, err := os.ReadFile(chartDir + "templates/" + f)
		require.NoError(t, err)
		require.Contains(t, string(body), `include "graph.workerServiceAccountSubjects"`, f)
		require.Equal(t, 1, strings.Count(string(body), "subjects:"), "%s binds a subject list other than the worker's", f)
	}

	serve, err := os.ReadFile(chartDir + "templates/deployment-serve.yaml")
	require.NoError(t, err)
	require.Contains(t, string(serve), "automountServiceAccountToken: false")
}

// image.digest pins every graph container to one image: the reference is
// built in one helper, and no template spells repository:tag itself.
func TestChartImageHonoursDigest(t *testing.T) {
	image := helmDefine(t, "graph.image")
	require.Contains(t, image, "@{{ . }}", "graph.image must render repository@digest when image.digest is set")
	require.Contains(t, image, "regexMatch", "a malformed digest must fail the render")

	templates, err := filepath.Glob(chartDir + "templates/*.yaml")
	require.NoError(t, err)
	uses := 0
	for _, f := range templates {
		body, err := os.ReadFile(f)
		require.NoError(t, err)
		require.NotContains(t, string(body), "Values.image.repository", "%s builds the graph image reference itself, bypassing image.digest", f)
		uses += strings.Count(string(body), `include "graph.image"`)
	}
	require.Equal(t, 5, uses, "serve, migrate, worker, scanner and node-posture each run the graph image")

	img, ok := chartValues(t)["image"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, img, "digest")
	require.Equal(t, "", img["digest"], "the default pulls by tag")
}

// image.pullPolicy reaches every graph container, init containers included:
// with pullPolicy Always on a moving tag, a migrate init container left on the
// IfNotPresent default runs a node's cached build while serve pulls the new one,
// so new serve code starts on an unmigrated schema.
func TestEveryGraphContainerFollowsPullPolicy(t *testing.T) {
	followed := regexp.MustCompile(`image: \{\{ include "graph\.image" [^}]*\}\}\n\s+imagePullPolicy: \{\{ \$?[a-z]*\.Values\.image\.pullPolicy \}\}\n`)
	templates, err := filepath.Glob(chartDir + "templates/*.yaml")
	require.NoError(t, err)
	uses := 0
	for _, f := range templates {
		body, err := os.ReadFile(f)
		require.NoError(t, err)
		n := strings.Count(string(body), `include "graph.image"`)
		uses += n
		require.Lenf(t, followed.FindAllString(string(body), -1), n,
			"every graph container in %s must set imagePullPolicy from image.pullPolicy right after its image", f)
	}
	require.NotZero(t, uses)
}

// With image.tag empty every graph container pulls the chart's appVersion, so
// appVersion must name a release: X.Y.Z, the image tag release.yaml pushes for
// the vX.Y.Z tag it refuses under any other appVersion. Never "edge", the
// rolling main-branch build that moves under a running install.
func TestChartDefaultImageTagIsPublished(t *testing.T) {
	raw, err := os.ReadFile(chartDir + "Chart.yaml")
	require.NoError(t, err)
	var chart struct {
		AppVersion string `yaml:"appVersion"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &chart))
	require.Regexp(t, `^[0-9]+\.[0-9]+\.[0-9]+$`, chart.AppVersion,
		"appVersion %q is not a release the workflow publishes", chart.AppVersion)

	img, ok := chartValues(t)["image"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "", img["tag"], "the default tag follows appVersion")
	require.Contains(t, helmDefine(t, "graph.image"), "default .Chart.AppVersion")
}

// The bundled DSNs say which transport they use: sslmode is explicit, and the
// modes that need a server certificate (and ClickHouse's secure port) refuse
// to render without one rather than producing a DSN every connection fails on.
func TestChartDatastoreDSNsDeclareTransport(t *testing.T) {
	body, err := os.ReadFile(chartDir + "templates/secret.yaml")
	require.NoError(t, err)
	tpl := string(body)
	require.Equal(t, 2, strings.Count(tpl, "@graph-postgres:5432/graph?sslmode=%s%s"), "the app DSN and the scanner DSN both carry the sslmode")
	require.Contains(t, tpl, "&sslrootcert=/etc/graph/postgres-ca/ca.crt", "the verify modes need the CA the chart mounts")
	require.Contains(t, tpl, "(not .Values.postgres.tlsSecret)")
	require.Contains(t, tpl, "@graph-clickhouse:9440/graph?secure=true")
	mount := helmDefine(t, "graph.dbCAVolume")
	require.Contains(t, mount, "items: [{ key: ca.crt, path: ca.crt }]", "only the CA reaches the graph pods, never the server key")
	for _, f := range []string{"deployment-serve.yaml", "deployment-worker.yaml", "deployment-scanner.yaml"} {
		body, err := os.ReadFile(chartDir + "templates/" + f)
		require.NoError(t, err)
		require.Equal(t, strings.Count(string(body), `include "graph.tmpVolumeMount"`), strings.Count(string(body), `include "graph.dbCAVolumeMount"`),
			"%s: every graph container that reads the DSN needs the CA its sslrootcert names", f)
	}
	require.Contains(t, tpl, "{{- if not .Values.clickhouse.tlsSecret }}")

	v := chartValues(t)
	pg, ok := v["postgres"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "prefer", pg["sslMode"])
	require.Equal(t, "", pg["tlsSecret"])
	ch, ok := v["clickhouse"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, false, ch["secure"])
	require.Equal(t, "", ch["tlsSecret"])
}

// REQUIRE_ADMIN_TOTP, TLS_PROXY and OIDC_REQUIRED_GROUPS are first-class chart
// values, off by default, so hardening an install does not need extraEnv. The
// CI helm job renders them; this pins the defaults and the env names serve
// reads.
func TestChartAuthHardeningValues(t *testing.T) {
	config := chartValues(t)["config"].(map[string]any)
	require.Equal(t, false, config["requireAdminTotp"])
	require.Equal(t, false, config["tlsProxy"])
	require.Equal(t, "", config["oidcRequiredGroups"])

	serve, err := os.ReadFile(chartDir + "templates/deployment-serve.yaml")
	require.NoError(t, err)
	require.Regexp(t, `(?s)if \.Values\.config\.requireAdminTotp \}\}.*?- name: REQUIRE_ADMIN_TOTP\n  value: "true"`, string(serve))
	require.Regexp(t, `if \.Values\.config\.tlsProxy \}\}\n(?:#[^\n]*\n)*- name: TLS_PROXY\n  value: "true"\n\{\{- end \}\}`, string(serve))
	require.Regexp(t, `(?s)with \.Values\.config\.oidcRequiredGroups \}\}\n- name: OIDC_REQUIRED_GROUPS`, helmDefine(t, "graph.podEnv"))

	security, err := os.ReadFile("serve_security.go")
	require.NoError(t, err)
	require.Contains(t, string(security), `getenv("TLS_PROXY") == "true"`, "the chart sets an env var serve does not read")
}

// Disk scanning is an opt-in with a cost: off must mean off. With
// config.diskScanEnabled false the chart renders no envelope key into the Secret
// and no disk-scan variable into any pod, so the scanner pod keeps holding no
// application secret. The values default and the hardened overlay stay off.
func TestChartDiskScanOffMeansOff(t *testing.T) {
	secret, err := os.ReadFile(chartDir + "templates/secret.yaml")
	require.NoError(t, err)
	gated := regexp.MustCompile(`(?s)\{\{- if \.Values\.config\.diskScanEnabled \}\}[^{]*?disk-scan-envelope-key:.*?\{\{- end \}\}`)
	assert.True(t, gated.Match(secret), "the envelope key must be rendered only inside the diskScanEnabled gate")

	helpers, err := os.ReadFile(chartDir + "templates/_helpers.tpl")
	require.NoError(t, err)
	block := regexp.MustCompile(`(?s)\{\{- if \.Values\.config\.diskScanEnabled \}\}(.*?)\n\{\{- end \}\}`).FindSubmatch(helpers)
	require.NotNil(t, block, "the pod env must have a diskScanEnabled block")
	assert.Contains(t, string(block[1]), "DISK_SCAN_ENABLED")
	assert.Contains(t, string(block[1]), "DISK_SCAN_ENVELOPE_KEY")
	outside := strings.Replace(string(helpers), string(block[0]), "", 1)
	assert.NotContains(t, outside, "DISK_SCAN", "no disk-scan variable may be rendered outside the gate")
	assert.NotContains(t, outside, "disk-scan-envelope-key", "the envelope key may not be referenced outside the gate")

	v := chartValues(t)
	cfg, ok := v["config"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, false, cfg["diskScanEnabled"], "disk scanning is off by default")

	hardened, err := os.ReadFile("../../deploy/helm-values/hardened.yaml")
	require.NoError(t, err)
	assert.NotContains(t, string(hardened), "diskScanEnabled: true", "the hardened overlay must not turn disk scanning on")
}
