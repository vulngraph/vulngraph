package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	hardenedOverlay = "../../deploy/helm-values/hardened.yaml"
	hardenedChecks  = chartDir + "templates/checks/hardened.yaml"
)

// hardenedRequired are the values only the operator knows. The overlay leaves
// each one empty under a REQUIRED comment, and hardened: true names each in
// its refusal, so the overlay alone never renders.
var hardenedRequired = []string{
	"image.digest",
	"networkPolicy.ingressNamespace",
	"networkPolicy.nodeCIDRs",
	"networkPolicy.metricsNamespace",
	"ingress.host",
	"config.trustedProxyCidrs",
	"postgres.tlsSecret",
	"clickhouse.tlsSecret",
}

func readYAMLMap(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var v map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &v))
	return v
}

// lookup walks a dotted path through decoded YAML maps.
func lookup(t *testing.T, v map[string]any, path string) (any, bool) {
	t.Helper()
	var cur any = v
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func TestHardenedOverlayLeavesOperatorValuesEmpty(t *testing.T) {
	raw, err := os.ReadFile(hardenedOverlay)
	require.NoError(t, err)
	require.Equal(t, len(hardenedRequired), strings.Count(string(raw), "# REQUIRED"),
		"every REQUIRED comment in the overlay is a value hardenedRequired lists")

	overlay := readYAMLMap(t, hardenedOverlay)
	checks := readRepoFile(t, hardenedChecks)
	for _, path := range hardenedRequired {
		val, ok := lookup(t, overlay, path)
		require.True(t, ok, "the overlay does not set %s", path)
		require.Empty(t, val, "%s must be left for the operator: a value here would render", path)
		require.Contains(t, checks, path, "hardened: true does not refuse an empty %s", path)
	}

	on := map[string]any{
		"hardened":                               true,
		"securityContext.enabled":                true,
		"securityContext.readOnlyRootFilesystem": true,
		"scanner.enabled":                        true,
		"networkPolicy.enabled":                  true,
		"metrics.enabled":                        true,
		"ingress.enabled":                        true,
		"ingress.tls":                            true,
		"config.requireAdminTotp":                true,
		"config.tlsProxy":                        true,
		"postgres.sslMode":                       "verify-full",
		"clickhouse.secure":                      true,
		"secret.create":                          true,
	}
	for path, want := range on {
		got, ok := lookup(t, overlay, path)
		require.True(t, ok, "the overlay does not set %s", path)
		require.Equal(t, want, got, path)
	}
	header, ok := lookup(t, overlay, "config.clientIpHeader")
	require.True(t, ok)
	require.NotEmpty(t, header)

	require.Equal(t, false, chartValues(t)["hardened"], "the default install runs no hardened checks")
}

// The checks render before every single-setting guard (Helm renders deeper
// templates first), and they are the only content of their template.
func TestHardenedChecksRenderNothing(t *testing.T) {
	checks := readRepoFile(t, hardenedChecks)
	require.Contains(t, checks, "{{- if .Values.hardened }}")
	require.Contains(t, checks, `{{- fail (printf "hardened: true refuses to render`)
	text := regexp.MustCompile(`(?s)\{\{.*?\}\}`).ReplaceAllString(checks, "")
	require.Empty(t, strings.TrimSpace(text), "the hardened checks emit output")
}

// Every flag in docs/security-hardening.md's dangerous-flags table, and every
// chart value that sets one, is refused under hardened: true.
func TestHardenedRefusesEveryDangerousFlag(t *testing.T) {
	doc := readRepoFile(t, "../../docs/security-hardening.md")
	start := strings.Index(doc, "## Dangerous flags")
	require.NotEqual(t, -1, start)
	table := doc[start:]
	table = table[:strings.Index(table, "\n### ")]

	checks := readRepoFile(t, hardenedChecks)
	flag := regexp.MustCompile("`([A-Z0-9_]+)=")
	var names []string
	for _, row := range strings.Split(table, "\n") {
		if !strings.HasPrefix(row, "| `") {
			continue
		}
		first := strings.SplitN(row, "|", 3)[1]
		for _, m := range flag.FindAllStringSubmatch(first, -1) {
			names = append(names, m[1])
		}
	}
	require.GreaterOrEqual(t, len(names), 15, "the dangerous-flags table did not parse")
	names = append(names, "PPROF_PORT")
	for _, name := range names {
		require.Contains(t, checks, `"`+name+`"`, "hardened: true lets extraEnv set %s", name)
	}

	weakening := regexp.MustCompile(`^(allowAnyDomain|.*AllowAnyDomain|.*AllowUnsigned|.*AllowPlaintext|.*AllowUnverifiedEmail|.*TrustGroups)$`)
	var keys []string
	var walk func(prefix string, v map[string]any)
	walk = func(prefix string, v map[string]any) {
		for k, val := range v {
			if m, ok := val.(map[string]any); ok {
				walk(prefix+k+".", m)
				continue
			}
			if weakening.MatchString(k) {
				keys = append(keys, prefix+k)
			}
		}
	}
	walk("", chartValues(t))
	sort.Strings(keys)
	require.NotEmpty(t, keys)
	for _, key := range keys {
		require.Contains(t, checks, `"`+key+`"`, "hardened: true does not refuse %s", key)
	}
}

// hardenedScript renders the overlay and fails unless each check refuses its
// gap; CI runs it in the helm job.
const hardenedScript = "../../scripts/check-chart-hardened.sh"

// Every check in templates/checks/hardened.yaml has a case in the script that
// trips it: the setting its refusal names leads some `refuses` expectation,
// and every refused chart value and dangerous flag is listed.
func TestHardenedScriptCoversEveryCheck(t *testing.T) {
	checks := readRepoFile(t, hardenedChecks)
	script := readRepoFile(t, hardenedScript)
	require.Contains(t, readRepoFile(t, "../../.github/workflows/ci.yaml"),
		"scripts/check-chart-hardened.sh", "CI does not run the hardened checks")

	var wants []string
	expect := regexp.MustCompile(`(?m)^\s*refuses ('[^']*'|"[^"]*"|\S+)`)
	for _, m := range expect.FindAllStringSubmatch(script, -1) {
		wants = append(wants, strings.Trim(m[1], `'"`))
	}
	require.NotEmpty(t, wants)

	site := regexp.MustCompile(`\$gaps = append \$gaps \(?(?:printf )?"([^"]*)"`)
	setting := regexp.MustCompile(`^[a-z][A-Za-z0-9.%]*`)
	sites := site.FindAllStringSubmatch(checks, -1)
	require.GreaterOrEqual(t, len(sites), 25, "the hardened checks did not parse")
	for _, m := range sites {
		name := setting.FindString(m[1])
		if name == "" || name == "%s" {
			continue // named per key below
		}
		pattern := regexp.MustCompile(strings.ReplaceAll(regexp.QuoteMeta(name), "%s", `\S+`))
		covered := false
		for _, want := range wants {
			covered = covered || pattern.MatchString(want)
		}
		require.True(t, covered, "no case in %s trips the check naming %q", hardenedScript, name)
	}

	for _, start := range []string{"{{- $refused := dict", "{{- $dangerous := list", "{{- $chartOwned := list"} {
		names := hardenedList(t, checks, start)
		require.NotEmpty(t, names, start)
		for _, n := range names {
			listed := regexp.MustCompile(`(^|\s)` + regexp.QuoteMeta(n) + `[\s;]`).MatchString(script)
			require.True(t, listed, "%s has no case for %s", hardenedScript, n)
		}
	}
}

// hardenedList returns the quoted names in the hardened checks' list or dict
// that starts with start.
func hardenedList(t *testing.T, checks, start string) []string {
	t.Helper()
	i := strings.Index(checks, start)
	require.NotEqual(t, -1, i, start)
	var names []string
	for _, m := range regexp.MustCompile(`"([A-Za-z0-9_.]+)"`).FindAllStringSubmatch(checks[i:i+strings.Index(checks[i:], "}}")], -1) {
		names = append(names, m[1])
	}
	return names
}

// Every sign-in variable serve reads is refused in extraEnv under hardened:
// an entry would turn on or reshape SSO past the checks on the chart's sso.*
// and config.* values. Every $chartOwned name is one the chart sets.
func TestHardenedRefusesSignInEnv(t *testing.T) {
	checks := readRepoFile(t, hardenedChecks)
	refused := map[string]bool{}
	for _, start := range []string{"{{- $dangerous := list", "{{- $chartOwned := list"} {
		for _, n := range hardenedList(t, checks, start) {
			refused[n] = true
		}
	}

	read := regexp.MustCompile(`getenv\("((?:OAUTH2_PROXY|IAP_|OIDC_|GOOGLE_|OKTA_|ADMIN_)[A-Z0-9_]*)"\)`).
		FindAllStringSubmatch(readRepoFile(t, "serve_auth.go"), -1)
	require.GreaterOrEqual(t, len(read), 20, "serve_auth.go's sign-in variables did not parse")
	for _, m := range read {
		require.True(t, refused[m[1]], "hardened: true lets extraEnv set %s, which serve reads for sign-in", m[1])
	}

	var templates strings.Builder
	require.NoError(t, filepath.WalkDir(chartDir+"templates", func(f string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			templates.WriteString(readRepoFile(t, f))
		}
		return err
	}))
	for _, n := range hardenedList(t, checks, "{{- $chartOwned := list") {
		require.Contains(t, templates.String(), "- name: "+n+"\n", "the chart never sets %s", n)
	}
}

// The hardened role-mapping check counts a value as set only if it holds a
// rune the class matches, and serve's splitCSV keeps an entry only if
// strings.TrimSpace leaves something: the class must match exactly the runes
// that are neither a comma nor unicode.IsSpace.
func TestHardenedRoleMappingClassMatchesSplitCSV(t *testing.T) {
	m := regexp.MustCompile("regexMatch `([^`]+)` ").FindStringSubmatch(readRepoFile(t, hardenedChecks))
	require.NotNil(t, m, "the role-mapping class did not parse")
	class := regexp.MustCompile(m[1])
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		s := string(r)
		require.Equal(t, len(splitCSV(s)) > 0, class.MatchString(s), "rune %U", r)
	}
}
