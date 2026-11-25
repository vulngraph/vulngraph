package main

import (
	"encoding/base64"
	"encoding/xml"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/vulngraph/vulngraph/internal/migrate"
)

const (
	composeDir         = "../../deploy/docker-compose/"
	postgresInitFile   = chartDir + "files/postgres-init.sql"
	clickhouseUserFile = chartDir + "files/clickhouse-users.xml"
)

// chUsers is the part of files/clickhouse-users.xml the tests read.
type chUsers struct {
	Users struct {
		Default struct {
			Remove string `xml:"remove,attr"`
		} `xml:"default"`
		Migrate chUser `xml:"graph_migrate"`
		App     chUser `xml:"graph"`
		Scanner chUser `xml:"graph_scanner"`
	} `xml:"users"`
}

type chUser struct {
	Password struct {
		FromEnv string `xml:"from_env,attr"`
	} `xml:"password"`
	DefaultDatabase string   `xml:"default_database"`
	Grants          []string `xml:"grants>query"`
}

func readCHUsers(t *testing.T) chUsers {
	t.Helper()
	raw, err := os.ReadFile(clickhouseUserFile)
	require.NoError(t, err)
	var u chUsers
	require.NoError(t, xml.Unmarshal(raw, &u))
	return u
}

func readRepoFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(raw)
}

type composeService struct {
	Environment map[string]string `yaml:"environment"`
	// Short-syntax strings or long-syntax maps.
	Volumes []any `yaml:"volumes"`
}

// requireStrictBind checks that svc bind-mounts source at target read-only,
// with create_host_path off: Docker would otherwise mount an empty directory
// in place of a file missing outside the checkout.
func requireStrictBind(t *testing.T, svc composeService, source, target string) {
	t.Helper()
	want := map[string]any{
		"type": "bind", "source": source, "target": target, "read_only": true,
		"bind": map[string]any{"create_host_path": false},
	}
	require.Contains(t, svc.Volumes, want)
}

// composeServices decodes deploy/docker-compose/docker-compose.yml's services.
func composeServices(t *testing.T) map[string]composeService {
	t.Helper()
	var c struct {
		Services map[string]composeService `yaml:"services"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(readRepoFile(t, composeDir+"docker-compose.yml")), &c))
	return c.Services
}

// The bundled datastores, in the chart and in the compose stack, give the
// graph containers users that are not admins: Postgres's app role is no
// superuser, and the admin and schema passwords reach only the datastore
// containers and migrate. An app connecting as the superuser can run programs
// on the database host (COPY ... TO PROGRAM); one connecting as the ClickHouse
// schema user can rewrite audit_events.
func TestBundledDatastoreAppUsersAreNotAdmins(t *testing.T) {
	sql := readRepoFile(t, postgresInitFile)
	require.Contains(t, sql, `\set ON_ERROR_STOP on`)
	for role, pw := range map[string][2]string{
		"graph":             {"graph_password", "GRAPH_DB_PASSWORD"},
		migrate.ScannerRole: {"scanner_password", "GRAPH_SCANNER_DB_PASSWORD"},
	} {
		require.Contains(t, sql, `\getenv `+pw[0]+` `+pw[1])
		require.Contains(t, sql, "CREATE ROLE "+role+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS\n    PASSWORD :'"+pw[0]+"';",
			"an unset password must be a syntax error, not an empty password")
	}
	require.Contains(t, sql, "ALTER DATABASE graph OWNER TO graph;", "migrate and River's reindexing need the app role to own the database")
	statements := regexp.MustCompile(`(?m)^--.*$`).ReplaceAllString(sql, "")
	require.NotRegexp(t, `(?i)\bGRANT\b`, statements, "the app role gets ownership of its database, and migrate grants the scanner's tables")

	readers := map[string][]string{}
	require.NoError(t, filepath.WalkDir(chartDir+"templates", func(f string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body := readRepoFile(t, f)
		for _, key := range []string{"postgres-superuser-password", "clickhouse-migrate-password", "clickhouse-migrate-url",
			"postgres-scanner-password", "clickhouse-scanner-password", "scanner-database-url", "scanner-clickhouse-url"} {
			if strings.Contains(body, key) {
				readers[key] = append(readers[key], filepath.Base(f))
			}
		}
		return nil
	}))
	require.Equal(t, map[string][]string{
		"postgres-superuser-password": {"postgres.yaml", "secret.yaml"},
		"clickhouse-migrate-password": {"clickhouse.yaml", "secret.yaml"},
		"clickhouse-migrate-url":      {"_helpers.tpl", "secret.yaml"},
		"postgres-scanner-password":   {"postgres.yaml", "secret.yaml"},
		"clickhouse-scanner-password": {"clickhouse.yaml", "secret.yaml"},
		"scanner-database-url":        {"_helpers.tpl", "secret.yaml"},
		"scanner-clickhouse-url":      {"_helpers.tpl", "secret.yaml"},
	}, readers, "an admin, schema or scanner credential reaches a template other than its datastore's or its pod's")
	require.Equal(t, 1, strings.Count(readRepoFile(t, chartDir+"templates/deployment-serve.yaml"), `"migrate" true`),
		"only the migrate init container connects as the ClickHouse schema user")
	for _, f := range []string{"deployment-worker.yaml", "deployment-scanner.yaml"} {
		require.NotContains(t, readRepoFile(t, chartDir+"templates/"+f), `"migrate" true`, f)
	}
	require.Contains(t, readRepoFile(t, chartDir+"templates/deployment-scanner.yaml"),
		`{{ include "graph.datastoreEnv" (dict "scanner" true "Values" .Values) }}`, "the scanner connects as graph_scanner")
	for _, f := range []string{"deployment-serve.yaml", "deployment-worker.yaml"} {
		require.NotContains(t, readRepoFile(t, chartDir+"templates/"+f), `"scanner" true`, f)
	}
	dsn := helmDefine(t, "graph.datastoreEnv")
	require.Contains(t, dsn, `key: {{ ternary "scanner-database-url" "database-url" (.scanner | default false) }}`)
	require.Contains(t, dsn, `key: {{ ternary "scanner-clickhouse-url" (ternary "clickhouse-migrate-url" "clickhouse-url" (.migrate | default false)) (.scanner | default false) }}`)
	secret := readRepoFile(t, chartDir+"templates/secret.yaml")
	for _, v := range []string{"scannerDatabaseUrl", "scannerClickhouseUrl"} {
		require.Regexp(t, `required "secret\.`+v+` is required with scanner\.enabled and an external`, secret,
			"an external datastore without a scanner DSN must fail the render, not hand the scanner the app's")
	}

	pg := readRepoFile(t, chartDir+"templates/postgres.yaml")
	require.Contains(t, pg, "- name: POSTGRES_USER\n              value: postgres\n")
	require.Contains(t, pg, `.Files.Get "files/postgres-init.sql"`)
	require.Contains(t, pg, "mountPath: /docker-entrypoint-initdb.d")
	ch := readRepoFile(t, chartDir+"templates/clickhouse.yaml")
	require.Contains(t, ch, "- name: CLICKHOUSE_SKIP_USER_SETUP\n              value: \"1\"\n",
		"the image's user setup would write its own users file over clickhouse-users.xml's")
	require.NotContains(t, ch, "- name: CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT\n")
	require.Contains(t, readRepoFile(t, chartDir+"templates/clickhouse-config.yaml"), `.Files.Get "files/clickhouse-users.xml"`)

	svc := composeServices(t)
	requireStrictBind(t, svc["postgres"], "../helm-chart/graph/files/postgres-init.sql", "/docker-entrypoint-initdb.d/10-graph-role.sql")
	requireStrictBind(t, svc["clickhouse"], "../helm-chart/graph/files/clickhouse-users.xml", "/etc/clickhouse-server/users.d/zz-graph-users.xml")
	require.Equal(t, "postgres", svc["postgres"].Environment["POSTGRES_USER"])
	require.Equal(t, "1", svc["clickhouse"].Environment["CLICKHOUSE_SKIP_USER_SETUP"])
	require.NotContains(t, svc["clickhouse"].Environment, "CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT")
	secrets := generatedSecrets(t)
	require.NotEmpty(t, secrets["postgres"]["GRAPH_SCANNER_DB_PASSWORD"], "the scanner role must not be created without a password")
	require.NotEmpty(t, secrets["clickhouse"]["GRAPH_CH_SCANNER_PASSWORD"], "ClickHouse takes an empty password as no password")
	for name, s := range svc {
		require.NotContains(t, s.Environment, "DATABASE_URL", "%s: the DSNs come from the generated env file", name)
		require.NotContains(t, s.Environment, "CLICKHOUSE_URL", "%s: the DSNs come from the generated env file", name)
	}
}

// secretsMounts is the generated env file each service reads: its own volume,
// so a container never holds a credential it does not use.
var secretsMounts = map[string]string{
	"postgres": "secrets-postgres", "clickhouse": "secrets-clickhouse",
	"migrate": "secrets-migrate", "serve": "secrets-app", "worker": "secrets-app",
}

// generatedSecrets runs deploy/docker-compose/init-secrets.sh into a temporary
// root, as the init service does, and returns each consumer's env file.
func generatedSecrets(t *testing.T) map[string]map[string]string {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	root := t.TempDir()
	out := map[string]map[string]string{}
	dirs := []string{"postgres", "clickhouse", "migrate", "app"}
	for _, dir := range dirs {
		require.NoError(t, os.Mkdir(filepath.Join(root, dir), 0o755))
	}
	run := func() {
		cmd := exec.Command(sh, composeDir+"init-secrets.sh")
		cmd.Env = append(os.Environ(), "SECRETS_DIR="+root)
		if msg, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("init-secrets.sh: %v\n%s", err, msg)
		}
	}
	read := func() {
		for _, dir := range dirs {
			env := map[string]string{}
			for _, line := range strings.Split(strings.TrimSpace(readRepoFile(t, filepath.Join(root, dir, "env"))), "\n") {
				k, v, ok := strings.Cut(line, "=")
				require.True(t, ok, "%s: %q", dir, line)
				env[k] = v
			}
			out[dir] = env
		}
	}
	run()
	read()
	first := maps.Clone(out)
	run()
	read()
	require.Equal(t, first, out, "a second start must keep the secrets the data volumes were created with")
	return out
}

func TestComposeSecretsAreGeneratedAndScoped(t *testing.T) {
	secrets := generatedSecrets(t)
	svc := composeServices(t)

	for name, vol := range secretsMounts {
		var mounted bool
		for _, v := range svc[name].Volumes {
			if m, ok := v.(map[string]any); ok && m["source"] == vol {
				require.Equal(t, "/secrets", m["target"], name)
				require.Equal(t, true, m["read_only"], "%s must not write its secrets", name)
				mounted = true
			}
		}
		require.True(t, mounted, "%s mounts %s", name, vol)
		for other := range secretsMounts {
			if secretsMounts[other] == vol {
				continue
			}
			for _, v := range svc[other].Volumes {
				if m, ok := v.(map[string]any); ok {
					require.NotEqual(t, vol, m["source"], "%s must not read %s's secrets", other, name)
				}
			}
		}
	}
	for _, name := range []string{"migrate", "serve", "worker"} {
		require.Equal(t, "/secrets/env", svc[name].Environment["GRAPH_ENV_FILE"], name)
	}

	app, pg, ch, mig := secrets["app"], secrets["postgres"], secrets["clickhouse"], secrets["migrate"]
	require.True(t, strings.HasPrefix(app["DATABASE_URL"], "postgres://graph:"+pg["GRAPH_DB_PASSWORD"]+"@postgres:5432/graph"))
	require.Equal(t, app["DATABASE_URL"], mig["DATABASE_URL"])
	require.Equal(t, "clickhouse://graph:"+ch["GRAPH_CH_APP_PASSWORD"]+"@clickhouse:9000/graph", app["CLICKHOUSE_URL"])
	require.Equal(t, "clickhouse://graph_migrate:"+ch["GRAPH_CH_MIGRATE_PASSWORD"]+"@clickhouse:9000/graph", mig["CLICKHOUSE_URL"])
	require.Equal(t, ch["GRAPH_CH_MIGRATE_PASSWORD"], ch["CLICKHOUSE_PASSWORD"], "the image creates the database as graph_migrate")
	raw, err := base64.StdEncoding.DecodeString(app["GRAPH_SECRET_KEY"])
	require.NoError(t, err)
	require.Len(t, raw, 32)
	require.Len(t, app["LADYBUG_RPC_SECRET"], 64)

	// The app files hold neither the superuser, scanner nor schema credentials.
	appFile := strings.Join(slices.Sorted(maps.Values(app)), "\n")
	for _, k := range []string{"POSTGRES_PASSWORD", "GRAPH_SCANNER_DB_PASSWORD"} {
		require.NotContains(t, appFile, pg[k], k)
	}
	for _, k := range []string{"GRAPH_CH_SCANNER_PASSWORD", "GRAPH_CH_MIGRATE_PASSWORD"} {
		require.NotContains(t, appFile, ch[k], k)
	}
	// Spliced into DSNs, so URL-safe, and distinct.
	seen := map[string]bool{}
	for _, v := range []string{pg["POSTGRES_PASSWORD"], pg["GRAPH_DB_PASSWORD"], pg["GRAPH_SCANNER_DB_PASSWORD"],
		ch["GRAPH_CH_APP_PASSWORD"], ch["GRAPH_CH_MIGRATE_PASSWORD"], ch["GRAPH_CH_SCANNER_PASSWORD"]} {
		require.Regexp(t, `^[0-9a-f]{48}$`, v)
		require.False(t, seen[v], "a password is reused")
		seen[v] = true
	}
}

// chUserSettings are the settings a user in clickhouse-users.xml may have:
// none of the other password forms (no_password, a hash in the file, LDAP,
// SSH keys), and no access_management or named-collection control.
var chUserSettings = []string{"password", "networks", "profile", "quota", "default_database", "grants"}

// chUserNames returns the users the file defines, and what is wrong with
// them: every one but the removed default needs its password from the
// environment and no setting outside chUserSettings.
func chUserNames(raw string) (names, problems []string, err error) {
	var f struct {
		Users struct {
			Users []struct {
				XMLName  xml.Name
				Remove   string `xml:"remove,attr"`
				Settings []struct {
					XMLName xml.Name
					FromEnv string `xml:"from_env,attr"`
					Text    string `xml:",chardata"`
				} `xml:",any"`
			} `xml:",any"`
		} `xml:"users"`
	}
	if err := xml.Unmarshal([]byte(raw), &f); err != nil {
		return nil, nil, err
	}
	for _, user := range f.Users.Users {
		name := user.XMLName.Local
		names = append(names, name)
		if user.Remove != "" {
			if user.Remove != "remove" || len(user.Settings) > 0 {
				problems = append(problems, name+": a removed user with settings")
			}
			continue
		}
		var passwords int
		for _, set := range user.Settings {
			switch {
			case !slices.Contains(chUserSettings, set.XMLName.Local):
				problems = append(problems, name+": "+set.XMLName.Local)
			case set.XMLName.Local == "password":
				passwords++
				if set.FromEnv == "" || strings.TrimSpace(set.Text) != "" {
					problems = append(problems, name+": a password in the file, or an empty one")
				}
			}
		}
		if passwords != 1 {
			problems = append(problems, name+": no password from the environment")
		}
	}
	slices.Sort(names)
	return names, problems, nil
}

// chUserNames refuses a user that logs in without a password or can manage
// access, wherever in the file it is added.
func TestCHUserNamesRefusesUnsafeUsers(t *testing.T) {
	ok := `<clickhouse><users><default remove="remove"/>` +
		`<a><password from_env="A"/><grants><query>GRANT SELECT ON graph.x</query></grants></a></users></clickhouse>`
	names, problems, err := chUserNames(ok)
	require.NoError(t, err)
	require.Empty(t, problems)
	require.Equal(t, []string{"a", "default"}, names)
	for bad, want := range map[string]string{
		`<b><networks><ip>::/0</ip></networks></b>`:                                             "b: no password from the environment",
		`<b><password></password></b>`:                                                          "b: a password in the file, or an empty one",
		`<b><password>pw</password></b>`:                                                        "b: a password in the file, or an empty one",
		`<b><password from_env="B"/><no_password/></b>`:                                         "b: no_password",
		`<b><password_sha256_hex>00</password_sha256_hex></b>`:                                  "b: password_sha256_hex",
		`<b><password from_env="B"/><access_management>1</access_management></b>`:               "b: access_management",
		`<b><password from_env="B"/><named_collection_control>1</named_collection_control></b>`: "b: named_collection_control",
		`<b remove="remove"><password from_env="B"/></b>`:                                       "b: a removed user with settings",
	} {
		_, problems, err := chUserNames(strings.Replace(ok, "</users>", bad+"</users>", 1))
		require.NoError(t, err)
		require.Contains(t, problems, want, bad)
	}
}

var chGrant = regexp.MustCompile(`^GRANT ([A-Z ,]+) ON ([a-z_]+)\.([a-z_*]+)$`)

// The bundled ClickHouse has no admin and no user without a password: the
// image's default (passwordless, with access management) is removed, and the
// image's bootstrap creates the graph database as graph_migrate, whose ALL on
// graph.* includes CREATE DATABASE graph. graph_scanner reads what the scanner
// targets and inserts findings, and nothing else: no audit_events, no
// mutations, no writes to assets or edges.
func TestClickHouseUsersHaveNoAdmin(t *testing.T) {
	u := readCHUsers(t)
	require.Equal(t, "remove", u.Users.Default.Remove, "the image's default user is a passwordless admin")
	names, problems, err := chUserNames(readRepoFile(t, clickhouseUserFile))
	require.NoError(t, err)
	require.Empty(t, problems, "a user that logs in without a password, or can manage access")
	require.Equal(t, []string{"default", "graph", "graph_migrate", "graph_scanner"}, names,
		"a user whose grants this test does not check")
	require.Equal(t, []string{"GRANT ALL ON graph.*"}, u.Users.Migrate.Grants)
	require.Empty(t, u.Users.Migrate.DefaultDatabase,
		"the bootstrap logs in as graph_migrate before graph exists, and a login to a missing default database fails")
	require.Equal(t, []string{
		"GRANT SELECT ON graph.goose_db_version",
		"GRANT SELECT ON graph.assets",
		"GRANT SELECT, INSERT ON graph.findings",
		"GRANT SELECT ON graph.finding_enrichment",
	}, u.Users.Scanner.Grants)

	envs := map[string]string{
		u.Users.App.Password.FromEnv:     "GRAPH_CH_APP_PASSWORD",
		u.Users.Migrate.Password.FromEnv: "GRAPH_CH_MIGRATE_PASSWORD",
		u.Users.Scanner.Password.FromEnv: "GRAPH_CH_SCANNER_PASSWORD",
	}
	require.Len(t, envs, 3)
	ch := readRepoFile(t, chartDir+"templates/clickhouse.yaml")
	compose := composeServices(t)["clickhouse"].Environment
	generated := generatedSecrets(t)["clickhouse"]
	for got, want := range envs {
		require.Equal(t, want, got)
		require.Contains(t, ch, "- name: "+got+"\n")
		require.Contains(t, generated, got)
	}
	require.Contains(t, ch, "- name: CLICKHOUSE_USER\n              value: graph_migrate\n")
	require.Contains(t, ch, "- name: CLICKHOUSE_PASSWORD\n              valueFrom: { secretKeyRef: { name: {{ .Values.secretName }}, key: clickhouse-migrate-password } }\n")
	require.Equal(t, "graph_migrate", compose["CLICKHOUSE_USER"])
	require.Equal(t, generated["GRAPH_CH_MIGRATE_PASSWORD"], generated["CLICKHOUSE_PASSWORD"])
}

// The NetworkPolicy is on by default and cannot break an install that sets
// nothing: serve's port stays open until ingressNamespace names the ingress
// controller (with the node CIDRs its probes need), while the datastores admit
// only the graph pods holding their credentials and ClickHouse's HTTP SQL port
// is never opened.
func TestChartNetworkPolicyIsLeastPrivilegeByDefault(t *testing.T) {
	np, ok := chartValues(t)["networkPolicy"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, true, np["enabled"])
	require.Equal(t, "", np["ingressNamespace"], "a namespace the cluster may not have would cut serve off from its ingress")
	require.Equal(t, "", np["metricsNamespace"])
	require.Empty(t, np["nodeCIDRs"])

	tpl := readRepoFile(t, chartDir+"templates/networkpolicy.yaml")
	require.Contains(t, tpl, "{{- if and $np.ingressNamespace (not $np.nodeCIDRs) }}\n{{- fail ",
		"limiting serve to the ingress namespace without node CIDRs blocks its kubelet probes")
	require.Contains(t, tpl, "{{- if and $np.nodeCIDRs (not $np.ingressNamespace) }}\n{{- fail ",
		"node CIDRs without the ingress namespace would leave serve open while looking restricted")
	require.Contains(t, tpl, "values: [serve, worker{{ if $scanner }}, scanner{{ end }}]")
	require.Equal(t, 1, strings.Count(tpl, "- podSelector:\n            matchExpressions:"),
		"the datastores' one peer is the graph pods that hold their credentials")
	require.NotContains(t, tpl, "port: 8123")
	require.NotContains(t, tpl, "namespaceSelector: {}")
	require.Contains(t, helmDefine(t, "graph.podEnv"), "(and .Values.networkPolicy.enabled .Values.networkPolicy.ingressNamespace)",
		"config.oauth2Proxy must refuse to render while serve's port is open to every source")
}
