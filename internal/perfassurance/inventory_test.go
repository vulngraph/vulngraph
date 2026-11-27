package perfassurance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInventoryReconcilesShippedWorkloads(t *testing.T) {
	root := "../.."
	inv, profiles, err := Load(root)
	require.NoError(t, err)
	entries, err := Discover(root)
	require.NoError(t, err)
	require.Empty(t, Validate(inv, profiles, entries))
	kinds := map[string]int{}
	for _, e := range entries {
		kinds[strings.SplitN(e.ID, ":", 2)[0]]++
	}
	for _, kind := range []string{"http", "openapi", "mcp", "collector", "job", "worker", "schedule", "correlation", "enrichment", "browser", "migration", "module"} {
		require.Positive(t, kinds[kind], kind)
	}
}

func TestInventoryRejectsUnmeasuredCreditAndScopeDrift(t *testing.T) {
	inv, profiles, err := Load("../..")
	require.NoError(t, err)
	entries, err := Discover("../..")
	require.NoError(t, err)
	require.NotEmpty(t, Validate(inv, profiles, append(entries, Entry{ID: "http:GET /api/new-expensive-work"})))
	f := &inv.Families[0]
	original := *f
	for _, mutate := range []func(){
		func() { f.Owner = "" }, func() { f.Weight = 2 }, func() { f.Scenarios = nil }, func() { f.Budget = "missing" },
		func() { f.Status = "covered" }, func() { f.Entries = []string{"module:removed.go"} }, func() { f.ID = inv.Families[1].ID },
	} {
		*f = original
		mutate()
		require.NotEmpty(t, Validate(inv, profiles, entries))
	}
}

func TestDiscoveryFindsNewOptionalRegistrations(t *testing.T) {
	root := t.TempDir()
	write := func(path, src string) {
		t.Helper()
		full := filepath.Join(root, path)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(src), 0o600))
	}
	write("internal/httpsrv/paths.go", `package httpsrv; const optionalPath="POST /api/optional"`)
	write("internal/httpsrv/server.go", `package httpsrv; func setup(){if enabled {mux.HandleFunc(optionalPath,h.Optional)}}`)
	write("internal/app/mcp/tools.go", `package mcp; const toolName="optional_tool";func setup(){h.register(tool{Name:toolName})}`)
	write("internal/jobs/extra.go", `package jobs;func (OptionalArgs) Kind() string{return "optional_job"};func setup(){river.AddWorker(workers,&OptionalWorker{})}`)
	write("internal/jobs/periodic.go", `package jobs;func schedule(){return OptionalArgs{},nil}`)
	write("cmd/graph/collect_registry.go", `package main;func setup(){registry.Register(connector.TypeNew,newCollector())}`)
	write("internal/collect/aws/new_service.go", `package aws;func collectNewService(){}`)
	write("internal/app/enrich/extra.go", `package enrich;func (OptionalSource) Name()string{return "new_source"}`)
	write("migrations/clickhouse/00005_new.go", `package clickhouse`)
	write("frontend/src/routes/Optional.tsx", `export const Optional=()=>null;`)
	write("frontend/src/router.tsx", `const routeTree=route("/optional",Optional);`)
	write("openapi/openapi.yaml", "paths:\n  /api/optional:\n    $ref: './domains/optional.yaml'\n")
	got, err := Discover(root)
	require.NoError(t, err)
	ids := map[string]bool{}
	for _, e := range got {
		ids[e.ID] = true
	}
	for _, id := range []string{"http:POST /api/optional", "mcp:optional_tool", "job:optional_job", "worker:OptionalWorker", "schedule:OptionalArgs", "collector:TypeNew", "module:internal/collect/aws/new_service.go", "enrichment:new_source", "migration:migrations/clickhouse/00005_new.go", "browser:Optional", "browser-route:route:/optional", "collection:internal/collect/aws:collectNewService", "openapi:/api/optional"} {
		require.True(t, ids[id], id)
	}
	// An unsupported registration must fail, rather than disappear from scope.
	write("internal/httpsrv/server.go", `package httpsrv;func setup(){mux.HandleFunc(config.Path,h.Optional)}`)
	_, err = Discover(root)
	require.ErrorContains(t, err, "dynamic HTTP route")
	write("internal/httpsrv/server.go", `package httpsrv`)
	write("internal/app/mcp/tools.go", `package mcp;func setup(){h.register(makeDynamicTool())}`)
	_, err = Discover(root)
	require.ErrorContains(t, err, "dynamic MCP registration")
}

func TestProfilesRejectMissingBudgetsAndInflatedCorrectnessTolerance(t *testing.T) {
	_, profiles, err := Load("../..")
	require.NoError(t, err)
	for _, field := range []string{"assets", "http_requests_per_second", "host", "limits", "budgets"} {
		var p map[string]any
		require.NoError(t, json.Unmarshal(profiles.Profiles["small"], &p))
		delete(p, field)
		data, err := json.Marshal(p)
		require.NoError(t, err)
		require.NotEmpty(t, validateProfile("small", data), field)
	}
	var p map[string]any
	require.NoError(t, json.Unmarshal(profiles.Profiles["small"], &p))
	p["budgets"].(map[string]any)["correctness_mismatches"] = 1
	data, err := json.Marshal(p)
	require.NoError(t, err)
	require.NotEmpty(t, validateProfile("small", data))
}
