package executor

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Vulngraph never executes a remediation without a person's explicit yes (ADR 087).
// These guards hold that at the executor, structurally and behaviourally:
//
//   - TestOnlyHumanTransportsBuildExecutionRequests: no file outside the two
//     transports a person drives writes an ExecutionRequest composite literal.
//     It sees only literals; a zero-value var or new(ExecutionRequest) passes
//     it, so the behavioural guarantee is the next test.
//   - TestExecute_RefusesWithoutAPrincipal: a context with no authenticated
//     person is refused before any approval check, intent row or cloud call.
//   - TestRunDecision_RefusesWithoutAPersonOrSecondAdmin: the decision panel's
//     approve-and-run holds the same line — no principal, no run; a
//     destructive fix with no second admin's request, no run.
//   - TestExecutorREST_APIKeyNeedsADifferentAdminsGrant (apikey_grant_test.go):
//     an API key over REST gets what MCP execute_action gets — every change
//     needs a different admin's session grant, and a key never mints one.

const executorImportPath = "github.com/vulngraph/vulngraph/internal/app/executor"

// humanTransports are the only files allowed to construct an ExecutionRequest,
// each with the reason a person stands behind every request it builds.
var humanTransports = map[string]string{
	"internal/app/executor/handler.go": "HTTP, behind RequireAuth and RequireRole(admin): the admin's request is the yes, " +
		"the destructive subset still needs a second admin's grant, and so does every action on an API key",
	"internal/app/mcp/tools_cloud.go": "MCP execute_action: an LLM client may hold the admin key, so every request " +
		"carries RequireGrant and runs only with a grant a DIFFERENT admin minted",
}

// grantRequired lists the transports whose requests must set RequireGrant:
// true — the ones an agent, not a person, may be typing into.
var grantRequired = map[string]bool{"internal/app/mcp/tools_cloud.go": true}

func TestOnlyHumanTransportsBuildExecutionRequests(t *testing.T) {
	root := guardModuleRoot(t)
	sites := map[string][]*ast.CompositeLit{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "frontend", "node_modules", "vendor", "third_party", "build":
				return filepath.SkipDir
			}
			// Hidden dirs (.git, nested worktrees) hold copies of the tree, not code
			// this binary builds.
			if path != root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		for _, lit := range executionRequestLiterals(file, filepath.ToSlash(filepath.Dir(rel)) == "internal/app/executor") {
			sites[filepath.ToSlash(rel)] = append(sites[filepath.ToSlash(rel)], lit)
		}
		return nil
	})
	require.NoError(t, err)

	var offenders []string
	for file := range sites {
		if _, ok := humanTransports[file]; !ok {
			offenders = append(offenders, file)
		}
	}
	sort.Strings(offenders)
	require.Emptyf(t, offenders,
		"executor.ExecutionRequest is built outside the transports a person drives:\n  %s\n\n"+
			"Vulngraph never executes a remediation on its own (ADR 087). A job, sweep, webhook consumer or the "+
			"decision pipeline must hand a proposal to a person (govern queue, approval grant), never call "+
			"Execute itself. If this really is a new human-driven transport, add it to humanTransports with "+
			"the reason a person stands behind every request it builds.",
		strings.Join(offenders, "\n  "))

	for file := range humanTransports {
		require.NotEmptyf(t, sites[file],
			"%s no longer builds an ExecutionRequest — drop it from humanTransports so the allowlist stays honest", file)
	}
	for file := range grantRequired {
		for _, lit := range sites[file] {
			require.Truef(t, setsTrue(lit, "RequireGrant"),
				"%s builds an ExecutionRequest without RequireGrant: true — an agent-driven transport must not "+
					"mutate without a different admin's grant", file)
		}
	}
}

// executionRequestLiterals returns the ExecutionRequest composite literals in
// file: `executor.ExecutionRequest{...}` under whatever name the file imports
// the package as, or a bare `ExecutionRequest{...}` inside the package itself.
func executionRequestLiterals(file *ast.File, inExecutorPkg bool) []*ast.CompositeLit {
	local := ""
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != executorImportPath {
			continue
		}
		local = "executor"
		if imp.Name != nil {
			local = imp.Name.Name
		}
	}
	var out []*ast.CompositeLit
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		switch typ := lit.Type.(type) {
		case *ast.SelectorExpr:
			if pkg, ok := typ.X.(*ast.Ident); ok && local != "" && pkg.Name == local && typ.Sel.Name == "ExecutionRequest" {
				out = append(out, lit)
			}
		case *ast.Ident:
			if inExecutorPkg && typ.Name == "ExecutionRequest" {
				out = append(out, lit)
			}
		}
		return true
	})
	return out
}

func setsTrue(lit *ast.CompositeLit, field string) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != field {
			continue
		}
		val, ok := kv.Value.(*ast.Ident)
		return ok && val.Name == "true"
	}
	return false
}

func guardModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqualf(t, dir, parent, "go.mod not found above %s", dir)
		dir = parent
	}
}

// TestExecute_RefusesWithoutAPrincipal: a real execution with no authenticated
// person on the context — the shape any background caller has — is refused
// before the approval check, the intent row and the cloud call, for the
// non-destructive actions that need no grant as much as for the rest.
func TestExecute_RefusesWithoutAPrincipal(t *testing.T) {
	audit := &fakeAuditor{}
	svc := NewService(awsRW()).WithAudit(audit)

	_, err := svc.Execute(context.Background(), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionS3BlockPublic, Params: map[string]string{ParamBucketName: "logs-bucket"},
	})
	require.ErrorIs(t, err, ErrNoPrincipal)
	require.NotErrorIs(t, err, ErrNoExecutionRole, "the cloud call was never reached")
	for _, e := range audit.events {
		require.NotEqual(t, AuditActionExecuteIntent, e.Action, "no intent row: nothing was about to run")
	}
	require.Len(t, audit.events, 1, "the refusal itself is audited")
	require.Equal(t, AuditActionExecuteFailed, audit.events[0].Action)

	// A dry run changes nothing and stays available without a principal.
	res, err := svc.Execute(context.Background(), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionS3BlockPublic, Params: map[string]string{ParamBucketName: "logs-bucket"}, DryRun: true,
	})
	require.NoError(t, err)
	require.True(t, res.DryRun)
}

// TestRunDecision_RefusesWithoutAPersonOrSecondAdmin: approve-and-run is a
// person's click or nothing. Without an authenticated principal the run is
// refused before anything is claimed or about to run; a destructive fix with
// no live request from a different admin is refused the same way, however
// it is confirmed.
func TestRunDecision_RefusesWithoutAPersonOrSecondAdmin(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	noIntent := func(t *testing.T) {
		t.Helper()
		for _, e := range f.audit.events {
			require.NotEqual(t, AuditActionExecuteIntent, e.Action, "nothing was about to run")
		}
	}

	_, _, err := f.svc.RunDecision(context.Background(), "d-s3", nil, "", decisionRequest)
	require.ErrorIs(t, err, ErrNoPrincipal)
	require.Empty(t, f.runs.rows, "no claim without a person")
	noIntent(t)

	_, _, err = f.svc.RunDecision(adminCtx("alice@example.com"), "d-stop", nil, "i-abc", decisionRequest)
	require.ErrorIs(t, err, ErrApprovalRequired)
	require.Empty(t, f.runs.rows, "no claim without the second admin")
	noIntent(t)
}
