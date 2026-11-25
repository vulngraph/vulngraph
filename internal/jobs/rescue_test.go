package jobs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// kindLiteralsInPackage parses this package's source and collects the string
// literal returned by every `func (XxxArgs) Kind() string` method.
func kindLiteralsInPackage(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()
	kinds := map[string]bool{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, entry.Name(), nil, 0)
		require.NoError(t, err)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "Kind" || fn.Recv == nil || len(fn.Body.List) != 1 {
				continue
			}
			ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				continue
			}
			lit, ok := ret.Results[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			kind, err := strconv.Unquote(lit.Value)
			require.NoError(t, err)
			kinds[kind] = true
		}
	}
	require.NotEmpty(t, kinds, "no Kind() methods found — parser broken?")
	return kinds
}

// TestAllJobKindsRescuable locks rescueRegistrations to the full set of job
// kinds declared in this package. A kind missing from the rescue set is
// permanently DISCARDED by any leader pod that doesn't work it (River
// JobRescuer behaviour) — add the new args type to rescueRegistrations.
func TestAllJobKindsRescuable(t *testing.T) {
	declared := kindLiteralsInPackage(t)
	rescuable := rescueRegistrations()

	for kind := range declared {
		assert.Contains(t, rescuable, kind,
			"job kind %q has no rescue-only registration; add rescueEntry for it in rescue.go", kind)
	}
	for kind := range rescuable {
		assert.Contains(t, declared, kind,
			"rescueRegistrations has %q but no Kind() method declares it", kind)
	}
}

// TestAddRescueOnlyWorkersSkipsRealRegistrations proves the fill-in never
// clobbers or panics over a real worker: a kind registered for real stays
// registered, and every other kind becomes known to the client.
func TestAddRescueOnlyWorkersSkipsRealRegistrations(t *testing.T) {
	workers := river.NewWorkers()
	river.AddWorker(workers, &ScanWorker{}) // real registration, kind "scan"

	require.NotPanics(t, func() { addRescueOnlyWorkers(workers) })

	// Every kind must now be taken: a fresh rescue registration errors as duplicate.
	for kind, reg := range rescueRegistrations() {
		err := reg.register(workers)
		require.Error(t, err, "kind %q was not registered by addRescueOnlyWorkers", kind)
		assert.True(t, strings.Contains(err.Error(), "already registered"),
			"unexpected error for kind %q: %v", kind, err)
	}
}

// TestRescueOnlyWorkerReportsRealTimeout pins the fix for the rescuer
// re-running long scans: River's JobRescuer leaves a running job alone while
// it is younger than its kind's Timeout, so a rescue-only registration must
// report the REAL worker's Timeout. With WorkerDefaults (Timeout 0) a
// worker-pod leader declared a 4h nuclei scan stuck at the 1h default
// RescueStuckJobsAfter and retried or discarded it mid-run.
func TestRescueOnlyWorkerReportsRealTimeout(t *testing.T) {
	regs := rescueRegistrations()
	want := map[string]time.Duration{
		ScanArgs{}.Kind():           ScanWorker{}.Timeout(nil),
		ScanProfileJobArgs{}.Kind(): ScanProfileWorker{}.Timeout(nil),
		ScanAssetArgs{}.Kind():      ScanAssetWorker{}.Timeout(nil),
		CorrelateArgs{}.Kind():      (&CorrelateWorker{}).Timeout(nil),
		RefreshOSVArgs{}.Kind():     OSVWorker{}.Timeout(nil),
		SyncConnectorArgs{}.Kind():  SyncWorker{}.Timeout(nil),
	}
	for kind, timeout := range want {
		require.Equal(t, timeout, regs[kind].timeout, "rescue-only %q must report its real worker's Timeout", kind)
	}

	// The two kinds that outlive River's default 1h rescue horizon: a
	// rescue-only registration reporting 0 for these is exactly the bug.
	for _, kind := range []string{ScanArgs{}.Kind(), ScanProfileJobArgs{}.Kind()} {
		require.Greater(t, regs[kind].timeout, time.Hour,
			"%q runs past River's default rescue horizon; its rescue-only Timeout must cover it", kind)
	}
}
