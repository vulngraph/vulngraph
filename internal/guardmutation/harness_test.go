//go:build guardmutation

// The mutation driver. Build-tagged because it EDITS FILES IN THE WORKING TREE:
// it must never run as a side effect of `go test ./...`, and it must never run
// concurrently with itself. The inventory check that keeps the catalogue honest
// is untagged and lives in inventory_test.go.
//
// Run it with:
//
//	go test -tags=guardmutation ./internal/guardmutation -run TestGuardsBite -v -timeout 40m
//
// CI splits the catalogue across parallel jobs with GUARD_SHARD=K/N (see shard_test.go).

package guardmutation

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// guardTimeout bounds one `go test -run '^TestX$'` invocation. Cold cgo builds
// of the graphstore tree dominate it.
const guardTimeout = 10 * time.Minute

// TestGuardsBite is the audit: for every catalogued guard, reintroduce the bug
// it exists to prevent and require the guard to FAIL.
//
// A guard that stays green under its own mutation is a defect, and it is
// reported as one — with the mutation that survived — rather than skipped.
func TestGuardsBite(t *testing.T) {
	root := moduleRoot(t)
	// Not "the tree is clean" — unrelated work may legitimately be in progress
	// in the checkout. The invariant is that
	// this run changes NOTHING: the set of dirty paths must be identical either
	// side of it.
	targets := map[string]bool{}
	for _, m := range mutations {
		targets[m.File] = true
	}
	before := treeState(t, root, targets)
	t.Cleanup(func() {
		require.Equalf(t, before, treeState(t, root, targets),
			"the mutation run changed the working tree — restore before trusting any result")
	})

	// A guard that is ALREADY red proves nothing when it goes red under
	// mutation, so establish the baseline once per guard first.
	shardK, shardN := shardFromEnv(t)
	baseline := map[string]bool{}
	for i, m := range mutations {
		if !inShard(i, shardK, shardN) {
			continue
		}
		key := m.Pkg + " " + m.Guard
		if baseline[key] {
			continue
		}
		res := runGuard(t, root, m.Pkg, m.Guard)
		require.Truef(t, res.passed,
			"baseline: %s is not green on the unmutated tree, so its behaviour under mutation means nothing:\n%s",
			m.Guard, res.output)
		baseline[key] = true
	}

	var toothless []string
	for i, m := range mutations {
		if !inShard(i, shardK, shardN) {
			continue
		}
		t.Run(m.Guard, func(t *testing.T) {
			restore := applyMutation(t, root, m)
			res := runGuard(t, root, m.Pkg, m.Guard)
			restore()

			// A mutation may break the build of a package the guard only parses
			// as text; it must never break the guard's own package, or a red
			// run would be a compile error rather than the guard biting.
			require.Falsef(t, res.buildFailed,
				"%s: the mutation broke the build of the guard's OWN package, so this run proves nothing "+
					"about the guard. Rewrite the mutation to keep %s compiling.\n%s", m.Guard, m.Pkg, res.output)

			if res.passed {
				toothless = append(toothless, fmt.Sprintf("%s (%s) — survived: %s", m.Guard, m.Pkg, m.Why))
				t.Errorf("GUARD DOES NOT BITE: %s stayed GREEN with its own bug reintroduced.\n"+
					"  mutation: %s\n    %q\n  →  %q\n  bug: %s\n"+
					"This guard is decoration. Fix it so this mutation fails it.",
					m.Guard, m.File, m.Old, m.New, m.Why)
				return
			}
			t.Logf("bites: %s fails when %s is mutated (%s)", m.Guard, m.File, m.Why)
		})
	}
	if len(toothless) > 0 {
		t.Logf("guards that did NOT bite:\n  %s", strings.Join(toothless, "\n  "))
	}
}

// applyMutation writes the mutated file and returns a restore func that puts
// the original bytes back and VERIFIES it, failing the whole run if it cannot.
//
// Restoration is the part that must not be trusted to convention: a `cp` that
// prompts, a partial write, or a mutation applied twice all leave the
// repository corrupted in a way the next test would silently inherit. So:
// original bytes are held in memory AND written to a uniquely-named backup
// outside the tree; the restore re-reads from disk and compares byte-for-byte;
// the backup is only removed once that comparison passes. It is also registered
// with t.Cleanup, so a panic or a failed require still restores.
func applyMutation(t *testing.T, root string, m Mutation) func() {
	t.Helper()
	path := filepath.Join(root, m.File)

	original, err := os.ReadFile(path)
	require.NoErrorf(t, err, "reading %s", m.File)
	info, err := os.Stat(path)
	require.NoError(t, err)

	require.Equalf(t, 1, strings.Count(string(original), m.Old),
		"mutation for %s must match %s exactly once — refusing to touch the file", m.Guard, m.File)

	backup := filepath.Join(t.TempDir(),
		fmt.Sprintf("%s.%d.%d.orig", strings.ReplaceAll(m.File, string(filepath.Separator), "_"), os.Getpid(), time.Now().UnixNano()))
	require.NoError(t, os.WriteFile(backup, original, 0o600))

	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		if werr := os.WriteFile(path, original, info.Mode().Perm()); werr != nil {
			t.Fatalf("RESTORE FAILED for %s: %v — original bytes are at %s", m.File, werr, backup)
		}
		back, rerr := os.ReadFile(path)
		if rerr != nil || string(back) != string(original) {
			t.Fatalf("RESTORE UNVERIFIED for %s (read err %v) — the tree is corrupt; original bytes are at %s",
				m.File, rerr, backup)
		}
		_ = os.Remove(backup)
	}
	t.Cleanup(restore)

	mutated := strings.Replace(string(original), m.Old, m.New, 1)
	require.NoError(t, os.WriteFile(path, []byte(mutated), info.Mode().Perm()))
	return restore
}

type guardResult struct {
	passed      bool
	buildFailed bool
	output      string
}

// runGuard runs exactly one test function in one package. Only that test is
// run: the full suite per mutation would take hours, and a guard's verdict is
// the only thing this harness is asking about.
func runGuard(t *testing.T, root, pkg, guard string) guardResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), guardTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "test", pkg, "-run", "^"+guard+"$", "-count=1")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	text := string(out)

	res := guardResult{output: text, passed: err == nil}
	switch {
	// A timeout is not a verdict. On a cold runner the first guard that links
	// liblbug can spend the whole budget building, and the empty output that
	// produces used to surface as "baseline is not green" — a slow build read as
	// a broken guard, which is exactly the misdiagnosis this harness exists to
	// prevent. Fail loudly and name the real cause instead.
	case ctx.Err() != nil:
		t.Fatalf("guard %s in %s exceeded %s. This is a BUILD timeout, not a guard verdict — "+
			"warm the build cache before the harness (see the CI job) or raise guardTimeout.\noutput:\n%s",
			guard, pkg, guardTimeout, text)
	case strings.Contains(text, "[build failed]"), strings.Contains(text, "[setup failed]"):
		res.buildFailed, res.passed = true, false
	case strings.Contains(text, "no tests to run"):
		t.Fatalf("`-run ^%s$` matched no test in %s — the guard was renamed or moved", guard, pkg)
	}
	return res
}

// treeState is the outer seatbelt: whatever the per-mutation restore believes,
// git is asked what the working tree actually looks like, before and after.
//
// Scoped to the files this harness touches, rather than the whole tree: a run
// takes minutes, other edits may happen in the checkout meanwhile, and
// an unrelated edit landing mid-run would fail the audit for a reason that has
// nothing to do with any guard.
func treeState(t *testing.T, root string, targets map[string]bool) string {
	t.Helper()
	cmd := exec.Command("git", "status", "--porcelain", "--untracked-files=all")
	cmd.Dir = root
	out, err := cmd.Output()
	require.NoError(t, err, "git status")

	var kept []string
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if len(line) < 4 {
			continue
		}
		if targets[strings.TrimSpace(line[3:])] {
			kept = append(kept, line)
		}
	}
	sort.Strings(kept)
	return strings.Join(kept, "\n")
}

// TestHarnessDetectsANonBitingGuard proves the harness itself works, against a
// tree it fully controls: a two-test fixture module where one guard genuinely
// asserts the invariant and one only pretends to. The harness must call the
// first a biter and the second toothless.
//
// Without this, "all guards bite" is indistinguishable from "the runner never
// noticed anything" — the exact failure mode this package exists to fix.
func TestHarnessDetectsANonBitingGuard(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}
	write("go.mod", "module guardfixture\n\ngo 1.26\n")
	write("registry.go", "package guardfixture\n\nvar Tables = []string{\"assets\", \"findings\"}\n")
	write("registry_test.go", `package guardfixture

import "testing"

// A real guard: every table must be known.
func TestTablesAreKnown(t *testing.T) {
	known := map[string]bool{"assets": true, "findings": true}
	for _, tbl := range Tables {
		if !known[tbl] {
			t.Fatalf("unknown table %q", tbl)
		}
	}
}

// A toothless guard, named for the same invariant, asserting something else —
// the shape both real regressions in this repo took.
func TestTablesAreKnownButChecksNothing(t *testing.T) {
	if len(Tables) == 0 {
		t.Fatal("no tables")
	}
}
`)

	mut := Mutation{
		File: "registry.go",
		Old:  "\"assets\", \"findings\"",
		New:  "\"assets\", \"fndings\"",
	}
	for _, tc := range []struct {
		guard    string
		wantBite bool
	}{
		{"TestTablesAreKnown", true},
		{"TestTablesAreKnownButChecksNothing", false},
	} {
		t.Run(tc.guard, func(t *testing.T) {
			m := mut
			m.Guard = tc.guard
			restore := applyMutation(t, dir, m)
			res := runGuard(t, dir, ".", tc.guard)
			restore()

			require.False(t, res.buildFailed, res.output)
			require.Equalf(t, tc.wantBite, !res.passed,
				"harness misclassified %s:\n%s", tc.guard, res.output)
		})
	}
}

// shardFromEnv is what the harness calls; a bad value fails the run loudly
// instead of silently auditing nothing.
func shardFromEnv(t *testing.T) (k, n int) {
	t.Helper()
	k, n, err := parseShard(os.Getenv(shardEnv))
	require.NoError(t, err)
	return k, n
}
