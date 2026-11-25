// Package coveragedoc assembles docs/cspm-coverage.md from the benchmark
// matrices, their recorded upstream snapshots, the framework mappings and the
// check registry's fixed Kubernetes namespace exemptions.
package coveragedoc

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/checks/benchmarks"
	"github.com/vulngraph/vulngraph/internal/checks/frameworks"
)

// Path is the document, relative to the repository root.
const Path = "docs/cspm-coverage.md"

// Render loads everything the document reads, relative to the repository
// root at root, and renders it. Deterministic: the committed file is
// compared against it, so a matrix or mapping edit that forgets to
// regenerate fails CI.
func Render(root string) (string, error) {
	bs, err := benchmarks.Load()
	if err != nil {
		return "", fmt.Errorf("Render: %w", err)
	}
	for _, b := range bs {
		if err := benchmarks.Validate(b); err != nil {
			return "", fmt.Errorf("Render: %w", err)
		}
	}
	snaps, err := benchmarks.ReadSnapshots(filepath.Join(root, benchmarks.SnapshotDir))
	if err != nil {
		return "", fmt.Errorf("Render: %w", err)
	}
	fws, err := frameworks.Load()
	if err != nil {
		return "", fmt.Errorf("Render: %w", err)
	}
	return benchmarks.RenderSummary(bs, snaps) + frameworks.RenderCoverage(fws, bs) +
		renderK8sExemptions(checks.K8sNamespaceExemptions()) + benchmarks.RenderGaps(bs), nil
}

// renderK8sExemptions lists the namespaces each Kubernetes check never
// evaluates: a benchmark control marked covered is not graded there.
func renderK8sExemptions(es []checks.K8sNamespaceExemption) string {
	var w strings.Builder
	w.WriteString("\n## Kubernetes namespace exemptions\n\n")
	w.WriteString("These Kubernetes checks skip fixed namespace lists, set in code and not configurable. ")
	w.WriteString("Nothing is reported for a resource in an exempt namespace, so a benchmark control marked covered ")
	w.WriteString("above is not graded there. Each check's description, shown on its findings, names its list.\n\n")
	w.WriteString("| Applies to | Namespaces never evaluated | Why | Checks |\n|---|---|---|---|\n")
	for _, e := range es {
		ns := code(e.Namespaces)
		if e.PrivilegedLabel {
			ns += ", and any namespace labelled `pod-security.kubernetes.io/enforce=privileged`"
		}
		fmt.Fprintf(&w, "| %s | %s | %s | %s |\n", e.Scope, ns, e.Reason, code(e.CheckIDs))
	}
	return w.String()
}

func code(xs []string) string { return "`" + strings.Join(xs, "`, `") + "`" }
