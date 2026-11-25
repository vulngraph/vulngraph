package checks

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestK8sNamespaceExemptionsAreDescribed: a check whose predicate reads a
// fixed namespace exemption names it in its Description, so a reader of its
// findings and of docs/cspm-coverage.md learns which namespaces it never
// grades. The test walks every Check literal in the package source and follows
// its Violates predicate through every package-level function it reaches, so a
// new check that skips system namespaces without the note fails here however
// many helpers stand between the predicate and the list. A check whose assets
// the collector never produces in some namespaces (collectorExempt) carries
// that list's note the same way.
func TestK8sNamespaceExemptionsAreDescribed(t *testing.T) {
	noteFor := map[string]string{
		"isK8sSystemPod":                    "k8sSystemPodNote",
		"k8sSystemNamespaces":               "k8sSystemNamespaceNote",
		"k8sNetworkPolicyExemptNamespaces":  "k8sNetworkPolicyNote",
		"k8sResourceLimitsExemptNamespaces": "k8sResourceLimitsExemptNote",
		"k8sConfigMapSkippedNamespaces":     "k8sConfigMapSkippedNote",
	}
	collectorExempt := map[string]string{
		"k8s-configmap-plaintext-secret": "k8sConfigMapSkippedNote",
	}
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	fset := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{}
	var parsed []*ast.File
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		require.NoError(t, err)
		parsed = append(parsed, af)
		for _, d := range af.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
				funcs[fd.Name.Name] = fd
			}
		}
	}
	idents := func(n ast.Node) map[string]bool {
		out := map[string]bool{}
		if n == nil {
			return out
		}
		ast.Inspect(n, func(x ast.Node) bool {
			if id, ok := x.(*ast.Ident); ok {
				out[id.Name] = true
			}
			return true
		})
		return out
	}
	// reaches is idents closed over the package-level functions n refers to,
	// directly or through other helpers.
	reaches := func(n ast.Node) map[string]bool {
		out := idents(n)
		queue := make([]string, 0, len(out))
		for name := range out {
			queue = append(queue, name)
		}
		visited := map[string]bool{}
		for len(queue) > 0 {
			name := queue[0]
			queue = queue[1:]
			fd := funcs[name]
			if fd == nil || visited[name] {
				continue
			}
			visited[name] = true
			for id := range idents(fd.Body) {
				if !out[id] {
					out[id] = true
					queue = append(queue, id)
				}
			}
		}
		return out
	}

	described := 0
	for _, af := range parsed {
		ast.Inspect(af, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if id, ok := cl.Type.(*ast.Ident); !ok || id.Name != "Check" {
				return true
			}
			var checkID string
			var violates, desc ast.Expr
			for _, e := range cl.Elts {
				kv, ok := e.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				switch kv.Key.(*ast.Ident).Name {
				case "ID":
					if lit, ok := kv.Value.(*ast.BasicLit); ok {
						checkID, _ = strconv.Unquote(lit.Value)
					}
				case "Violates":
					violates = kv.Value
				case "Description":
					desc = kv.Value
				}
			}
			reads := reaches(violates)
			descIdents := idents(desc)
			want := collectorExempt[checkID]
			for _, list := range []string{"isK8sSystemPod", "k8sSystemNamespaces", "k8sNetworkPolicyExemptNamespaces", "k8sResourceLimitsExemptNamespaces"} {
				if reads[list] {
					want = noteFor[list]
					break
				}
			}
			for _, note := range noteFor {
				if note == want {
					require.Truef(t, descIdents[note], "%s reads a namespace exemption; its Description must end with %s", checkID, note)
					described++
				} else {
					require.Falsef(t, descIdents[note], "%s carries %s but its predicate does not apply that exemption", checkID, note)
				}
			}
			return true
		})
	}
	require.Equal(t, 21, described, "a namespace-exempt check was added or removed: update this count")
}

func TestK8sNamespaceExemptionNotes(t *testing.T) {
	require.Equal(t,
		" Not evaluated in the namespaces calico-system, cert-manager, datadog, falco, gke-system, gmp-public, gmp-system, istio-system, kube-node-lease, kube-public, kube-system and monitoring, or in a namespace labelled pod-security.kubernetes.io/enforce=privileged.",
		k8sSystemPodNote)
	require.Equal(t,
		" Not evaluated in the namespaces calico-system, cert-manager, gke-system, kube-system and monitoring.",
		exemptionNote(map[string]bool{"kube-system": true, "monitoring": true, "cert-manager": true, "gke-system": true, "calico-system": true}, false))

	byNote := map[string][]string{}
	for _, e := range K8sNamespaceExemptions() {
		require.NotEmpty(t, e.CheckIDs, "an exemption no registered check applies is dead")
		byNote[strings.Join(e.Namespaces, ",")+strconv.FormatBool(e.PrivilegedLabel)] = e.CheckIDs
	}
	pod := byNote[strings.Join(sortedNames(k8sSystemNamespaces), ",")+"true"]
	require.Contains(t, pod, "k8s-privileged-container")
	require.Contains(t, pod, "k8s-host-network-pod")
	require.NotContains(t, pod, "k8s-namespace-no-pod-security-enforcement")
	ns := byNote[strings.Join(sortedNames(k8sSystemNamespaces), ",")+"false"]
	require.ElementsMatch(t, []string{"k8s-default-sa-automount", "k8s-namespace-no-default-deny", "k8s-namespace-no-pod-security-enforcement"}, ns)
	require.Equal(t, []string{"k8s-namespace-no-network-policy"}, byNote[strings.Join(sortedNames(k8sNetworkPolicyExemptNamespaces), ",")+"false"])
	require.Equal(t, []string{"k8s-pod-no-resource-limits"}, byNote[strings.Join(sortedNames(k8sResourceLimitsExemptNamespaces), ",")+"false"])
	require.Equal(t, []string{"k8s-configmap-plaintext-secret"}, byNote[strings.Join(sortedNames(k8sConfigMapSkippedNamespaces), ",")+"false"])
}
