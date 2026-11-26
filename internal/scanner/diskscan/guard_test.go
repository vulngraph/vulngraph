package diskscan

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// mutatingVerb matches the method names that change cloud state. SDK
// operations are verb+noun (CreateSnapshot, BeginGrantAccess), so a bare verb
// such as aws.Config.Copy or ticker.Stop is not one.
var mutatingVerb = regexp.MustCompile(`^((Create|Delete|Put|Modify|Update|Attach|Detach|Insert|Set|Copy|Register|Deregister|Start|Stop|Terminate)[A-Z]|Begin(CreateOrUpdate|Delete|Grant|Revoke))`)

// cloudSDKPrefixes are the import paths of cloud client libraries.
var cloudSDKPrefixes = []string{
	"github.com/aws/aws-sdk-go-v2/service/",
	"github.com/Azure/azure-sdk-for-go/",
	"google.golang.org/api/",
	"cloud.google.com/go/",
}

// mutationAllowlist names every method call matching mutatingVerb that the
// scanned trees may make on a cloud client outside package snapshotter, as
// "<file path as walked from this directory>:<method>". Each entry must say why
// it is not a cloud mutation; a new entry is a review decision.
var mutationAllowlist = map[string]string{
	"../../collect/azure/vms.go:SetLimit": "errgroup.Group.SetLimit bounds local NIC lookup goroutines",
	"awsdisk/blocksource.go:SetLimit":     "errgroup.Group.SetLimit bounds local goroutines",
}

type parsedFile struct {
	path    string
	file    *ast.File
	imports map[string]string // local name -> import path
}

// parseTree parses every non-test Go file under root (relative to this
// package directory), skipping skipDir.
func parseTree(t *testing.T, root, skipDir string) []parsedFile {
	t.Helper()
	var out []parsedFile
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir != "" && filepath.Clean(path) == filepath.Clean(skipDir) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		imports := map[string]string{}
		for _, spec := range f.Imports {
			p, _ := strconv.Unquote(spec.Path.Value)
			name := filepath.Base(p)
			if spec.Name != nil {
				name = spec.Name.Name
			}
			imports[name] = p
		}
		out = append(out, parsedFile{path: filepath.ToSlash(path), file: f, imports: imports})
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, out, "no Go files under %s", root)
	return out
}

func importsCloudSDK(f parsedFile) bool {
	for _, p := range f.imports {
		for _, prefix := range cloudSDKPrefixes {
			if strings.HasPrefix(p, prefix) {
				return true
			}
		}
	}
	return false
}

// diskscanTrees are the trees whose cloud calls the guards constrain:
// everything under the engine except snapshotter/, and the collectors.
func diskscanTrees(t *testing.T) []parsedFile {
	t.Helper()
	files := parseTree(t, ".", "snapshotter")
	return append(files, parseTree(t, filepath.Join("..", "..", "collect"), "")...)
}

// TestSnapshotMutationAllowlist: outside package snapshotter, no file that
// imports a cloud SDK calls a method whose name is a mutating verb, unless
// the call is in the explicit allowlist.
func TestSnapshotMutationAllowlist(t *testing.T) {
	var violations []string
	for _, f := range diskscanTrees(t) {
		if !importsCloudSDK(f) {
			continue
		}
		ast.Inspect(f.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !mutatingVerb.MatchString(sel.Sel.Name) {
				return true
			}
			if _, allowed := mutationAllowlist[f.path+":"+sel.Sel.Name]; !allowed {
				violations = append(violations, f.path+":"+sel.Sel.Name)
			}
			return true
		})
	}
	sort.Strings(violations)
	require.Empty(t, dedupe(violations), "mutating cloud calls belong in package snapshotter; add to mutationAllowlist only with a reason")
}

// TestMutatingClientsOnlyInSnapshotter: outside package snapshotter, nothing
// under the diskscan tree (the collectors hold read clients for inventory and
// are covered by the allowlist guard) names a concrete cloud client that can
// mutate (ec2.Client, ebs.Client, ARM clients), and no interface declares a
// mutating method. Read-only providers take narrow interfaces.
func TestMutatingClientsOnlyInSnapshotter(t *testing.T) {
	var violations []string
	for _, f := range parseTree(t, ".", "snapshotter") {
		ast.Inspect(f.file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.SelectorExpr:
				id, ok := v.X.(*ast.Ident)
				if !ok {
					return true
				}
				pkg := f.imports[id.Name]
				if isConcreteMutatingClient(pkg, v.Sel.Name) {
					violations = append(violations, f.path+": concrete client "+id.Name+"."+v.Sel.Name)
				}
			case *ast.InterfaceType:
				for _, m := range v.Methods.List {
					for _, name := range m.Names {
						if mutatingVerb.MatchString(name.Name) && importsCloudSDK(f) {
							violations = append(violations, f.path+": interface method "+name.Name)
						}
					}
				}
			}
			return true
		})
	}
	sort.Strings(violations)
	require.Empty(t, dedupe(violations))
}

// isConcreteMutatingClient reports ec2.Client, ebs.Client and the Azure/GCP
// SDK client types, which expose Create/Delete/Begin* methods.
func isConcreteMutatingClient(importPath, name string) bool {
	switch {
	case importPath == "github.com/aws/aws-sdk-go-v2/service/ec2" || importPath == "github.com/aws/aws-sdk-go-v2/service/ebs":
		return name == "Client"
	case strings.HasPrefix(importPath, "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/"):
		return strings.HasSuffix(name, "Client") && !strings.HasSuffix(name, "ClientOptions")
	case importPath == "google.golang.org/api/compute/v1":
		return name == "Service" || name == "SnapshotsService" || name == "DisksService" || name == "InstancesService"
	}
	return false
}

func dedupe(in []string) []string {
	var out []string
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}
