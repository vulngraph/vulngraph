package migrate

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/migrations"
)

const module = "github.com/vulngraph/vulngraph/"

// scannerSourcePkgs are the packages the walk reads: the scanner's entry
// point, its job workers, and every domain the scanner runs SQL through.
var scannerSourcePkgs = []string{
	"cmd/graph", "internal/jobs", "internal/migrate", "internal/app/asset",
	"internal/app/finding", "internal/app/enrichcache", "internal/app/explore", "internal/app/diskscan", "internal/db/sqlcgen",
}

// scannerOpaquePkgs are the module packages the scanner's code calls into
// that the walk does not read, with why they name no table. None but
// internal/db may import a datastore driver. Reaching any other unread
// module package fails the walk.
var scannerOpaquePkgs = map[string]string{
	"internal/db":  "the pools and the ClickHouse client; they run the SQL their callers pass",
	"internal/obs": "metrics and tracing",
	// The disk scan's cloud and disk code: no SQL, and no datastore import (checked above).
	"internal/app/diskscan/envelope":        "AES-GCM seal of the disk-scan credential envelope",
	"internal/scanner/diskscan":             "the disk reader and the opt-in check",
	"internal/scanner/diskscan/awsdisk":     "reads EBS snapshots over the AWS API",
	"internal/scanner/diskscan/azuredisk":   "reads Azure snapshots over SAS URLs",
	"internal/scanner/diskscan/snapshotter": "the only tagged-snapshot writer",
	"internal/scanner/pkginventory":         "package-database parsers and the CVE-gap rule",
	"internal/collect/aws":                  "AWS credential chain (BaseConfig)",
	"internal/intel/updateinfo":             "the advisory feeds' static source list, for the periodic schedule",
	"pkg/egress":                            "the egress switches",
	"pkg/envswitch":                         "environment flag parsing",
	"pkg/log":                               "logging",
}

// datastoreImports are the packages through which code reaches a datastore.
var datastoreImports = []string{
	"database/sql", "github.com/jackc/pgx/", "github.com/ClickHouse/clickhouse-go/", module + "internal/db",
}

// scannerUnwiredIfaces are the module interfaces the walk calls that nothing
// the scanner builds implements, with why. Any other such interface means
// the walk lost track of what implements it, and fails.
var scannerUnwiredIfaces = map[string]string{
	"internal/db/sqlcgen.DBTX": "the pgx pool or transaction sqlc's queries run on",
}

// scannerLibraryGrants are the scanner role's grants on tables only library
// code queries, which the walk cannot see: River's client (the scanner's job
// queue and, as leader, its maintenance) and the readiness wait's version
// reads (goose and rivermigrate).
var scannerLibraryGrants = map[string][]string{
	"goose_db_version": {"SELECT"},
	"river_migration":  {"SELECT"},
	"river_job":        {"DELETE", "INSERT", "SELECT", "UPDATE"},
	"river_leader":     {"DELETE", "INSERT", "SELECT", "UPDATE"},
	"river_queue":      {"DELETE", "INSERT", "SELECT", "UPDATE"},
	"river_job_id_seq": {"USAGE"},
}

// scannerCHLibraryGrants is the same for ClickHouse: goose's version read.
var scannerCHLibraryGrants = map[string][]string{"goose_db_version": {"SELECT"}}

// reach walks the code the scanner process can run, from cmd/graph.scanner:
// every function it calls or takes the value of, every method called on a
// concrete type, and, for a method called through one of the module's
// interfaces, that method on every type the walk has seen built that has the
// interface's methods. River calls Work on the workers registered with it,
// so a river.AddWorker call is walked into its worker's Work. It collects the
// strings those functions use, the package-level constants and variables
// included.
type reach struct {
	t       *testing.T
	pkgs    map[string]*types.Package
	funcs   map[string]funcSrc
	vars    map[string]funcSrc
	seen    map[string]bool
	queue   []string
	built   map[string]*types.Named
	ifaces  map[string]ifaceCall
	strs    []string
	unknown []string
	opaque  map[string]bool
}

type funcSrc struct {
	node ast.Node
	info *types.Info
}

type ifaceCall struct {
	methods  map[string]string // name: sigKey
	called   map[string]bool
	resolved bool
}

// srcPackage is one package as `go list` reports it.
type srcPackage struct {
	ImportPath string
	Dir        string
	Export     string
	GoFiles    []string
	Imports    []string
}

// loadScannerReach type-checks scannerSourcePkgs from source, with their
// imports from the export data `go list -export` builds (read by the
// toolchain's own importer, so it matches any Go version), and walks them.
func loadScannerReach(t *testing.T) *reach {
	t.Helper()
	args := []string{"list", "-export", "-deps", "-json=ImportPath,Dir,Export,GoFiles,Imports"}
	for _, p := range scannerSourcePkgs {
		args = append(args, module+p)
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = "../.."
	out, err := cmd.Output()
	require.NoError(t, err, "go list")
	exports := map[string]string{}
	listed := map[string]srcPackage{}
	for dec := json.NewDecoder(bytes.NewReader(out)); dec.More(); {
		var p srcPackage
		require.NoError(t, dec.Decode(&p))
		exports[p.ImportPath] = p.Export
		listed[p.ImportPath] = p
	}
	for rel := range scannerOpaquePkgs {
		lp, ok := listed[module+rel]
		if !ok || rel == "internal/db" {
			continue
		}
		for _, imp := range lp.Imports {
			for _, ds := range datastoreImports {
				require.False(t, strings.HasPrefix(imp, ds), "%s imports %s: the walk must read it, not skip it", rel, imp)
			}
		}
	}
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		return os.Open(exports[path])
	})

	r := &reach{
		t: t, pkgs: map[string]*types.Package{}, funcs: map[string]funcSrc{}, vars: map[string]funcSrc{},
		seen: map[string]bool{}, built: map[string]*types.Named{}, ifaces: map[string]ifaceCall{},
		opaque: map[string]bool{},
	}
	for _, rel := range scannerSourcePkgs {
		lp, ok := listed[module+rel]
		require.True(t, ok, rel)
		var files []*ast.File
		for _, name := range lp.GoFiles {
			f, err := parser.ParseFile(fset, filepath.Join(lp.Dir, name), nil, parser.SkipObjectResolution)
			require.NoError(t, err)
			files = append(files, f)
		}
		info := &types.Info{
			Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{},
			Uses: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{},
		}
		pkg, err := (&types.Config{Importer: imp}).Check(lp.ImportPath, fset, files, info)
		require.NoError(t, err, rel)
		r.pkgs[lp.ImportPath] = pkg
		for _, f := range files {
			for _, d := range f.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					if fn, ok := info.Defs[d.Name].(*types.Func); ok {
						r.funcs[funcKey(fn)] = funcSrc{node: d, info: info}
					}
				case *ast.GenDecl:
					for _, s := range d.Specs {
						if vs, ok := s.(*ast.ValueSpec); ok && d.Tok == token.VAR {
							for _, n := range vs.Names {
								r.vars[lp.ImportPath+"."+n.Name] = funcSrc{node: vs, info: info}
							}
						}
					}
				}
			}
		}
	}
	entry, ok := r.pkgs[module+"cmd/graph"].Scope().Lookup("scanner").(*types.Func)
	require.True(t, ok, "cmd/graph.scanner")
	r.visit(entry)
	for len(r.queue) > 0 {
		key := r.queue[0]
		r.queue = r.queue[1:]
		r.walk(r.funcs[key])
	}
	return r
}

// funcKey names a function the same way from any package's view of it:
// "pkg.Func" or "pkg.Type.Method".
func funcKey(fn *types.Func) string {
	fn = fn.Origin()
	sig, _ := fn.Type().(*types.Signature)
	if sig == nil || sig.Recv() == nil {
		return fn.Pkg().Path() + "." + fn.Name()
	}
	if n := namedOf(sig.Recv().Type()); n != nil {
		return n.Obj().Pkg().Path() + "." + n.Obj().Name() + "." + fn.Name()
	}
	return fn.Pkg().Path() + ".?." + fn.Name()
}

func namedOf(t types.Type) *types.Named {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	n, _ := types.Unalias(t).(*types.Named)
	if n != nil {
		n = n.Origin()
	}
	return n
}

func inModule(path string) bool { return strings.HasPrefix(path, module) }

// visit queues fn's body, or records it as unread when it is module code
// the walk has no source for.
func (r *reach) visit(fn *types.Func) {
	if fn.Pkg() == nil {
		return
	}
	key := funcKey(fn)
	if r.seen[key] {
		return
	}
	r.seen[key] = true
	if _, ok := r.funcs[key]; ok {
		r.queue = append(r.queue, key)
		return
	}
	pkg := fn.Pkg().Path()
	if !inModule(pkg) {
		return
	}
	if _, ok := scannerOpaquePkgs[strings.TrimPrefix(pkg, module)]; ok {
		r.opaque[strings.TrimPrefix(pkg, module)] = true
		return
	}
	if _, ok := r.pkgs[pkg]; ok {
		r.t.Errorf("no source for %s, in a package the walk reads", key)
		return
	}
	r.unknown = append(r.unknown, key)
}

// build records that the scanner constructs t, and resolves the interface
// calls seen so far against it.
func (r *reach) build(t types.Type) {
	n := namedOf(t)
	if n == nil || n.Obj().Pkg() == nil || !inModule(n.Obj().Pkg().Path()) || types.IsInterface(n) {
		return
	}
	key := n.Obj().Pkg().Path() + "." + n.Obj().Name()
	if _, ok := r.built[key]; ok {
		return
	}
	if p, ok := r.pkgs[n.Obj().Pkg().Path()]; ok {
		if obj := p.Scope().Lookup(n.Obj().Name()); obj != nil {
			if src, ok := obj.Type().(*types.Named); ok {
				n = src
			}
		}
	}
	r.built[key] = n
	ms := methodsOf(n)
	for k, c := range r.ifaces {
		r.ifaces[k] = r.resolve(c, ms)
	}
}

func methodsOf(n *types.Named) map[string]*types.Func {
	ms := types.NewMethodSet(types.NewPointer(n))
	out := make(map[string]*types.Func, ms.Len())
	for i := range ms.Len() {
		if fn, ok := ms.At(i).Obj().(*types.Func); ok {
			out[fn.Name()] = fn
		}
	}
	return out
}

// sigKey is fn's signature without parameter names, the same from any
// package's view of it.
func sigKey(fn *types.Func) string {
	sig := fn.Type().(*types.Signature)
	var b strings.Builder
	for _, tuple := range []*types.Tuple{sig.Params(), sig.Results()} {
		b.WriteString("(")
		for i := range tuple.Len() {
			b.WriteString(types.TypeString(tuple.At(i).Type(), nil) + ",")
		}
		b.WriteString(")")
	}
	if sig.Variadic() {
		b.WriteString("...")
	}
	return b.String()
}

// resolve visits every called method of c on a type that has all of c's
// methods, with their signatures.
func (r *reach) resolve(c ifaceCall, ms map[string]*types.Func) ifaceCall {
	for name, sig := range c.methods {
		if fn, ok := ms[name]; !ok || sigKey(fn) != sig {
			return c
		}
	}
	c.resolved = true
	for m := range c.called {
		r.visit(ms[m])
	}
	return c
}

// calleeOf returns the function a call's Fun names, through a generic
// instantiation, or nil for a call of a value.
func calleeOf(info *types.Info, fun ast.Expr) *types.Func {
	switch f := fun.(type) {
	case *ast.IndexExpr:
		return calleeOf(info, f.X)
	case *ast.IndexListExpr:
		return calleeOf(info, f.X)
	case *ast.SelectorExpr:
		fn, _ := info.Uses[f.Sel].(*types.Func)
		return fn
	case *ast.Ident:
		fn, _ := info.Uses[f].(*types.Func)
		return fn
	}
	return nil
}

// registerWorker visits the Work method River calls on a worker the scanner
// registers.
func (r *reach) registerWorker(t types.Type) {
	n := namedOf(t)
	require.NotNil(r.t, n, "a worker of unnamed type %s", t)
	fn, ok := methodsOf(n)["Work"]
	require.True(r.t, ok, "%s has no Work method", n)
	r.visit(fn)
}

// callIface records a call of fn through the interface type recv (a named
// or literal interface, or a type parameter's constraint) and visits fn on
// every type built so far that has all of recv's methods.
func (r *reach) callIface(recv types.Type, fn *types.Func) {
	if fn.Pkg() == nil || !inModule(fn.Pkg().Path()) {
		if n := namedOf(recv); n == nil || n.Obj().Pkg() == nil || !inModule(n.Obj().Pkg().Path()) {
			return
		}
	}
	key := types.TypeString(recv, nil)
	c, ok := r.ifaces[key]
	if !ok {
		it := recv.Underlying().(*types.Interface)
		c.called, c.methods = map[string]bool{}, map[string]string{}
		for i := range it.NumMethods() {
			c.methods[it.Method(i).Name()] = sigKey(it.Method(i))
		}
	}
	if c.called[fn.Name()] {
		return
	}
	c.called[fn.Name()] = true
	for _, b := range r.built {
		c = r.resolve(c, methodsOf(b))
	}
	r.ifaces[key] = c
}

func (r *reach) walk(src funcSrc) {
	info := src.info
	ast.Inspect(src.node, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.BasicLit:
			if n.Kind == token.STRING {
				if s, err := strconv.Unquote(n.Value); err == nil {
					r.strs = append(r.strs, s)
				}
			}
		case *ast.CompositeLit:
			r.build(info.TypeOf(n))
		case *ast.CallExpr:
			if callee := calleeOf(info, n.Fun); callee != nil && callee.Pkg() != nil &&
				callee.Pkg().Path() == "github.com/riverqueue/river" && strings.HasPrefix(callee.Name(), "AddWorker") {
				r.registerWorker(info.TypeOf(n.Args[1]))
			}
			switch t := info.TypeOf(n).(type) {
			case *types.Tuple:
				for i := range t.Len() {
					r.build(t.At(i).Type())
				}
			case nil:
			default:
				r.build(t)
			}
		case *ast.SelectorExpr:
			sel, ok := info.Selections[n]
			if !ok || sel.Kind() == types.FieldVal {
				return true
			}
			fn := sel.Obj().(*types.Func)
			if recv := fn.Type().(*types.Signature).Recv(); types.IsInterface(sel.Recv()) || types.IsInterface(recv.Type()) {
				if !types.IsInterface(sel.Recv()) {
					r.callIface(recv.Type(), fn) // promoted from an embedded interface
				} else {
					r.callIface(sel.Recv(), fn)
				}
			} else {
				r.visit(fn)
			}
		case *ast.Ident:
			switch obj := info.Uses[n].(type) {
			case *types.Func:
				if obj.Type().(*types.Signature).Recv() == nil {
					r.visit(obj)
				}
			case *types.Const:
				if obj.Val().Kind() == constant.String {
					r.strs = append(r.strs, constant.StringVal(obj.Val()))
				}
			case *types.Var:
				if obj.Pkg() != nil && obj.Parent() == obj.Pkg().Scope() {
					key := obj.Pkg().Path() + "." + obj.Name()
					if !r.seen["var "+key] {
						r.seen["var "+key] = true
						if v, ok := r.vars[key]; ok {
							r.walk(v)
						}
					}
				}
			}
		}
		return true
	})
}

// The statement forms the code writes, each capturing the table it names,
// schema-qualified or not (a graph. prefix is dropped; any other schema, such
// as system., stays on the name).
var (
	sqlInsert   = regexp.MustCompile(`\bINSERT\s+INTO\s+((?:\w+\.)?\w+)`)
	sqlUpdate   = regexp.MustCompile(`\bUPDATE\s+((?:\w+\.)?\w+)\s+SET\b`)
	sqlDelete   = regexp.MustCompile(`\bDELETE\s+FROM\s+((?:\w+\.)?\w+)`)
	sqlRead     = regexp.MustCompile(`\b(?:FROM|JOIN)\s+((?:\w+\.)?\w+)`)
	sqlUpsert   = regexp.MustCompile(`\bON\s+CONFLICT\b[^;]*\bDO\s+UPDATE\b`)
	sqlReturns  = regexp.MustCompile(`\bRETURNING\b`)
	scannerOnPG = regexp.MustCompile(`^GRANT ([A-Z, ]+) ON (?:SEQUENCE )?([a-z_, ]+) TO graph_scanner$`)
	scannerOnCH = regexp.MustCompile(`^GRANT ([A-Z, ]+) ON graph\.([a-z_]+)$`)
	// A verb followed by no literal table name: a %s, a quoted name, or the
	// end of a literal that a + joins the table onto.
	sqlBuiltTable = regexp.MustCompile(`\b(?:FROM|JOIN|INTO|UPDATE)(?:\s*$|\s+[^\s\w(])`)
)

// tableUse is one privilege a statement needs on the table it names.
type tableUse struct{ table, priv string }

// tableUses returns the privileges statement s needs, on every table it
// names. A write that reads its target (WHERE, RETURNING) needs SELECT too,
// and an upsert's DO UPDATE needs UPDATE.
func tableUses(s string) []tableUse {
	var out []tableUse
	add := func(table, priv string) {
		out = append(out, tableUse{table: strings.TrimPrefix(table, "graph."), priv: priv})
	}
	for _, m := range sqlRead.FindAllStringSubmatch(s, -1) {
		add(m[1], "SELECT")
	}
	for _, m := range sqlInsert.FindAllStringSubmatch(s, -1) {
		add(m[1], "INSERT")
		if sqlUpsert.MatchString(s) {
			add(m[1], "UPDATE")
		}
		if sqlReturns.MatchString(s) {
			add(m[1], "SELECT")
		}
	}
	for _, m := range sqlUpdate.FindAllStringSubmatch(s, -1) {
		add(m[1], "UPDATE")
		add(m[1], "SELECT")
	}
	for _, m := range sqlDelete.FindAllStringSubmatch(s, -1) {
		add(m[1], "DELETE")
	}
	return out
}

// privileges returns the privileges the statements in strs need on tables,
// the tables of one datastore.
func privileges(strs []string, tables map[string]bool) map[string][]string {
	out := map[string][]string{}
	for _, s := range strs {
		for _, u := range tableUses(s) {
			if tables[u.table] && !slices.Contains(out[u.table], u.priv) {
				out[u.table] = append(out[u.table], u.priv)
			}
		}
	}
	for k := range out {
		slices.Sort(out[k])
	}
	return out
}

// unreadTables returns what the statements in strs name that is in none of
// known (a system table, a table no migration creates), and the statements
// whose table is built at run time. privileges grants neither, so a scanner
// that ran them would be refused at run time while its grants looked right.
func unreadTables(strs []string, known ...map[string]bool) []string {
	var out []string
	for _, s := range strs {
		if sqlBuiltTable.MatchString(s) {
			out = append(out, "a table built at run time: "+s)
		}
	uses:
		for _, u := range tableUses(s) {
			for _, k := range known {
				if k[u.table] {
					continue uses
				}
			}
			out = append(out, u.table+": "+s)
		}
	}
	return out
}
func grantedTo(t *testing.T, grants []string, re *regexp.Regexp) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, g := range grants {
		m := re.FindStringSubmatch(g)
		require.NotNil(t, m, "unparsed grant %q", g)
		for _, table := range strings.Split(m[2], ",") {
			for _, priv := range strings.Split(m[1], ",") {
				out[strings.TrimSpace(table)] = append(out[strings.TrimSpace(table)], strings.TrimSpace(priv))
			}
		}
	}
	for k := range out {
		slices.Sort(out[k])
	}
	return out
}

var migrationCreates = regexp.MustCompile(
	`(?m)^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:TABLE|(?:MATERIALIZED\s+)?VIEW|DICTIONARY)\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:graph\.)?([a-z_0-9]+)`)

// migrationTables returns the tables, views and dictionaries every migration
// in migrations/<dir> creates.
func migrationTables(t *testing.T, dir string) map[string]bool {
	t.Helper()
	return createdIn(t, migrations.FS, dir)
}

func createdIn(t *testing.T, fsys fs.FS, dir string) map[string]bool {
	t.Helper()
	files, err := fs.Glob(fsys, dir+"/*.sql")
	require.NoError(t, err)
	require.NotEmpty(t, files, dir)
	out := map[string]bool{}
	for _, f := range files {
		body, err := fs.ReadFile(fsys, f)
		require.NoError(t, err)
		for _, m := range migrationCreates.FindAllStringSubmatch(string(body), -1) {
			out[m[1]] = true
		}
	}
	require.NotEmpty(t, out, dir)
	return out
}

func withLibrary(derived, library map[string][]string) map[string][]string {
	out := map[string][]string{}
	for _, m := range []map[string][]string{derived, library} {
		for table, privs := range m {
			for _, p := range privs {
				if !slices.Contains(out[table], p) {
					out[table] = append(out[table], p)
				}
			}
		}
	}
	for k := range out {
		slices.Sort(out[k])
	}
	return out
}

// The scanner's datastore users hold exactly what the code the scanner pod
// can run needs: the walk from its entry point finds every table its
// statements read or write, on Postgres and on ClickHouse, and the grants of
// scannerGrants and of graph_scanner in clickhouse-users.xml must match it.
// A table joined into a query the scanner runs, or a new call from a scan
// worker into another domain, changes what the walk finds, and fails here
// until the grants follow (or the call goes).
func TestScannerGrantsMatchWhatTheScannerRuns(t *testing.T) {
	r := loadScannerReach(t)
	require.Empty(t, r.unknown, "the scanner reaches module code the walk does not read: add its package to scannerSourcePkgs, "+
		"or to scannerOpaquePkgs if it names no table")
	for rel := range scannerOpaquePkgs {
		require.True(t, r.opaque[rel], "stale scannerOpaquePkgs entry %s: the scanner does not reach it", rel)
	}
	var unwired []string
	for name, c := range r.ifaces {
		if !c.resolved {
			if _, ok := scannerUnwiredIfaces[strings.TrimPrefix(name, module)]; !ok {
				unwired = append(unwired, name)
			}
		}
	}
	slices.Sort(unwired)
	require.Empty(t, unwired, "interfaces the scanner calls that nothing it builds implements: "+
		"the walk lost their implementation, or list them in scannerUnwiredIfaces with why")
	for name := range scannerUnwiredIfaces {
		c, ok := r.ifaces[module+name]
		require.True(t, ok && !c.resolved, "stale scannerUnwiredIfaces entry %s", name)
	}
	for _, key := range []string{
		module + "internal/jobs.DiskScanVolumeWorker.Work",
	} {
		require.True(t, r.seen[key], "the walk missed %s: it is broken", key)
	}

	pgTables, chTables := migrationTables(t, "postgres"), migrationTables(t, "clickhouse")
	require.Empty(t, unreadTables(r.strs, pgTables, chTables),
		"statements the scanner runs on tables the grants below cannot follow: grant the scanner what they need "+
			"(and teach privileges to read it), or keep the table a literal the migrations create")

	pgWant := withLibrary(privileges(r.strs, pgTables), scannerLibraryGrants)
	require.Equal(t, pgWant, grantedTo(t, scannerGrants, scannerOnPG), "scannerGrants")

	raw, err := os.ReadFile("../../deploy/helm-chart/graph/files/clickhouse-users.xml")
	require.NoError(t, err)
	var u struct {
		Grants []string `xml:"users>graph_scanner>grants>query"`
	}
	require.NoError(t, xml.Unmarshal(raw, &u))
	chWant := withLibrary(privileges(r.strs, chTables), scannerCHLibraryGrants)
	require.Equal(t, chWant, grantedTo(t, u.Grants, scannerOnCH), "graph_scanner in clickhouse-users.xml")
}

// privileges reads the statement forms the code writes.
func TestPrivilegesReadsEveryForm(t *testing.T) {
	tables := map[string]bool{"a": true, "b": true, "c": true}
	for _, tc := range []struct {
		sql  string
		want map[string][]string
	}{
		{"SELECT x FROM a JOIN b ON a.id = b.id", map[string][]string{"a": {"SELECT"}, "b": {"SELECT"}}},
		{"INSERT INTO graph.a (x) VALUES (?)", map[string][]string{"a": {"INSERT"}}},
		{"INSERT INTO a (x) VALUES ($1) ON CONFLICT (x) DO UPDATE SET x = EXCLUDED.x RETURNING id",
			map[string][]string{"a": {"INSERT", "SELECT", "UPDATE"}}},
		{"INSERT INTO a (x) VALUES ($1) ON CONFLICT DO NOTHING", map[string][]string{"a": {"INSERT"}}},
		{"UPDATE a SET x = 1 WHERE id = $1", map[string][]string{"a": {"SELECT", "UPDATE"}}},
		{"DELETE FROM c WHERE id = $1", map[string][]string{"c": {"DELETE", "SELECT"}}},
		{"SELECT 1 FROM unknown_table", map[string][]string{}},
		{"SELECT 1 FROM system.a", map[string][]string{}},
		{"failed to read from a", map[string][]string{}},
	} {
		require.Equal(t, tc.want, privileges([]string{tc.sql}, tables), tc.sql)
	}
}

// What privileges cannot grant fails the walk: a table no migration
// creates, a system table, and a table filled in at run time.
func TestUnreadTablesFindsWhatTheGrantsCannotFollow(t *testing.T) {
	pg, ch := map[string]bool{"a": true}, map[string]bool{"b": true}
	for _, tc := range []struct {
		sql  string
		want []string
	}{
		{"SELECT x FROM a JOIN graph.b ON a.id = b.id", nil},
		{"INSERT INTO a (x) VALUES ($1) ON CONFLICT (x) DO UPDATE SET x = EXCLUDED.x", nil},
		{"SELECT x FROM (SELECT x FROM a) AS s", nil},
		{"SELECT 1 FROM c", []string{"c: SELECT 1 FROM c"}},
		{"SELECT sum(rows) FROM system.parts", []string{"system.parts: SELECT sum(rows) FROM system.parts"}},
		{"DELETE FROM graph.c WHERE 1", []string{"c: DELETE FROM graph.c WHERE 1", "c: DELETE FROM graph.c WHERE 1"}},
		{"SELECT x FROM %s WHERE id = ?", []string{"a table built at run time: SELECT x FROM %s WHERE id = ?"}},
		{"SELECT x FROM ", []string{"a table built at run time: SELECT x FROM "}},
		{"INSERT INTO \"a\" VALUES (1)", []string{"a table built at run time: INSERT INTO \"a\" VALUES (1)"}},
		{"failed to read from c", nil},
	} {
		require.Equal(t, tc.want, unreadTables([]string{tc.sql}, pg, ch), tc.sql)
	}
}

// The known tables are what every migration creates, not only the first.
func TestMigrationTablesReadsEveryMigration(t *testing.T) {
	fsys := fstest.MapFS{
		"pg/00001_init.sql": {Data: []byte("-- +goose Up\nCREATE TABLE a (\n  id int\n);\n")},
		"pg/00002_more.sql": {Data: []byte("-- +goose Up\nCREATE TABLE IF NOT EXISTS b (id int);\n" +
			"CREATE MATERIALIZED VIEW graph.c TO a AS SELECT 1;\n  CREATE VIEW d AS SELECT 1;\nCREATE DICTIONARY e (id UInt64);\n")},
		"pg/README.md": {Data: []byte("CREATE TABLE notes (id int);\n")},
	}
	require.Equal(t, map[string]bool{"a": true, "b": true, "c": true, "d": true, "e": true}, createdIn(t, fsys, "pg"))
	require.True(t, migrationTables(t, "postgres")["scan_runs"])
	require.True(t, migrationTables(t, "clickhouse")["findings"])
}
