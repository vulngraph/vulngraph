package upstream

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"github.com/vulngraph/vulngraph/internal/checks/benchmarks"
)

// Observation is one matrix's upstream as read from a bundle.
type Observation struct {
	Benchmark string
	// Source names the file(s) the IDs were read from.
	Source string
	Pinned string
	// SourceVersion is the version the IDs were read from: Pinned when the
	// upstream publishes it (Exact), else the nearest version below it.
	SourceVersion string
	Exact         bool
	// Latest is the newest version any upstream of this benchmark publishes.
	Latest   string
	Controls []Control
}

// IDs returns the observed control IDs.
func (o Observation) IDs() []string {
	out := make([]string, 0, len(o.Controls))
	for _, c := range o.Controls {
		out = append(out, c.ID)
	}
	return out
}

func has(b fs.FS, path string) bool {
	_, err := fs.Stat(b, path)
	return err == nil
}

func listing(b fs.FS, path string) ([]string, error) {
	raw, err := fs.ReadFile(b, path)
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", path, err)
	}
	names, err := githubListing(raw)
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", path, err)
	}
	return names, nil
}

// Wanted returns the bundle paths the diff (and, with frameworks, the
// framework-mapping generator) still needs, given what the bundle already
// holds. Directory listings come first; the files they make nameable are
// asked for on the next call, so a caller fetches until Wanted returns
// nothing. An unreadable listing is an error rather than a smaller plan.
func Wanted(b fs.FS, bs []benchmarks.Benchmark, frameworks bool) ([]string, error) {
	var want []string
	add := func(p string) {
		if !has(b, p) {
			want = append(want, p)
		}
	}
	for _, provider := range ProwlerProviders {
		idx := ProwlerIndexPath(provider)
		if !has(b, idx) {
			want = append(want, idx)
			continue
		}
		names, err := listing(b, idx)
		if err != nil {
			return nil, fmt.Errorf("Wanted: %w", err)
		}
		for _, f := range prowlerFilesWanted(provider, names, bs, frameworks) {
			add(ProwlerFilePath(provider, f))
		}
	}
	if !has(b, PathSecurityHubAPI) || frameworks {
		add(PathSecurityHubReference)
	}
	if frameworks && has(b, PathSecurityHubReference) {
		raw, err := fs.ReadFile(b, PathSecurityHubReference)
		if err != nil {
			return nil, fmt.Errorf("Wanted: %w", err)
		}
		for _, p := range securityHubPages(raw) {
			add(SecurityHubPagePath(p))
		}
	}
	if frameworks {
		add(PathNISTCatalog)
	}
	add(PathAzurePolicyIndex)
	kb, err := kubeBenchWanted(b, bs)
	if err != nil {
		return nil, fmt.Errorf("Wanted: %w", err)
	}
	for _, p := range kb {
		add(p)
	}
	sort.Strings(want)
	return want, nil
}

// prowlerFilesWanted: the pinned (or nearest) CIS file per matrix, plus,
// for framework generation, the FSBP JSON and every framework file mapped.
func prowlerFilesWanted(provider string, names []string, bs []benchmarks.Benchmark, frameworks bool) []string {
	var out []string
	for _, src := range Sources {
		if src.Kind != KindProwler || src.Provider != provider {
			continue
		}
		bm, ok := find(bs, src.Benchmark)
		if !ok {
			continue
		}
		vs := versionsMatching(names, prowlerCISPattern(provider))
		if v := nearestAtMost(keys(vs), bm.Version); v != "" {
			out = append(out, vs[v])
		}
	}
	if frameworks {
		for _, fw := range FrameworkSources {
			if f, ok := fw.Prowler[provider]; ok && contains(names, f) {
				out = append(out, f)
			}
		}
		if provider == "aws" && contains(names, prowlerFSBPFile) {
			out = append(out, prowlerFSBPFile)
		}
	}
	return out
}

func kubeBenchWanted(b fs.FS, bs []benchmarks.Benchmark) ([]string, error) {
	if !has(b, PathKubeBenchIndex) {
		return []string{PathKubeBenchIndex}, nil
	}
	dirs, err := listing(b, PathKubeBenchIndex)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, src := range Sources {
		if src.Kind != KindKubeBench {
			continue
		}
		bm, ok := find(bs, src.Benchmark)
		if !ok {
			continue
		}
		vs := versionsMatching(dirs, kubeBenchPattern(src.KubeBenchPrefix))
		v := nearestAtMost(keys(vs), bm.Version)
		if v == "" {
			continue
		}
		dir := vs[v]
		idx := KubeBenchDirIndexPath(dir)
		if !has(b, idx) {
			out = append(out, idx)
			continue
		}
		files, err := listing(b, idx)
		if err != nil {
			return nil, err
		}
		for _, f := range kubeBenchConfigFiles(files) {
			out = append(out, KubeBenchFilePath(dir, f))
		}
	}
	return out, nil
}

// Observe reads every matrix's upstream from a complete bundle.
func Observe(b fs.FS, bs []benchmarks.Benchmark) ([]Observation, error) {
	var out []Observation
	var errs []error
	for _, bm := range bs {
		src, ok := SourceFor(bm.ID)
		if !ok {
			errs = append(errs, fmt.Errorf("%s: no upstream source declared", bm.ID))
			continue
		}
		var o Observation
		var err error
		switch src.Kind {
		case KindProwler:
			o, err = observeProwler(b, src, bm)
		case KindKubeBench:
			o, err = observeKubeBench(b, src, bm)
		case KindSecurityHub:
			o, err = observeSecurityHub(b, bm)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", bm.ID, err))
			continue
		}
		out = append(out, o)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("Observe: %w", err)
	}
	return out, nil
}

func observeProwler(b fs.FS, src Source, bm benchmarks.Benchmark) (Observation, error) {
	names, err := listing(b, ProwlerIndexPath(src.Provider))
	if err != nil {
		return Observation{}, err
	}
	vs := versionsMatching(names, prowlerCISPattern(src.Provider))
	o := Observation{Benchmark: bm.ID, Pinned: bm.Version}
	all := keys(vs)
	if src.KubeBenchPrefix != "" {
		dirs, err := listing(b, PathKubeBenchIndex)
		if err != nil {
			return Observation{}, err
		}
		all = append(all, keys(versionsMatching(dirs, kubeBenchPattern(src.KubeBenchPrefix)))...)
	}
	if src.AzurePolicy {
		initiatives, err := listing(b, PathAzurePolicyIndex)
		if err != nil {
			return Observation{}, err
		}
		all = append(all, azurePolicyCISVersions(initiatives)...)
	}
	o.Latest = newest(append(all, bm.Version))
	v := nearestAtMost(keys(vs), bm.Version)
	if v == "" {
		return Observation{}, fmt.Errorf("prowler %s publishes no CIS version at or below %s", src.Provider, bm.Version)
	}
	file := ProwlerFilePath(src.Provider, vs[v])
	raw, err := fs.ReadFile(b, file)
	if err != nil {
		return Observation{}, err
	}
	f, err := decodeProwler(raw)
	if err != nil {
		return Observation{}, fmt.Errorf("%s: %w", file, err)
	}
	o.Source = "prowler " + src.Provider + "/" + vs[v]
	o.SourceVersion, o.Exact = v, sameVersion(v, bm.Version)
	for _, id := range prowlerIDs(f) {
		o.Controls = append(o.Controls, Control{ID: id})
	}
	return o, nil
}

func observeKubeBench(b fs.FS, src Source, bm benchmarks.Benchmark) (Observation, error) {
	dirs, err := listing(b, PathKubeBenchIndex)
	if err != nil {
		return Observation{}, err
	}
	vs := versionsMatching(dirs, kubeBenchPattern(src.KubeBenchPrefix))
	o := Observation{Benchmark: bm.ID, Pinned: bm.Version, Latest: newest(append(keys(vs), bm.Version))}
	v := nearestAtMost(keys(vs), bm.Version)
	if v == "" {
		return Observation{}, fmt.Errorf("kube-bench has no %s version at or below %s", src.KubeBenchPrefix, bm.Version)
	}
	dir := vs[v]
	files, err := listing(b, KubeBenchDirIndexPath(dir))
	if err != nil {
		return Observation{}, err
	}
	seen := map[string]bool{}
	for _, f := range kubeBenchConfigFiles(files) {
		raw, err := fs.ReadFile(b, KubeBenchFilePath(dir, f))
		if err != nil {
			return Observation{}, err
		}
		ids, err := kubeBenchIDs(raw)
		if err != nil {
			return Observation{}, fmt.Errorf("%s/%s: %w", dir, f, err)
		}
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				o.Controls = append(o.Controls, Control{ID: id})
			}
		}
	}
	if len(o.Controls) == 0 {
		return Observation{}, fmt.Errorf("kube-bench %s: no checks", dir)
	}
	o.Source = "kube-bench cfg/" + dir
	o.SourceVersion, o.Exact = v, sameVersion(v, bm.Version)
	return o, nil
}

// observeSecurityHub prefers the API listing (authoritative, current) and
// falls back to the controls reference page. FSBP has carried one version
// (1.0.0) since launch; controls are added to it in place.
func observeSecurityHub(b fs.FS, bm benchmarks.Benchmark) (Observation, error) {
	o := Observation{Benchmark: bm.ID, Pinned: bm.Version, SourceVersion: bm.Version, Exact: true, Latest: bm.Version}
	var err error
	if has(b, PathSecurityHubAPI) {
		raw, rerr := fs.ReadFile(b, PathSecurityHubAPI)
		if rerr != nil {
			return Observation{}, rerr
		}
		o.Controls, err = securityHubAPIControls(raw)
		o.Source = "securityhub ListSecurityControlDefinitions, FSBP standard"
	} else {
		raw, rerr := fs.ReadFile(b, PathSecurityHubReference)
		if rerr != nil {
			return Observation{}, rerr
		}
		o.Controls, err = securityHubReferenceFSBP(raw)
		o.Source = "securityhub controls reference, FSBP rows"
	}
	if err != nil {
		return Observation{}, err
	}
	return o, nil
}

func find(bs []benchmarks.Benchmark, id string) (benchmarks.Benchmark, bool) {
	for _, b := range bs {
		if b.ID == id {
			return b, true
		}
	}
	return benchmarks.Benchmark{}, false
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(names []string, n string) bool {
	for _, x := range names {
		if x == n {
			return true
		}
	}
	return false
}
