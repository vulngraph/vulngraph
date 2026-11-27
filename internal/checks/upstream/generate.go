package upstream

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/vulngraph/vulngraph/internal/checks/benchmarks"
	"github.com/vulngraph/vulngraph/internal/checks/frameworks"
)

// frameworkMeta is the fixed header and ID grammar of each framework.
type frameworkMeta struct {
	name, version string
	sources       []string
	// id maps a Prowler requirement to its canonical requirement ID ("" to skip).
	id func(ProwlerRequirement) string
}

const prowlerAttribution = "Prowler compliance mappings (Apache-2.0, github.com/prowler-cloud/prowler), joined through Prowler's CIS and FSBP files"

var nistID = regexp.MustCompile(`^([A-Z]{2}-[0-9]+)(\([0-9]+\))?`)

// firstTok is the ID prefix of a Prowler Name ("CC6.1 …", "164.312(b) …").
func firstTok(r ProwlerRequirement) string {
	tok, _, _ := strings.Cut(strings.TrimSpace(r.Name), " ")
	return tok
}

var frameworkMetas = map[string]frameworkMeta{
	"nist-800-53-r5": {
		name: "NIST SP 800-53", version: "Rev. 5",
		sources: []string{prowlerAttribution, "AWS Security Hub FSBP related requirements (NIST.800-53.r5)", "NIST OSCAL SP 800-53 Rev. 5 catalog (titles, public domain)"},
		id: func(r ProwlerRequirement) string {
			if m := nistID.FindStringSubmatch(firstTok(r)); m != nil {
				return m[1] + m[2]
			}
			return ""
		},
	},
}

// GenerateFrameworks rebuilds every built-in framework mapping from a bundle
// fetched with frameworks enabled. A requirement the NIST catalog has no
// title for is an error naming it, never a placeholder title.
func GenerateFrameworks(b fs.FS, bs []benchmarks.Benchmark) ([]frameworks.Framework, error) {
	ix := frameworks.NewIndex(bs)
	byCheck, err := prowlerCheckRefs(b, bs, ix)
	if err != nil {
		return nil, fmt.Errorf("GenerateFrameworks: %w", err)
	}
	related, err := securityHubRelatedAll(b)
	if err != nil {
		return nil, fmt.Errorf("GenerateFrameworks: %w", err)
	}
	nist, err := nistTitles(b)
	if err != nil {
		return nil, fmt.Errorf("GenerateFrameworks: %w", err)
	}
	var out []frameworks.Framework
	var errs []error
	for _, src := range FrameworkSources {
		fw, err := generateOne(b, src, frameworkMetas[src.ID], byCheck, related, ix, nist)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, fw)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("GenerateFrameworks: %w", err)
	}
	return out, nil
}

// reqAcc accumulates one requirement. unjoined holds the source mappings
// ("aws/<prowler check>", "securityhub/<control>") that reached no matrix
// row: evidence the source counts that graph does not evaluate, so the
// requirement can never pass on what remains (ADR 093).
type reqAcc struct {
	refs     map[string]bool
	unjoined map[string]bool
}

func newReqAcc() *reqAcc { return &reqAcc{refs: map[string]bool{}, unjoined: map[string]bool{}} }

func generateOne(b fs.FS, src FrameworkSource, meta frameworkMeta, byCheck map[string]map[string][]string,
	related map[string]string, ix frameworks.Index, nist map[string]string) (frameworks.Framework, error) {
	acc := map[string]*reqAcc{}
	get := func(id string) *reqAcc {
		if acc[id] == nil {
			acc[id] = newReqAcc()
		}
		return acc[id]
	}
	for _, provider := range ProwlerProviders {
		file, ok := src.Prowler[provider]
		if !ok {
			continue
		}
		raw, err := fs.ReadFile(b, ProwlerFilePath(provider, file))
		if err != nil {
			return frameworks.Framework{}, fmt.Errorf("%s: %w", src.ID, err)
		}
		pf, err := decodeProwler(raw)
		if err != nil {
			return frameworks.Framework{}, fmt.Errorf("%s: %s: %w", src.ID, file, err)
		}
		for _, r := range pf.Requirements {
			id := meta.id(r)
			if id == "" {
				continue
			}
			a := get(id)
			for _, chk := range r.Checks {
				refs := byCheck[provider][chk]
				if len(refs) == 0 {
					a.unjoined[provider+"/"+chk] = true
				}
				for _, ref := range refs {
					a.refs[ref] = true
				}
			}
		}
	}
	if src.SecurityHubPrefix != "" {
		re := regexp.MustCompile(regexp.QuoteMeta(src.SecurityHubPrefix) + `([A-Z]{0,2}-?[0-9]+(?:\.[0-9]+)*(?:\([0-9]+\))?)`)
		for control, text := range related {
			ref := "aws-fsbp/" + control
			_, joined := ix[ref]
			for _, m := range re.FindAllStringSubmatch(text, -1) {
				if joined {
					get(m[1]).refs[ref] = true
				} else {
					get(m[1]).unjoined["securityhub/"+control] = true
				}
			}
		}
	}
	acc = foldUnknownEnhancements(acc, nist)

	fw := frameworks.Framework{ID: src.ID, Name: meta.name, Version: meta.version, Sources: meta.sources}
	var untitled []string
	for id, a := range acc {
		title := nist[id]
		if title == "" {
			untitled = append(untitled, id)
			continue
		}
		refs := make([]string, 0, len(a.refs))
		for r := range a.refs {
			refs = append(refs, r)
		}
		sort.Strings(refs)
		fw.Requirements = append(fw.Requirements, frameworks.Requirement{ID: id, Title: title, Unjoined: len(a.unjoined), Controls: refs})
	}
	if len(untitled) > 0 {
		sort.Slice(untitled, func(i, j int) bool { return NaturalLess(untitled[i], untitled[j]) })
		return frameworks.Framework{}, fmt.Errorf("%s: requirements the NIST catalog has no title for: %s",
			src.ID, strings.Join(untitled, ", "))
	}
	sort.Slice(fw.Requirements, func(i, j int) bool { return NaturalLess(fw.Requirements[i].ID, fw.Requirements[j].ID) })
	return fw, nil
}

// foldUnknownEnhancements merges an "XX-n(m)" the NIST catalog does not
// define into its base control: Prowler writes some statement items of a
// base control with enhancement syntax ("CP-1(2)" for CP-1 item 2).
func foldUnknownEnhancements(acc map[string]*reqAcc, nist map[string]string) map[string]*reqAcc {
	out := map[string]*reqAcc{}
	for id, a := range acc {
		if base, _, isEnh := strings.Cut(id, "("); isEnh && nist[id] == "" && nist[base] != "" {
			id = base
		}
		if out[id] == nil {
			out[id] = newReqAcc()
		}
		for r := range a.refs {
			out[id].refs[r] = true
		}
		for u := range a.unjoined {
			out[id].unjoined[u] = true
		}
	}
	return out
}

// prowlerCheckRefs maps provider → Prowler check → the benchmark controls
// that check sits under in Prowler's own CIS (pinned version only: CIS
// renumbers between versions) and FSBP files. Only references that resolve
// to a matrix row are kept.
func prowlerCheckRefs(b fs.FS, bs []benchmarks.Benchmark, ix frameworks.Index) (map[string]map[string][]string, error) {
	out := map[string]map[string][]string{}
	add := func(provider, chk, ref string) {
		if _, ok := ix[ref]; !ok {
			return
		}
		if out[provider] == nil {
			out[provider] = map[string][]string{}
		}
		out[provider][chk] = append(out[provider][chk], ref)
	}
	read := func(provider, file string) (ProwlerFramework, error) {
		raw, err := fs.ReadFile(b, ProwlerFilePath(provider, file))
		if err != nil {
			return ProwlerFramework{}, err
		}
		return decodeProwler(raw)
	}
	for _, src := range Sources {
		if src.Kind != KindProwler {
			continue
		}
		bm, ok := find(bs, src.Benchmark)
		if !ok {
			continue
		}
		names, err := listing(b, ProwlerIndexPath(src.Provider))
		if err != nil {
			return nil, err
		}
		vs := versionsMatching(names, prowlerCISPattern(src.Provider))
		v := nearestAtMost(keys(vs), bm.Version)
		if v == "" || !sameVersion(v, bm.Version) {
			continue
		}
		pf, err := read(src.Provider, vs[v])
		if err != nil {
			return nil, fmt.Errorf("prowlerCheckRefs: %w", err)
		}
		for _, r := range pf.Requirements {
			for _, chk := range r.Checks {
				add(src.Provider, chk, bm.ID+"/"+r.ID)
			}
		}
	}
	pf, err := read("aws", prowlerFSBPFile)
	if err != nil {
		return nil, fmt.Errorf("prowlerCheckRefs: %w", err)
	}
	for _, r := range pf.Requirements {
		for _, chk := range r.Checks {
			add("aws", chk, "aws-fsbp/"+r.ID)
		}
	}
	return out, nil
}

// securityHubRelatedAll reads every per-service page's related requirements.
func securityHubRelatedAll(b fs.FS) (map[string]string, error) {
	raw, err := fs.ReadFile(b, PathSecurityHubReference)
	if err != nil {
		return nil, fmt.Errorf("securityHubRelatedAll: %w", err)
	}
	fsbp, err := securityHubReferenceFSBP(raw)
	if err != nil {
		return nil, fmt.Errorf("securityHubRelatedAll: %w", err)
	}
	inFSBP := map[string]bool{}
	for _, c := range fsbp {
		inFSBP[c.ID] = true
	}
	out := map[string]string{}
	for _, p := range securityHubPages(raw) {
		page, err := fs.ReadFile(b, SecurityHubPagePath(p))
		if err != nil {
			return nil, fmt.Errorf("securityHubRelatedAll: %w", err)
		}
		// Only FSBP controls: graph's matrix is the FSBP standard, so a
		// control outside it could never be joined and is not a source the
		// mapping claims.
		for k, v := range securityHubRelated(page) {
			if inFSBP[k] {
				out[k] = v
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("securityHubRelatedAll: no related requirements (page layout changed?)")
	}
	return out, nil
}

// nistTitles maps "AC-2" / "AC-2(1)" to its OSCAL catalog title.
func nistTitles(b fs.FS) (map[string]string, error) {
	raw, err := fs.ReadFile(b, PathNISTCatalog)
	if err != nil {
		return nil, fmt.Errorf("nistTitles: %w", err)
	}
	type control struct {
		ID       string    `json:"id"`
		Title    string    `json:"title"`
		Controls []control `json:"controls"`
	}
	var doc struct {
		Catalog struct {
			Groups []struct {
				Controls []control `json:"controls"`
			} `json:"groups"`
		} `json:"catalog"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("nistTitles: %w", err)
	}
	out := map[string]string{}
	var walk func([]control)
	walk = func(cs []control) {
		for _, c := range cs {
			base, enh, isEnh := strings.Cut(c.ID, ".")
			id := strings.ToUpper(base)
			if isEnh {
				id += "(" + enh + ")"
			}
			out[id] = c.Title
			walk(c.Controls)
		}
	}
	for _, g := range doc.Catalog.Groups {
		walk(g.Controls)
	}
	if len(out) == 0 {
		return nil, errors.New("nistTitles: empty catalog")
	}
	return out, nil
}

// NaturalLess orders requirement IDs with numeric runs compared as numbers:
// A.5.9 < A.5.10, AC-2(3) < AC-2(12).
func NaturalLess(a, b string) bool {
	ca, cb := chunks(a), chunks(b)
	for i := 0; i < len(ca) && i < len(cb); i++ {
		if ca[i] == cb[i] {
			continue
		}
		na, ea := strconv.Atoi(ca[i])
		nb, eb := strconv.Atoi(cb[i])
		if ea == nil && eb == nil {
			return na < nb
		}
		return ca[i] < cb[i]
	}
	return len(ca) < len(cb)
}

func chunks(s string) []string {
	var out []string
	var cur strings.Builder
	digit := false
	for i, r := range s {
		d := unicode.IsDigit(r)
		if i > 0 && d != digit {
			out = append(out, cur.String())
			cur.Reset()
		}
		digit = d
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
