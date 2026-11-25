package jobs

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/internal/scanner/imagevuln"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// Declared beside the finding literal so coverage.DeclaredSources, which
// resolves identifiers per file, sees the source.
const (
	baseImageSource = "base_image"
	// baseImageGroupCheckID names the per-base root-cause finding.
	baseImageGroupCheckID = "base-image-root-cause"
)

// maxListedImages caps the image ids, repos and patches listed on one
// root-cause finding; the counts always cover the whole group.
const maxListedImages = 50

// maxListedPatches caps the FROM patches rendered into one remediation.
const maxListedPatches = 5

// groupKeyOf is the root-cause key of an image's base: the base image it names
// when it names one, else its base OS release. ok=false for an unidentified
// base, which belongs to no group.
func groupKeyOf(b asset.ImageBase) (key string, ok bool) {
	if b.BaseImageSource == imagevuln.BaseSourceAnnotation && b.BaseImage != "" {
		return "image:" + normalizeBaseRef(b.BaseImage), true
	}
	if b.BaseOS != "" {
		return "os:" + b.BaseOS, true
	}
	return "", false
}

// normalizeBaseRef folds the spellings of one Docker Hub reference together
// ("docker.io/library/debian:12" = "debian:12") and drops a pinned digest; the
// tag is kept, because debian:11 and debian:12 are different roots.
func normalizeBaseRef(ref string) string {
	ref = strings.ToLower(strings.TrimSpace(ref))
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	for _, p := range []string{"index.docker.io/library/", "docker.io/library/", "index.docker.io/", "docker.io/", "library/"} {
		if rest, ok := strings.CutPrefix(ref, p); ok {
			return rest
		}
	}
	return ref
}

// baseGroup is every running image built on one base.
type baseGroup struct {
	key       string
	images    []*runningImage
	baseVulns map[string]finding.Finding // package findings on OS packages, by finding id
	appVulns  map[string]finding.Finding // package findings on language packages
}

// groupByBase buckets the running, identified images by base and attributes
// each image's open package findings to the base or the application layer.
//
// The attribution is a heuristic, stated on every finding: a package from the
// distribution's package manager (dpkg, apk, rpm) is the BASE layer's, a
// language-ecosystem package (npm, PyPI, Go, Maven, RubyGems, crates) the
// APPLICATION's. It over-attributes to the base the OS packages a Dockerfile
// installs on top (apt-get install …); layer-exact attribution would need the
// base image's own layer digests, which the scan does not resolve.
func groupByBase(running []*runningImage, vulns map[string][]finding.Finding) map[string]*baseGroup {
	groups := map[string]*baseGroup{}
	for _, r := range running {
		if !r.scanned {
			continue
		}
		key, ok := groupKeyOf(r.base)
		if !ok {
			continue
		}
		g := groups[key]
		if g == nil {
			g = &baseGroup{key: key, baseVulns: map[string]finding.Finding{}, appVulns: map[string]finding.Finding{}}
			groups[key] = g
		}
		g.images = append(g.images, r)
		for _, purl := range r.purls {
			for _, f := range vulns[purl] {
				if isBaseLayerPackage(purl, f) {
					g.baseVulns[f.ID] = f
				} else {
					g.appVulns[f.ID] = f
				}
			}
		}
	}
	for _, g := range groups {
		sort.Slice(g.images, func(i, j int) bool { return g.images[i].img.ID < g.images[j].img.ID })
	}
	return groups
}

// isBaseLayerPackage: the package's ecosystem is a distribution's, or failing
// that its purl type is a distribution package manager's.
func isBaseLayerPackage(purl string, f finding.Finding) bool {
	if _, ok := distro.FamilyOf(f.Metadata["ecosystem"]); ok {
		return true
	}
	typ, _, _ := strings.Cut(strings.TrimPrefix(purl, "pkg:"), "/")
	return typ == "deb" || typ == "apk" || typ == "rpm"
}

// inventoryUnknown reports whether a member's package inventory is missing —
// no runs_package edge at all, so its scan has aged out of edge freshness. A
// group with such a member cannot prove its CVEs are gone.
func (g *baseGroup) inventoryUnknown() bool {
	for _, r := range g.images {
		if len(r.purls) == 0 {
			return true
		}
	}
	return false
}

// groupStats is what a root-cause finding reports about its group.
type groupStats struct {
	workloads, exposedWorkloads int
	baseCVEs, appCVEs           int
	baseKEV, appKEV             int
	baseCritHigh                int
}

func (g *baseGroup) stats() groupStats {
	var s groupStats
	workloads, exposed := map[string]bool{}, map[string]bool{}
	for _, r := range g.images {
		for _, wl := range r.workloads {
			workloads[wl] = true
		}
		for _, wl := range r.exposed {
			exposed[wl] = true
		}
	}
	s.workloads, s.exposedWorkloads = len(workloads), len(exposed)
	s.baseCVEs, s.baseKEV, s.baseCritHigh = cveCounts(g.baseVulns)
	s.appCVEs, s.appKEV, _ = cveCounts(g.appVulns)
	return s
}

// cveCounts counts distinct check ids (a CVE, or an advisory id with none):
// one CVE in five packages is one CVE.
func cveCounts(fs map[string]finding.Finding) (cves, kev, critHigh int) {
	all, known, severe := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, f := range fs {
		all[f.CheckID] = true
		if f.KnownExploited {
			known[f.CheckID] = true
		}
		if f.Severity == finding.SeverityCritical || f.Severity == finding.SeverityHigh {
			severe[f.CheckID] = true
		}
	}
	return len(all), len(known), len(severe)
}

// baseOS is the group's base OS release: shared by every member of an OS
// group, and for an image group the most common among members that have one.
func (g *baseGroup) baseOS() string {
	counts := map[string]int{}
	best := ""
	for _, r := range g.images {
		if os := r.base.BaseOS; os != "" {
			counts[os]++
			if counts[os] > counts[best] || (counts[os] == counts[best] && os < best) {
				best = os
			}
		}
	}
	return best
}

// baseGroupFindingID is a root-cause finding's identity: its base, never the
// member it sits on.
func baseGroupFindingID(groupKey string) string {
	return dbutil.DeterministicID("base-image-group", groupKey)
}

// representative is the member image the root-cause finding sits on: a real
// image, so enrich classifies it with that image's own reachability; an
// exposed one when any is; and the previous one (prevRep) while it stays
// eligible, so the finding's resource does not churn pass to pass. images is
// sorted by id, which breaks a fresh tie.
func (g *baseGroup) representative(prevRep string) *runningImage {
	eligible := g.images
	var exposed []*runningImage
	for _, r := range g.images {
		if len(r.exposed) > 0 {
			exposed = append(exposed, r)
		}
	}
	if len(exposed) > 0 {
		eligible = exposed
	}
	for _, r := range eligible {
		if r.img.ID == prevRep {
			return r
		}
	}
	return eligible[0]
}

// finding shapes the group's root-cause finding. ok=false when the base has
// nothing to fix: no base-layer CVE and not end-of-life.
func (g *baseGroup) finding(cat imagevuln.Catalogue, prevRep string, now time.Time) (finding.Finding, bool) {
	s := g.stats()
	baseOS := g.baseOS()
	lc, lcKnown := distro.EndOfLife(baseOS)
	eol := lcKnown && lc.Past(now)
	if s.baseCVEs == 0 && !eol {
		return finding.Finding{}, false
	}

	rep := g.representative(prevRep)
	label := strings.TrimPrefix(strings.TrimPrefix(g.key, "image:"), "os:")
	baseImage := ""
	if strings.HasPrefix(g.key, "image:") {
		baseImage = label
	}

	var purls []string
	ids := make([]string, 0, len(g.images))
	repos := map[string]string{}
	for _, r := range g.images {
		ids = append(ids, r.img.ID)
		purls = append(purls, r.purls...)
		for repo, path := range r.repos {
			repos[repo] = path
		}
	}
	runtime := imagevuln.RuntimeOf(purls)
	recs := cat.Recommend(runtime, baseOS, now)

	meta := map[string]string{
		"base_group":              g.key,
		asset.MetaBaseImage:       baseImage,
		asset.MetaBaseImageSource: rep.base.BaseImageSource,
		asset.MetaBaseOS:          baseOS,
		"running_images":          strconv.Itoa(len(g.images)),
		"affected_image_ids":      strings.Join(ids[:min(len(ids), maxListedImages)], ","),
		"workloads":               strconv.Itoa(s.workloads),
		"exposed_workloads":       strconv.Itoa(s.exposedWorkloads),
		"base_layer_cves":         strconv.Itoa(s.baseCVEs),
		"app_layer_cves":          strconv.Itoa(s.appCVEs),
		"base_layer_kev":          strconv.Itoa(s.baseKEV),
		"app_layer_kev":           strconv.Itoa(s.appKEV),
		"app_runtime":             string(runtime),
		"attribution":             "os_package_is_base",
	}
	if lcKnown {
		meta["end_of_life"] = lc.End.Format(time.DateOnly)
		meta["past_end_of_life"] = strconv.FormatBool(eol)
	}
	if len(recs) > 0 {
		meta["recommended_base"] = recs[0].Image
	}
	if len(repos) > 0 {
		meta["owner_repos"] = strings.Join(sortedKeys(repos, maxListedImages), ",")
	}

	return finding.Finding{
		ID:           baseGroupFindingID(g.key),
		Source:       baseImageSource,
		Type:         "root_cause",
		Severity:     groupSeverity(s, eol),
		Title:        groupTitle(label, len(g.images), s, eol),
		Description:  groupDescription(label, baseOS, len(g.images), s, eol, lc),
		Remediation:  groupRemediation(label, baseImage, baseOS, recs, repos),
		ResourceType: rep.img.Type,
		ResourceID:   rep.img.ID,
		ResourceName: rep.img.Name,
		Region:       rep.img.Region,
		CheckID:      baseImageGroupCheckID,
		DetectedAt:   now,
		Metadata:     meta,
	}, true
}

// groupSeverity: High when a base that cannot be patched in place (KEV in the
// base layer, or end-of-life) runs behind a directly exposed workload; Medium
// for either alone or for critical/high base-layer CVEs; Low otherwise.
func groupSeverity(s groupStats, eol bool) finding.Severity {
	switch {
	case (s.baseKEV > 0 || eol) && s.exposedWorkloads > 0:
		return finding.SeverityHigh
	case s.baseKEV > 0 || eol || s.baseCritHigh > 0:
		return finding.SeverityMedium
	}
	return finding.SeverityLow
}

func groupTitle(label string, images int, s groupStats, eol bool) string {
	noun := "image"
	if images != 1 {
		noun = "images"
	}
	t := fmt.Sprintf("Base %s: %d running %s, %d base-layer CVEs (%d KEV)", label, images, noun, s.baseCVEs, s.baseKEV)
	if eol {
		t += ", end of life"
	}
	return t
}

func groupDescription(label, baseOS string, images int, s groupStats, eol bool, lc distro.Lifecycle) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d running container images (%d workloads, %d directly internet-exposed) are built on %s", images, s.workloads, s.exposedWorkloads, label)
	if baseOS != "" && baseOS != label {
		fmt.Fprintf(&b, " (%s)", baseOS)
	}
	fmt.Fprintf(&b, ". Their open CVEs: %d from the base layer (%d known exploited), %d from the application layer (%d known exploited). ",
		s.baseCVEs, s.baseKEV, s.appCVEs, s.appKEV)
	b.WriteString("Base-layer CVEs are fixed once, by rebuilding on a patched or different base, rather than image by image. ")
	if eol {
		fmt.Fprintf(&b, "%s reached the end of standard support on %s: ", baseOS, lc.End.Format(time.DateOnly))
		if lc.Final {
			b.WriteString("its vendor publishes no further advisories, so new vulnerabilities in it are never reported. ")
		} else {
			fmt.Fprintf(&b, "fixes reach only subscribers (%s). ", lc.Note)
		}
	}
	b.WriteString("Attribution heuristic: distribution packages (dpkg, apk, rpm) count as base layer and language packages as application layer, " +
		"so OS packages a Dockerfile installs on top of the base are counted as base. The per-package CVE findings remain the record; this finding groups them.")
	return b.String()
}

func groupRemediation(label, baseImage, baseOS string, recs []imagevuln.Recommendation, repos map[string]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Rebuild the images built on %s on a supported, minimal base, then redeploy their workloads. Candidates:\n", label)
	for _, r := range recs {
		target := r.Image
		if target == "" {
			target = "(build recipe)"
		}
		fmt.Fprintf(&b, "- %s: %s — %s", r.Name, target, r.Reason)
		if r.Note != "" {
			fmt.Fprintf(&b, "; %s", r.Note)
		}
		b.WriteString("\n")
	}
	if replacement := firstImage(recs); replacement != "" && len(repos) > 0 {
		b.WriteString("Suggested change in the repositories that build these images (not applied):\n")
		for _, repo := range sortedKeys(repos, maxListedPatches) {
			b.WriteString(imagevuln.FromPatch(repo, repos[repo], baseImage, baseOS, replacement))
			b.WriteString("\n")
		}
	}
	b.WriteString("Vulngraph does not open the pull request: changing a repository is a mutation and would need a person's approval.")
	return b.String()
}

// firstImage is the first proposal that is a FROM reference, not a recipe.
func firstImage(recs []imagevuln.Recommendation) string {
	for _, r := range recs {
		if r.Image != "" {
			return r.Image
		}
	}
	return ""
}

// sortedKeys returns up to limit of m's keys, sorted.
func sortedKeys(m map[string]string, limit int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys[:min(len(keys), limit)]
}
