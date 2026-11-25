package imagevuln

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/distro"
)

// Base-image recommendations (ADR 088). Vulngraph answers a vulnerable or
// end-of-life base with guidance — which minimal or hardened base to rebuild
// on, and the FROM line to change — and never with a mutation: it opens no pull
// request and writes to no repository (ADR 087).
//
// The catalogue is vendor-neutral. The defaults name freely pullable images
// (Google distroless, Wolfi/Chainguard, Ubuntu Chiseled, Alpine) plus the
// newest supported release of the image's own distribution, derived from the
// lifecycle table. An operator adds their own preferred bases (Docker Hardened
// Images, a vendor's hardened distro, an internal golden image) through
// BASE_IMAGE_CATALOGUE; those are proposed first.

// Runtime is what an image's application layer needs from its base.
type Runtime string

const (
	// RuntimeStatic: a self-contained binary (Go, Rust) that needs no libc.
	RuntimeStatic Runtime = "static"
	// RuntimeGlibc: native code, several language runtimes, or nothing
	// identifiable — a minimal glibc base is the safe proposal.
	RuntimeGlibc  Runtime = "glibc"
	RuntimePython Runtime = "python"
	RuntimeNode   Runtime = "node"
	RuntimeJava   Runtime = "java"
	RuntimeRuby   Runtime = "ruby"
	// RuntimeAny marks a catalogue entry that fits every runtime.
	RuntimeAny Runtime = "any"
)

var validRuntimes = map[Runtime]bool{
	RuntimeStatic: true, RuntimeGlibc: true, RuntimePython: true, RuntimeNode: true,
	RuntimeJava: true, RuntimeRuby: true, RuntimeAny: true,
}

// interpreterRuntimes maps an application-layer purl type to the runtime it
// needs from the base. Go and Rust map to static only when nothing else does.
var interpreterRuntimes = map[string]Runtime{
	"pypi": RuntimePython, "npm": RuntimeNode, "maven": RuntimeJava, "gem": RuntimeRuby,
}

// RuntimeOf infers what the base must provide from an image's package purls.
// Exactly one interpreted ecosystem decides it; Go or Rust modules alone mean a
// static binary; anything else (none, or several interpreters) is glibc. OS
// packages say nothing about the application and are ignored.
func RuntimeOf(purls []string) Runtime {
	found := map[Runtime]bool{}
	compiled := false
	for _, p := range purls {
		typ := purlType(p)
		if rt, ok := interpreterRuntimes[typ]; ok {
			found[rt] = true
		}
		if typ == "golang" || typ == "cargo" {
			compiled = true
		}
	}
	switch {
	case len(found) == 1:
		for rt := range found {
			return rt
		}
	case len(found) == 0 && compiled:
		return RuntimeStatic
	}
	return RuntimeGlibc
}

// purlType returns the type of a package URL ("pkg:pypi/requests@2" → "pypi").
func purlType(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	typ, _, _ := strings.Cut(rest, "/")
	return typ
}

// CatalogueEntry is one base image Vulngraph may propose.
type CatalogueEntry struct {
	Name    string  `json:"name"`    // who publishes it / what it is: "Google distroless"
	Image   string  `json:"image"`   // the FROM reference; "" for a build recipe (Note says how)
	Runtime Runtime `json:"runtime"` // the runtime it serves, or "any"
	Note    string  `json:"note"`
}

// Catalogue is the ordered set of proposable bases; earlier entries win.
type Catalogue struct{ entries []CatalogueEntry }

// defaultEntries are verified pullable (2026-10-08). Distroless tracks Debian
// 13; Chainguard's free tier serves :latest of each image.
var defaultEntries = []CatalogueEntry{
	{Name: "Google distroless", Image: "gcr.io/distroless/static-debian13", Runtime: RuntimeStatic,
		Note: "no shell or package manager; the binary must be statically linked (CGO_ENABLED=0)"},
	{Name: "Wolfi (Chainguard)", Image: "cgr.dev/chainguard/static", Runtime: RuntimeStatic},
	{Name: "Google distroless", Image: "gcr.io/distroless/base-debian13", Runtime: RuntimeGlibc},
	{Name: "Wolfi (Chainguard)", Image: "cgr.dev/chainguard/glibc-dynamic", Runtime: RuntimeGlibc},
	{Name: "Ubuntu Chiseled", Runtime: RuntimeGlibc,
		Note: "build a chiselled rootfs holding only the slices the app needs: chisel cut --release ubuntu-24.04 --root /rootfs base-files_base ca-certificates_data libc6_libs, then COPY it onto scratch"},
	{Name: "Google distroless", Image: "gcr.io/distroless/python3-debian13", Runtime: RuntimePython},
	{Name: "Wolfi (Chainguard)", Image: "cgr.dev/chainguard/python", Runtime: RuntimePython},
	{Name: "Ubuntu Chiseled", Image: "ubuntu/python:3.12-24.04_stable", Runtime: RuntimePython},
	{Name: "Google distroless", Image: "gcr.io/distroless/nodejs22-debian13", Runtime: RuntimeNode},
	{Name: "Wolfi (Chainguard)", Image: "cgr.dev/chainguard/node", Runtime: RuntimeNode},
	{Name: "Google distroless", Image: "gcr.io/distroless/java21-debian13", Runtime: RuntimeJava},
	{Name: "Wolfi (Chainguard)", Image: "cgr.dev/chainguard/jre", Runtime: RuntimeJava},
}

// DefaultCatalogue is the built-in vendor-neutral catalogue.
func DefaultCatalogue() Catalogue {
	return Catalogue{entries: append([]CatalogueEntry(nil), defaultEntries...)}
}

// catalogueFile is the operator's BASE_IMAGE_CATALOGUE document.
type catalogueFile struct {
	// ReplaceDefaults drops the built-in entries, for an operator who allows
	// only their own bases.
	ReplaceDefaults bool             `json:"replace_defaults"`
	Entries         []CatalogueEntry `json:"entries"`
}

// ErrBadCatalogue means the operator's catalogue file is unusable.
var ErrBadCatalogue = errors.New("imagevuln: invalid base image catalogue")

// LoadCatalogue builds the catalogue from the operator's JSON file at path,
// its entries ahead of the defaults (or instead of them with
// replace_defaults). An empty path is the default catalogue. A file that
// cannot be read or validated is an error, never a silent fallback: the
// operator configured it so their bases would be proposed.
func LoadCatalogue(path string) (Catalogue, error) {
	if strings.TrimSpace(path) == "" {
		return DefaultCatalogue(), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Catalogue{}, fmt.Errorf("LoadCatalogue: %w", err)
	}
	var file catalogueFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return Catalogue{}, fmt.Errorf("LoadCatalogue: %w: %w", ErrBadCatalogue, err)
	}
	for i, e := range file.Entries {
		if err := e.validate(); err != nil {
			return Catalogue{}, fmt.Errorf("LoadCatalogue: entry %d: %w", i, err)
		}
	}
	entries := append([]CatalogueEntry(nil), file.Entries...)
	if !file.ReplaceDefaults {
		entries = append(entries, defaultEntries...)
	}
	if len(entries) == 0 {
		return Catalogue{}, fmt.Errorf("LoadCatalogue: %w: replace_defaults with no entries proposes nothing", ErrBadCatalogue)
	}
	return Catalogue{entries: entries}, nil
}

func (e CatalogueEntry) validate() error {
	switch {
	case strings.TrimSpace(e.Name) == "":
		return fmt.Errorf("%w: name is required", ErrBadCatalogue)
	case !validRuntimes[e.Runtime]:
		return fmt.Errorf("%w: runtime %q is not one of static, glibc, python, node, java, ruby, any", ErrBadCatalogue, e.Runtime)
	case e.Image == "" && e.Note == "":
		return fmt.Errorf("%w: %s needs an image or a note saying how to build it", ErrBadCatalogue, e.Name)
	case strings.ContainsAny(e.Image, " \t\r\n"):
		return fmt.Errorf("%w: image %q is not a reference", ErrBadCatalogue, e.Image)
	}
	return nil
}

// Recommendation is one proposed replacement base.
type Recommendation struct {
	Name   string
	Image  string // "" for a build recipe
	Note   string
	Reason string // why it fits this image
}

// maxCatalogueRecommendations bounds the catalogue proposals per base: a list
// a responder reads, not an inventory.
const maxCatalogueRecommendations = 3

// alpineNote qualifies the Alpine proposal for an image not already on it.
const alpineNote = "musl libc: rebuild native code and wheels for musl, and confirm the application runs on it"

// Recommend proposes replacement bases for images whose application layer
// needs rt, built on baseOS (an ecosystem coordinate, "" when unknown):
//
//  1. up to three catalogue entries for rt, in catalogue order (the operator's
//     own bases lead);
//  2. the newest supported release of baseOS's own distribution — the smallest
//     change, and the only one that keeps the same package manager;
//  3. the newest supported Alpine branch, for an image not on Alpine.
//
// The two derived proposals read the lifecycle table, so they move forward
// with it rather than naming a release that has since reached its end.
func (c Catalogue) Recommend(rt Runtime, baseOS string, now time.Time) []Recommendation {
	var out []Recommendation
	for _, e := range c.entries {
		if len(out) == maxCatalogueRecommendations {
			break
		}
		if e.Runtime != rt && e.Runtime != RuntimeAny {
			continue
		}
		reason := "minimal base for a " + string(rt) + " application"
		if e.Runtime == RuntimeAny {
			reason = "minimal general-purpose base"
		}
		out = append(out, Recommendation{Name: e.Name, Image: e.Image, Note: e.Note, Reason: reason})
	}
	if r, ok := sameFamilyUpgrade(baseOS, now); ok {
		out = append(out, r)
	}
	if fam, _ := distro.FamilyOf(baseOS); fam.Name != "Alpine" {
		if r, ok := familyLatest("Alpine", now); ok {
			r.Note, r.Reason = alpineNote, "minimal general-purpose base"
			out = append(out, r.Recommendation)
		}
	}
	return out
}

// familyImages is the conventional minimal image of each distribution's
// release (%s is the release from distro.LatestSupported, Alpine's "v"
// removed), verified pullable 2026-10-08.
var familyImages = map[string]string{
	"Debian":       "debian:%s-slim",
	"Ubuntu":       "ubuntu:%s",
	"Alpine":       "alpine:%s",
	"Amazon Linux": "amazonlinux:%s",
	"Red Hat":      "registry.access.redhat.com/ubi%s/ubi-minimal",
	"Rocky Linux":  "rockylinux/rockylinux:%s-minimal",
	"AlmaLinux":    "almalinux:%s-minimal",
	"Oracle Linux": "oraclelinux:%s-slim",
	"SUSE":         "registry.suse.com/bci/bci-minimal:%s",
	"openSUSE":     "opensuse/leap:%s",
	"CentOS":       "quay.io/centos/centos:stream%s",
}

// sameFamilyUpgrade proposes the family's newest supported release, unless
// the image is already on it.
func sameFamilyUpgrade(baseOS string, now time.Time) (Recommendation, bool) {
	fam, ok := distro.FamilyOf(baseOS)
	if !ok {
		return Recommendation{}, false
	}
	r, ok := familyLatest(fam.Name, now)
	if !ok || r.release == distro.Release(baseOS) {
		return Recommendation{}, false
	}
	r.Reason = "newest supported release of the same distribution: the smallest change, same package manager"
	return r.Recommendation, true
}

// familyRecommendation is a derived proposal plus the release it names.
type familyRecommendation struct {
	Recommendation
	release string
}

// familyLatest is the conventional image of a family's newest supported release.
func familyLatest(family string, now time.Time) (familyRecommendation, bool) {
	latest, ok := distro.LatestSupported(family, now)
	if !ok {
		return familyRecommendation{}, false
	}
	tmpl, ok := familyImages[family]
	if !ok {
		return familyRecommendation{}, false
	}
	return familyRecommendation{
		Recommendation: Recommendation{
			Name:  family + " " + latest,
			Image: fmt.Sprintf(tmpl, strings.TrimPrefix(latest, "v")),
		},
		release: latest,
	}, true
}

// FromPatch renders the suggested Dockerfile change for one owning repository
// as text, for a responder to apply. Nothing applies it: changing a repository
// is a mutation and would need a person's approval (ADR 087). current is the
// base the image names, "" when only its OS is known; declaredAt is the file
// in the repo that names the image (the Dockerfile itself is not located).
func FromPatch(repo, declaredAt, current, baseOS, replacement string) string {
	from := current
	if from == "" {
		from = "<current " + baseOS + " base>"
	}
	where := ""
	if declaredAt != "" {
		where = " (the image is declared in " + declaredAt + ")"
	}
	return fmt.Sprintf("%s — final stage of the image's Dockerfile%s:\n-FROM %s\n+FROM %s", repo, where, from, replacement)
}
