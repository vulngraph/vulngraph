package imagevuln

import (
	"io/fs"
	"strings"
	"unicode"

	"github.com/vulngraph/vulngraph/internal/distro"
)

// Where a scanned image's base identity came from, most confident first.
const (
	// BaseSourceAnnotation: the image names its base in the OCI
	// org.opencontainers.image.base.name annotation (or the same-named label).
	// Docker's official images and BuildKit builds with provenance set it.
	BaseSourceAnnotation = "annotation"
	// BaseSourceOSRelease: no annotation, but the OS package database and
	// os-release identify the base OS release ("Debian:12"). The base IMAGE is
	// not known — python:3.12-slim and debian:12 are both Debian 12.
	BaseSourceOSRelease = "os_release"
	// BaseSourceUnknown: neither. A scratch/static image, or an OS package
	// database whose release could not be read. Unknown is never "fine": the
	// end-of-life check stays silent and the image counts against coverage.
	BaseSourceUnknown = "unknown"
)

// The OCI image-spec pre-defined annotation keys for an image's base
// (https://github.com/opencontainers/image-spec/blob/main/annotations.md).
const (
	annotationBaseName   = "org.opencontainers.image.base.name"
	annotationBaseDigest = "org.opencontainers.image.base.digest"
)

// maxBaseNameLen bounds an annotation value taken from an image: a reference
// longer than this is not a reference, and the value is attacker-controlled.
const maxBaseNameLen = 255

// BaseIdentity is what a scan learned about the image an image was built on.
type BaseIdentity struct {
	// Image is the base image reference the image names ("debian:trixie-slim"),
	// set only when Source is BaseSourceAnnotation.
	Image string
	// Digest is the base image's content digest when the image names one.
	Digest string
	// Source is one of the BaseSource* constants.
	Source string
	// OS is the base OS release as an ecosystem coordinate ("Debian:12",
	// "Alpine:v3.20"), "" when the release is not known. Set independently of
	// Source: an annotated image still has its OS read from its packages.
	OS string
}

// ImageAnnotated is implemented by an image view that read the image's OCI
// manifest annotations and config labels. RegistryImageSource's view does; a
// mounted rootfs has neither, and its base is identified from os-release alone.
type ImageAnnotated interface {
	ImageAnnotations() map[string]string
}

// identifyBase decides the base identity from the image's annotations and the
// OS ecosystem its packages were stamped with (pkginventory.OSCVEGap's).
func identifyBase(root fs.FS, osEcosystem string) BaseIdentity {
	id := BaseIdentity{Source: BaseSourceUnknown, OS: baseOS(osEcosystem)}
	if a, ok := root.(ImageAnnotated); ok {
		ann := a.ImageAnnotations()
		// Docker's own base images (alpine, debian, ubuntu) annotate their base
		// as "scratch": the image IS the base, and its OS release names it.
		if name := cleanAnnotation(ann[annotationBaseName]); name != "" && name != "scratch" {
			id.Image, id.Source = name, BaseSourceAnnotation
			if d := cleanAnnotation(ann[annotationBaseDigest]); strings.HasPrefix(d, "sha256:") {
				id.Digest = d
			}
			return id
		}
	}
	if id.OS != "" {
		id.Source = BaseSourceOSRelease
	}
	return id
}

// baseOS keeps an ecosystem coordinate only when it names a known
// distribution AND a release. "Debian" with no release (no os-release) or an
// unqualified "Alpine" is not an identity: grouping by it would pool every
// release together, and no lifecycle applies to it.
func baseOS(ecosystem string) string {
	if _, ok := distro.FamilyOf(ecosystem); !ok || distro.Release(ecosystem) == "" {
		return ""
	}
	return ecosystem
}

// cleanAnnotation returns an annotation value fit to store and display, or ""
// when it is not a plausible image reference or digest.
func cleanAnnotation(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > maxBaseNameLen {
		return ""
	}
	for _, r := range v {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return ""
		}
	}
	return v
}
