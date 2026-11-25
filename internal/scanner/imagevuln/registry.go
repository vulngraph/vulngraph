package imagevuln

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
	"github.com/vulngraph/vulngraph/pkg/log"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

// RegistryImageSource pulls an image from a registry and serves its package
// manifests. It is the only ImageSource that can reach a live registry — the
// alternative, LocalImageSource, needs a pre-unpacked directory and cannot
// obtain a rootfs on its own.
//
// It does NOT extract the image. The package parsers read a fixed set of
// manifest paths (pkginventory.PackageManifestPaths), so this streams the
// flattened layer tar and keeps only those files, in memory: megabytes instead
// of gigabytes of disk, no cleanup to leak, and almost no tar attack surface —
// nothing is ever written to a path derived from archive content, so the usual
// extraction hazards (path traversal, symlink escape, device nodes) cannot
// arise here.
type RegistryImageSource struct {
	// Keychain resolves registry credentials. Nil means anonymous, which is correct
	// for public registries such as registry.k8s.io.
	Keychain authn.Keychain
	// Transport carries every registry request — manifest, blob, the redirects a
	// registry hands out for blobs, and the token fetch from whatever realm its
	// WWW-Authenticate names. Image references come from connector data, so it
	// must be SSRF-guarded at dial time; nil uses safenet.NewGuardedTransport with
	// no private ranges allowed.
	Transport http.RoundTripper
	// MaxManifestBytes caps a single manifest file. A dpkg status file on a large
	// Debian image runs to a few MB; the cap stops a hostile or corrupt image from
	// making us buffer without bound.
	MaxManifestBytes int64
	// MaxStreamBytes caps how much of the layer stream is read while looking for the
	// manifests. Needed because finding a file means streaming until it appears, and
	// a maliciously huge image would otherwise stream forever.
	MaxStreamBytes int64
	// Timeout bounds one image pull. Zero uses defaultPullTimeout.
	Timeout time.Duration
}

const (
	defaultMaxManifestBytes = 32 << 20 // 32 MiB
	defaultMaxStreamBytes   = 4 << 30  // 4 GiB
	defaultPullTimeout      = 5 * time.Minute
	registryDialTimeout     = 30 * time.Second
)

// preferredPlatforms is the order a multi-arch image's platform is chosen in.
// The fleet's node architecture is not collected, so amd64 — still most
// clusters — is preferred, and arm64 is the fallback so an arm64-only image is
// scanned rather than failed. Either way the scan reads one architecture's
// packages; for the same tag they are, in practice, the same versions.
var preferredPlatforms = []v1.Platform{
	{OS: "linux", Architecture: "amd64"},
	{OS: "linux", Architecture: "arm64"},
}

// ErrNoManifests means the pull succeeded but the image carried none of the package
// manifests we know how to read — a distroless or scratch image, typically.
//
// It is a distinct error rather than an empty result on purpose: "this image has no
// packages" and "we could not see this image's packages" are different facts, and
// conflating them is how a scanner reports full coverage over images it never
// actually inventoried.
var ErrNoManifests = errors.New("imagevuln: image carries no readable package manifests")

// Open pulls ref (by digest when one is supplied, so the scan is pinned to the exact
// image that is running) and returns an fs.FS containing only the package manifests.
func (s RegistryImageSource) Open(ctx context.Context, ref, digest string) (fs.FS, func(), error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = defaultPullTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	pullRef, err := pullReference(ref, digest)
	if err != nil {
		return nil, nil, err
	}

	transport := s.Transport
	if transport == nil {
		transport = safenet.NewGuardedTransport(registryDialTimeout, nil)
	}
	opts := []remote.Option{remote.WithContext(ctx), remote.WithTransport(transport)}
	if s.Keychain != nil {
		opts = append(opts, remote.WithAuthFromKeychain(s.Keychain))
	} else {
		// Explicitly anonymous rather than falling back to the ambient docker config:
		// a scanner should not silently acquire whatever credentials happen to be on
		// the pod, and every registry we must reach without a keychain is public.
		opts = append(opts, remote.WithAuth(authn.Anonymous))
	}

	img, err := pullImage(pullRef, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("imagevuln: pull %s: %w", pullRef, err)
	}

	annotations := imageAnnotations(ctx, img)
	walk, err := s.readManifests(img)
	if err != nil {
		return nil, nil, err
	}
	if len(walk.files) == 0 && len(walk.packages) == 0 {
		if walk.incomplete != "" {
			return nil, nil, fmt.Errorf("imagevuln: read %s: %s", pullRef, walk.incomplete)
		}
		if walk.languageGap != "" {
			return nil, nil, fmt.Errorf("%w: %s (%s)", ErrNoManifests, pullRef, walk.languageGap)
		}
		return nil, nil, fmt.Errorf("%w: %s", ErrNoManifests, pullRef)
	}
	if walk.incomplete != "" {
		// A partial inventory is still worth matching, but it is reported as
		// partial (manifestFS.IncompleteReason): it reads exactly like a
		// smaller, cleaner image otherwise.
		log.FromContext(ctx).Warn().Str("ref", pullRef.String()).Str("reason", walk.incomplete).
			Int("manifests", len(walk.files)).Int("packages", len(walk.packages)).
			Msg("imagevuln: partial manifest inventory; scanning what was read and reporting the gap")
	}
	// No cleanup: nothing was written to disk.
	return manifestFS{
		files: walk.files, packages: walk.packages, annotations: annotations,
		incomplete: walk.incomplete, languageGap: walk.languageGap,
	}, func() {}, nil
}

// pullImage resolves ref to one image. A multi-arch index is resolved to the
// first of preferredPlatforms it carries; a single-platform manifest is the
// image whatever its architecture.
func pullImage(ref name.Reference, opts []remote.Option) (v1.Image, error) {
	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return nil, fmt.Errorf("pullImage: %w", err)
	}
	if !desc.MediaType.IsIndex() {
		img, err := desc.Image()
		if err != nil {
			return nil, fmt.Errorf("pullImage: %w", err)
		}
		return img, nil
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("pullImage: %w", err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("pullImage: %w", err)
	}
	child, err := selectPlatform(im.Manifests)
	if err != nil {
		return nil, fmt.Errorf("pullImage: %w", err)
	}
	img, err := idx.Image(child.Digest)
	if err != nil {
		return nil, fmt.Errorf("pullImage: %w", err)
	}
	return img, nil
}

// selectPlatform picks the index entry for the first of preferredPlatforms the
// index carries. An image with neither fails rather than scanning another
// architecture's packages, which would report versions that are not deployed.
func selectPlatform(manifests []v1.Descriptor) (v1.Descriptor, error) {
	for _, want := range preferredPlatforms {
		for _, m := range manifests {
			if m.Platform != nil && m.Platform.OS == want.OS && m.Platform.Architecture == want.Architecture {
				return m, nil
			}
		}
	}
	var have []string
	for _, m := range manifests {
		if m.Platform != nil {
			have = append(have, m.Platform.String())
		}
	}
	return v1.Descriptor{}, fmt.Errorf("selectPlatform: index carries no linux/amd64 or linux/arm64 image (has %s)", strings.Join(have, ", "))
}

// imageAnnotations merges the image config's labels with the manifest's
// annotations, the manifest winning: the OCI base-image keys are defined as
// manifest annotations, and a label of the same name is the older Dockerfile
// LABEL spelling. Neither failing stops the scan — the base then falls back to
// os-release, which records itself as the weaker source rather than claiming
// an annotation that was never read.
func imageAnnotations(ctx context.Context, img v1.Image) map[string]string {
	out := map[string]string{}
	if cf, err := img.ConfigFile(); err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("imagevuln: image config unreadable; base identity falls back to os-release")
	} else if cf != nil {
		for k, v := range cf.Config.Labels {
			out[k] = v
		}
	}
	if m, err := img.Manifest(); err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("imagevuln: image manifest unreadable; base identity falls back to os-release")
	} else if m != nil {
		for k, v := range m.Annotations {
			out[k] = v
		}
	}
	return out
}

// pullReference prefers the content digest so a scan is pinned to the exact
// image running in the fleet. A mutable tag can move between the collector
// observing it and the scanner pulling it, which would report packages from an
// image nothing is running.
func pullReference(ref, digest string) (name.Reference, error) {
	ref = strings.TrimSpace(ref)
	digest = strings.TrimSpace(digest)
	if ref == "" {
		return nil, errors.New("imagevuln: empty image reference")
	}
	// A bare digest ("sha256:hex", no registry/repo at all) carries no pull
	// target. Falling through to the repo+digest construction below would
	// strip "sha256:hex" at its OWN internal colon (LastIndex(":") finds the
	// one inside the digest, not a tag separator), treat "sha256" as the
	// repository name, and silently pull from docker.io/library/sha256
	// instead of erroring — every digest-only image_ref would then fail its
	// scan with a bogus docker.io/library/sha256/... reference. Reject explicitly.
	if isBareDigest(ref) {
		return nil, fmt.Errorf("imagevuln: image reference %q is a bare digest with no registry/repo — cannot resolve a pull target", ref)
	}
	// A ref may already carry a digest (…@sha256:…); trust it and don't double-append.
	if digest != "" && !strings.Contains(ref, "@") {
		repo := ref
		if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
			repo = ref[:i] // strip the tag; the digest supersedes it
		}
		d, err := name.NewDigest(repo + "@" + digest)
		if err != nil {
			// Refused, not degraded to the tag: the result is stored under this
			// digest's key, and the tag may name a different image by now.
			return nil, fmt.Errorf("imagevuln: digest %q for %q is malformed; refusing to pull the mutable tag in its place: %w", digest, ref, err)
		}
		return d, nil
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("imagevuln: parse reference %q: %w", ref, err)
	}
	return r, nil
}

// isBareDigest reports whether ref is a content digest with no registry/repo
// at all ("sha256:hex") — as opposed to a full reference ("repo@sha256:hex")
// or a tagged reference ("repo:tag"). A bare digest has no "/" (no registry
// or repo path segment) and its only ":" is the digest's own algorithm
// separator, not a tag separator.
func isBareDigest(ref string) bool {
	return !strings.Contains(ref, "/") && strings.HasPrefix(ref, "sha256:")
}

// manifestFS is a read-only fs.FS over the manifests pulled from an image, plus
// the language packages the pull already resolved. Only Open is needed for the
// files: the parsers use root.Open and fs.ReadFile, and ReadFile falls back to
// Open. Deliberately not fstest.MapFS — that lives in a testing package.
type manifestFS struct {
	files       map[string][]byte
	packages    []pkginventory.InstalledPackage
	annotations map[string]string
	incomplete  string
	languageGap string
}

func (m manifestFS) Open(name string) (fs.File, error) {
	data, ok := m.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return &manifestFile{name: name, Reader: bytes.NewReader(data), size: int64(len(data))}, nil
}

// ReadDir lists the kept files directly under dir. The OS parsers need it for
// databases that are a directory of files rather than one file — a distroless
// image's /var/lib/dpkg/status.d/.
func (m manifestFS) ReadDir(dir string) ([]fs.DirEntry, error) {
	var out []fs.DirEntry
	for name, data := range m.files {
		if path.Dir(name) == dir {
			out = append(out, fs.FileInfoToDirEntry(manifestInfo{name: name, size: int64(len(data))}))
		}
	}
	if len(out) == 0 {
		return nil, &fs.PathError{Op: "readdir", Path: dir, Err: fs.ErrNotExist}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

// InventoriedPackages satisfies pkginventory.PreInventoried: the language manifests
// were parsed while the layer stream went past and their bytes were never kept.
func (m manifestFS) InventoriedPackages() []pkginventory.InstalledPackage {
	return m.packages
}

// ImageAnnotations satisfies ImageAnnotated.
func (m manifestFS) ImageAnnotations() map[string]string { return m.annotations }

// IncompleteReason satisfies PartialInventory.
func (m manifestFS) IncompleteReason() string { return m.incomplete }

// LanguageGap satisfies PartialInventory.
func (m manifestFS) LanguageGap() string { return m.languageGap }

type manifestFile struct {
	*bytes.Reader
	name string
	size int64
}

func (f *manifestFile) Stat() (fs.FileInfo, error) {
	return manifestInfo{name: f.name, size: f.size}, nil
}
func (f *manifestFile) Close() error { return nil }

type manifestInfo struct {
	name string
	size int64
}

func (i manifestInfo) Name() string       { return path.Base(i.name) }
func (i manifestInfo) Size() int64        { return i.size }
func (i manifestInfo) Mode() fs.FileMode  { return 0o444 }
func (i manifestInfo) ModTime() time.Time { return time.Time{} }
func (i manifestInfo) IsDir() bool        { return false }
func (i manifestInfo) Sys() any           { return nil }
