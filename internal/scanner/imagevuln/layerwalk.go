package imagevuln

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
)

// Retention caps for one image's walk. MaxManifestBytes bounds a single file;
// these bound the total, because a hostile image can carry thousands of
// status.d paragraphs or several maximum-size rpm databases, each under its
// own cap. One full rpm database plus every dpkg/apk/release file a real image
// carries fits well inside both.
const (
	maxRetainedBytes = pkginventory.MaxRPMDBBytes + 64<<20
	maxRetainedFiles = 2048
)

// maxGoProbeBytes caps how much of one image is spent probing executables for Go
// build info. It bounds total work, not peak memory (one binary is buffered at a
// time, so the memory ceiling is pkginventory's per-file cap), and it's a budget
// rather than a filter: an image can carry hundreds of MiB of non-Go executables
// alongside a Go service binary of similar size, so a hard exclusion by size or
// count would misclassify one or the other.
const maxGoProbeBytes = 512 << 20

// readManifests walks the image's layers from newest to oldest, keeping the OS
// package databases and converting every language manifest it passes into
// packages on the spot.
//
// It reads layers directly rather than streaming mutate.Extract because Extract
// re-serializes the ENTIRE merged filesystem through a tar writer — every byte
// of every file is read, copied and written so that a handful can be kept.
// Reading layers ourselves skips uninteresting entries without copying their
// bodies. The walk is bounded only by MaxStreamBytes — language manifests can
// appear at unbounded depth and count, so there is no early-stop heuristic.
//
// Newest-first with first-hit-wins is the same precedence Extract applies, plus
// explicit whiteout handling: a `.wh.<name>` tombstone or an opaque-directory
// marker in a newer layer means the path is deleted in the merged filesystem, so
// the lower-layer copy must not be resurrected.
//
// A file the walk will not hold — over the per-file cap, or past the image's
// retention caps — is skipped and recorded in the incomplete reason, and the
// walk carries on: the layer itself is sound, and stopping would lose the base
// layer to one oversized lockfile.
//
// A walk that cannot finish — the stream cap, a corrupt or unreadable layer —
// STOPS and records why in the walk's incomplete reason. It
// does not skip to the next layer: the rest of the broken layer may have held
// whiteouts, so an older layer read past it could resurrect deleted files. And
// because layers are read newest-first, the layers lost are the oldest — the
// base layer that carries os-release and the OS package database — which is
// why the reason must reach the caller rather than a log line.
func (s RegistryImageSource) readManifests(img v1.Image) (*manifestWalk, error) {
	maxStream := s.MaxStreamBytes
	if maxStream <= 0 {
		maxStream = defaultMaxStreamBytes
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("imagevuln: read image layers: %w", err)
	}

	w := &manifestWalk{
		files:    map[string][]byte{},
		resolved: map[string]struct{}{},
		opaque:   map[string]struct{}{},
		read:     map[string]struct{}{},
		maxFile:  s.MaxManifestBytes,
		goBudget: maxGoProbeBytes,
	}
	if w.maxFile <= 0 {
		w.maxFile = defaultMaxManifestBytes
	}

	var read int64
	for i := len(layers) - 1; i >= 0; i-- {
		unread := fmt.Sprintf("layer %d of %d and the %d older layer(s) were not read", len(layers)-i, len(layers), i)
		if read >= maxStream {
			w.markIncomplete(fmt.Sprintf("layer stream exceeded the %d-byte budget; %s", maxStream, unread))
			break
		}
		n, err := w.readLayer(layers[i], maxStream-read)
		read += n
		if err != nil {
			w.markIncomplete(fmt.Sprintf("%v; %s in full", err, unread))
			break
		}
	}
	return w, nil
}

// manifestWalk carries the newest-first walk's state across layers.
type manifestWalk struct {
	files    map[string][]byte
	packages []pkginventory.InstalledPackage // language packages parsed at stream time
	// resolved holds paths a newer layer settled — supplied, replaced by a
	// non-directory entry, or whited out. Each one hides the same path AND
	// everything beneath it in older layers: a file or a tombstone where an
	// older layer had a directory replaces the whole directory.
	resolved map[string]struct{}
	opaque   map[string]struct{} // directories emptied by an opaque whiteout in a newer layer
	// read holds manifest paths whose content was actually read, so a hardlink
	// to one is known to add nothing; see noteUnreadHardlink.
	read     map[string]struct{}
	maxFile  int64
	goBudget int64

	retainedBytes int64
	// incomplete is why the walk did not read every package file of every
	// layer, "" when it did; see markIncomplete.
	incomplete string
	// languageGap is why some LANGUAGE packages were not inventoried, "" when
	// none were missed; see markLanguageGap.
	languageGap string

	// Tombstones read from the layer currently being walked; see commitWhiteouts.
	pendingResolved []string
	pendingOpaque   []string
}

// markIncomplete records one reason the walk is partial, once each.
func (w *manifestWalk) markIncomplete(reason string) { addNote(&w.incomplete, reason) }

// markLanguageGap records language packages the walk could not inventory. It
// is kept apart from incomplete on purpose: a skipped Go binary or lockfile says
// nothing about the OS package database, and must not turn a fully matched OS
// inventory into scan_incomplete.
func (w *manifestWalk) markLanguageGap(reason string) { addNote(&w.languageGap, reason) }

// addNote appends reason to a "; "-joined note, once.
func addNote(note *string, reason string) {
	switch {
	case *note == "":
		*note = reason
	case !strings.Contains(*note, reason):
		*note += "; " + reason
	}
}

// skipOversized records a file too large to hold and settles its path, so an
// older layer's copy — which the running container does not have — is not
// read in its place.
func (w *manifestWalk) skipOversized(clean string, size int64, language bool) {
	w.resolved[clean] = struct{}{}
	reason := fmt.Sprintf("%s is %d bytes, over the %d-byte manifest cap", clean, size, w.maxFile)
	if language {
		w.markLanguageGap(reason)
		return
	}
	w.markIncomplete(reason)
}

// errStreamBudget is the stream cap tripping mid-layer.
var errStreamBudget = errors.New("layer stream exceeded the byte budget")

// readLayer scans one layer's tar for wanted paths, returning how many bytes of
// the layer were consumed. Any error means the layer was not read in full.
func (w *manifestWalk) readLayer(layer v1.Layer, budget int64) (int64, error) {
	rc, err := layer.Uncompressed()
	if err != nil {
		return 0, fmt.Errorf("open layer: %w", err)
	}
	defer func() { _ = rc.Close() }()

	counted := &countingReader{r: rc, limit: budget}
	// Tombstones this layer declares apply to OLDER layers only, so they are
	// staged and merged once the layer is done. Applying them as they are read
	// deletes the layer's OWN files: Docker writes a directory's opaque marker
	// before the directory's contents, so an eagerly-applied marker can hide
	// nearly every installed Python distribution in an image.
	defer w.commitWhiteouts()
	tr := tar.NewReader(counted)
	for {
		hdr, err := tr.Next()
		if err != nil {
			// Check the cap FIRST. Tripping it makes countingReader return io.EOF:
			// mid-entry tar reports that as "unexpected EOF", and on a header
			// boundary as a plain io.EOF — indistinguishable from the archive's
			// real end without this check.
			if counted.exceeded {
				return counted.n, errStreamBudget
			}
			if errors.Is(err, io.EOF) {
				return counted.n, nil
			}
			return counted.n, fmt.Errorf("corrupt layer: %w", err)
		}
		if err := w.readEntry(hdr, tr); err != nil {
			if counted.exceeded {
				return counted.n, errStreamBudget
			}
			return counted.n, err
		}
	}
}

// readEntry handles one tar entry of the layer being read.
func (w *manifestWalk) readEntry(hdr *tar.Header, tr io.Reader) error {
	clean := normalizeTarPath(hdr.Name)
	if hdr.Typeflag == tar.TypeDir {
		return nil // a directory in a newer layer merges with, never hides, an older one
	}
	if w.noteWhiteout(clean) {
		return nil
	}
	if !w.wanted(clean) {
		return nil
	}
	if hdr.Typeflag != tar.TypeReg {
		// Symlinks, hardlinks and devices are never followed or read, but they
		// still occupy the path: an older layer's file there is not in the
		// merged filesystem.
		w.resolved[clean] = struct{}{}
		if hdr.Typeflag == tar.TypeLink {
			w.noteUnreadHardlink(clean, hdr.Linkname)
		}
		return nil
	}
	mode := hdr.FileInfo().Mode()
	kind := pkginventory.ClassifyManifest(clean, mode, hdr.Size)
	switch {
	case kind == pkginventory.KindNone:
		if mode&0o111 != 0 {
			// An executable that is not a Go candidate (a script, a small
			// binary) still replaces an older layer's binary at this path.
			w.resolved[clean] = struct{}{}
		}
		return nil
	case kind.IsLanguage():
		return w.parseLanguage(kind, clean, hdr.Size, tr)
	case kind == pkginventory.KindRpmDB:
		return w.keepRPMDB(clean, hdr.Size, tr)
	}
	if hdr.Size > w.maxFile {
		w.skipOversized(clean, hdr.Size, languageKind(kind))
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
	if err != nil {
		return fmt.Errorf("read %s: %w", clean, err)
	}
	w.keep(clean, data)
	return nil
}

// noteUnreadHardlink records a hardlink at a manifest path whose target the walk
// did not read (a tar hardlink names an earlier entry of the same layer): the
// content is the target's, so the manifest is unread. A target that WAS read
// already contributed the same packages, and is no gap. A
// tar hardlink carries no size, so only path-recognised kinds are seen here; a
// hardlinked Go binary is indistinguishable from any other link.
func (w *manifestWalk) noteUnreadHardlink(clean, target string) {
	if _, read := w.read[normalizeTarPath(target)]; read {
		return // same content, already inventoried at the target (a conda pkgs/ cache)
	}
	kind := pkginventory.ClassifyManifest(clean, 0o644, 0)
	switch {
	case kind == pkginventory.KindNone:
		return
	case languageKind(kind):
		w.markLanguageGap(fmt.Sprintf("%s is a hardlink; its content was not read", clean))
	default:
		w.markIncomplete(fmt.Sprintf("%s is a hardlink; its content was not read", clean))
	}
}

// languageKind reports whether a manifest kind describes language packages:
// the self-describing kinds, plus the root lockfiles, which are not parsed in
// the stream but say nothing about the OS either.
func languageKind(k pkginventory.ManifestKind) bool {
	return k.IsLanguage() || k == pkginventory.KindNpmLock || k == pkginventory.KindPyRequirements
}

// whiteoutPrefix and opaqueWhiteout are the OCI layer tombstone conventions.
const (
	whiteoutPrefix = ".wh."
	opaqueWhiteout = ".wh..wh..opq"
)

// noteWhiteout stages a tombstone declared by the layer being read and reports
// whether the entry was one. Staged, not applied: see commitWhiteouts.
func (w *manifestWalk) noteWhiteout(clean string) bool {
	base := path.Base(clean)
	if base == opaqueWhiteout {
		w.pendingOpaque = append(w.pendingOpaque, path.Dir(clean))
		return true
	}
	if !strings.HasPrefix(base, whiteoutPrefix) {
		return false
	}
	w.pendingResolved = append(w.pendingResolved,
		path.Join(path.Dir(clean), strings.TrimPrefix(base, whiteoutPrefix)))
	return true
}

// commitWhiteouts applies the layer's tombstones now that it has been read, so
// they bite on the older layers still to come and never on the layer that
// declared them.
func (w *manifestWalk) commitWhiteouts() {
	for _, p := range w.pendingResolved {
		w.resolved[p] = struct{}{}
	}
	for _, d := range w.pendingOpaque {
		w.opaque[d] = struct{}{}
	}
	w.pendingResolved, w.pendingOpaque = nil, nil
}

// wanted reports whether clean is still live in the merged filesystem and has not
// already been supplied by a newer layer.
//
// Every ancestor is checked, not just the path: `rm -rf /app/node_modules` in a
// newer layer is ONE tombstone (.wh.node_modules), and an opaque marker empties
// a whole tree — installed language packages sit several directories below
// either, and a shallow check would resurrect a tree the running container
// doesn't have.
func (w *manifestWalk) wanted(clean string) bool {
	if _, settled := w.resolved[clean]; settled {
		return false
	}
	for dir := path.Dir(clean); dir != "." && dir != "/"; dir = path.Dir(dir) {
		if _, gone := w.resolved[dir]; gone {
			return false
		}
		if _, hidden := w.opaque[dir]; hidden {
			return false
		}
	}
	return true
}

// parseLanguage converts a language manifest to packages as it streams past,
// keeping the result and discarding the bytes. Retaining them instead would
// mean holding every manifest and binary in the image whole for the scan's
// duration, which can be a large multiple of the packages actually extracted.
func (w *manifestWalk) parseLanguage(kind pkginventory.ManifestKind, clean string, size int64, r io.Reader) error {
	w.resolved[clean] = struct{}{}
	if kind == pkginventory.KindGoBinary {
		return w.parseGoBinary(clean, size, r)
	}
	if size > w.maxFile {
		w.skipOversized(clean, size, true)
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(r, size))
	if err != nil {
		return fmt.Errorf("read %s: %w", clean, err)
	}
	w.packages = append(w.packages, pkginventory.ParseManifest(kind, clean, data)...)
	w.read[clean] = struct{}{}
	return nil
}

// parseGoBinary buffers a candidate executable only once its first four bytes say
// it is ELF, and charges the probe budget only for what was actually buffered.
// The tar reader then skips the remainder of a rejected entry without copying it,
// so an ML image full of shared objects costs four bytes each instead of gigabytes.
//
// The path is settled whatever the outcome (parseLanguage): a non-ELF file or
// one past the budget still replaces an older layer's binary at the same path.
func (w *manifestWalk) parseGoBinary(clean string, size int64, r io.Reader) error {
	if w.goBudget < size {
		// Budget spent (see maxGoProbeBytes): this and later binaries are not
		// inventoried, and that must be visible rather than read as none.
		w.markLanguageGap(fmt.Sprintf("the %d MiB Go build-info probe budget was spent; later Go binaries were not inventoried", maxGoProbeBytes>>20))
		return nil
	}
	head := make([]byte, pkginventory.ELFPrefixLen)
	if _, err := io.ReadFull(r, head); err != nil || !pkginventory.IsELF(head) {
		return nil
	}
	rest, err := io.ReadAll(io.LimitReader(r, size-int64(len(head))))
	if err != nil {
		return fmt.Errorf("read %s: %w", clean, err)
	}
	w.goBudget -= size
	w.read[clean] = struct{}{}
	w.packages = append(w.packages, pkginventory.ParseManifest(
		pkginventory.KindGoBinary, clean, append(head, rest...))...)
	return nil
}

// keepRPMDB retains an rpm database whole, under its own cap rather than
// MaxManifestBytes: a full install's database runs to tens of MB, and unlike a
// language manifest it can only be parsed once the image's os-release — maybe
// in another layer — is known. One over pkginventory.MaxRPMDBBytes is kept empty,
// so the scan reports the image's OS packages unread rather than absent.
func (w *manifestWalk) keepRPMDB(clean string, size int64, r io.Reader) error {
	if size > pkginventory.MaxRPMDBBytes {
		w.keep(clean, nil)
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(r, size))
	if err != nil {
		return fmt.Errorf("read %s: %w", clean, err)
	}
	w.keep(clean, data)
	return nil
}

// keep stores a manifest and marks its path settled for older layers. Past the
// image's retained total or file count it keeps nothing more and records the
// walk as incomplete.
func (w *manifestWalk) keep(clean string, data []byte) {
	w.resolved[clean] = struct{}{}
	if len(w.files) >= maxRetainedFiles {
		w.markIncomplete(fmt.Sprintf("image carries more than %d package database files", maxRetainedFiles))
		return
	}
	if w.retainedBytes+int64(len(data)) > maxRetainedBytes {
		w.markIncomplete(fmt.Sprintf("image's package databases exceed %d MiB in total", maxRetainedBytes>>20))
		return
	}
	w.retainedBytes += int64(len(data))
	w.files[clean] = data
	w.read[clean] = struct{}{}
}

// normalizeTarPath makes an archive path comparable to the fs.FS-relative paths the
// parsers use: image tars vary between "var/lib/dpkg/status", "./var/lib/…" and
// "/var/lib/…" for the same file.
func normalizeTarPath(p string) string {
	return strings.TrimPrefix(path.Clean("/"+p), "/")
}

// countingReader fails the read once limit bytes have passed through, so an
// unbounded image cannot stream forever.
type countingReader struct {
	r        io.Reader
	limit    int64
	n        int64
	exceeded bool
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.n >= c.limit {
		c.exceeded = true
		return 0, io.EOF
	}
	if int64(len(p)) > c.limit-c.n {
		p = p[:c.limit-c.n]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
