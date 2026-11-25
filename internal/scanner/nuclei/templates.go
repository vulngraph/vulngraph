package nuclei

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"

	"github.com/vulngraph/vulngraph/pkg/safenet"
)

// templateRelease is one nuclei-templates release: its tag and the sha256 of
// the source archive GitHub serves for that tag.
type templateRelease struct {
	Version string
	SHA256  string
}

// pinnedTemplates is the nuclei-templates release scans run unless an operator
// overrides it (NUCLEI_TEMPLATES_VERSION + NUCLEI_TEMPLATES_SHA256) or supplies
// a directory (NUCLEI_TEMPLATES_DIR). The sha256 is of
// https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/<Version>.tar.gz.
// GitHub generates that archive on request; should its bytes ever change, the
// install fails closed (checksum mismatch) rather than running unverified
// templates: re-download, diff against the tag, and re-pin.
var pinnedTemplates = templateRelease{
	Version: "v10.5.1",
	SHA256:  "30fe1cfaced4635f886e4a2673641bba86998dceec28e468274524e789aa56eb",
}

var (
	releaseVersionRe = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	sha256HexRe      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// releaseFromEnv returns the operator's release override, or pinnedTemplates
// when neither variable is set. overridden says the variables were set.
func releaseFromEnv(getenv func(string) string) (release templateRelease, overridden bool, err error) {
	version := strings.TrimSpace(getenv(TemplatesVersionEnv))
	sum := strings.ToLower(strings.TrimSpace(getenv(TemplatesSHA256Env)))
	switch {
	case version == "" && sum == "":
		return pinnedTemplates, false, nil
	case version == "" || sum == "":
		return pinnedTemplates, true, fmt.Errorf("%s and %s must be set together", TemplatesVersionEnv, TemplatesSHA256Env)
	case !releaseVersionRe.MatchString(version):
		return pinnedTemplates, true, fmt.Errorf("%s=%q: want a nuclei-templates release tag such as %s", TemplatesVersionEnv, version, pinnedTemplates.Version)
	case !sha256HexRe.MatchString(sum):
		return pinnedTemplates, true, fmt.Errorf("%s: want 64 hex characters (the sha256 of the release's source archive)", TemplatesSHA256Env)
	}
	return templateRelease{Version: version, SHA256: sum}, true, nil
}

// installDir is where release is installed under home. The version and the
// sha256 are both in the name, so a tree verified for one release is never
// replaced by another (an override can give a tag a different checksum) while
// a process is scanning with it, and a templates set the SDK once downloaded
// to $HOME/nuclei-templates is never mistaken for it.
func (r templateRelease) installDir(home string) string {
	return filepath.Join(home, "nuclei-templates-"+r.Version+"-"+r.SHA256)
}

// Limits on the archive and what it may unpack to. v10.5.1 is about 10 MiB
// compressed and 80 MiB on disk in 15,000 entries; the Helm chart's $HOME
// emptyDir (homeSizeLimit, 1Gi) has to hold the archive and the tree.
const (
	maxTemplateArchiveBytes = 64 << 20
	maxTemplateTreeBytes    = 512 << 20
	maxTemplateFileBytes    = 64 << 20
	maxTemplateEntries      = 100_000
	templateDownloadTimeout = 5 * time.Minute
)

// templatesMarker is written into an install directory last, holding the
// sha256 the archive was verified against. A directory without a matching
// marker is a foreign install and is replaced.
const templatesMarker = ".vulngraph-sha256"

// Names beside the install directories. Every process installing under one
// parent takes the lock file there; it is never removed, since a process
// waiting on a removed lock file would hold a lock no one else contends for.
// Archives, staging trees and replaced trees all carry templatesTempPrefix,
// so the lock holder can remove what a crashed install left behind.
const (
	templatesLockName   = ".nuclei-templates.lock"
	templatesTempPrefix = ".nuclei-templates-tmp-"
	templatesLockPoll   = 250 * time.Millisecond
)

// templateArchiveHosts are the hosts the archive request may be redirected
// to: github.com answers it with a redirect to codeload.github.com.
var templateArchiveHosts = map[string]bool{"github.com": true, "codeload.github.com": true}

var (
	errTemplatesChecksum     = errors.New("nuclei templates: archive checksum mismatch")
	errTemplatesArchive      = errors.New("nuclei templates: archive rejected")
	errTemplatesNotInstalled = errors.New("nuclei templates: not installed")
	errTemplatesDownload     = errors.New("nuclei templates: download")
)

// templateInstaller makes the configured templates available before a scan.
// sem serialises installs within the process (the lock file, across
// processes); ready is the directory already verified in this process.
type templateInstaller struct {
	// client is the archive client for NUCLEI_TEMPLATES_PROXY (nil: direct).
	client     func(proxy *url.URL) *http.Client
	archiveURL func(version string) string
	// ignorePath is where nuclei reads its ignore file (.nuclei-ignore: tags
	// left out of a default run). The SDK's own installer copies it out of the
	// release; this one does the same so a scan runs the same set.
	ignorePath func() string
	sem        chan struct{}
	ready      string
}

// newTemplateInstaller downloads from a compiled-in GitHub URL and verifies
// what it gets.
func newTemplateInstaller() *templateInstaller {
	return &templateInstaller{
		client: templateClient,
		archiveURL: func(version string) string {
			return "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/" + version + ".tar.gz"
		},
		ignorePath: config.DefaultConfig.GetIgnoreFilePath,
		sem:        make(chan struct{}, 1),
	}
}

var templateSet = newTemplateInstaller()

// templateClient is the trusted client for the archive: through proxy when
// one is named, never through HTTPS_PROXY/HTTP_PROXY, with redirects held to
// GitHub's archive hosts.
func templateClient(proxy *url.URL) *http.Client {
	client := safenet.NewInternalVia(templateDownloadTimeout, proxy)
	client.CheckRedirect = checkTemplateRedirect
	return client
}

// ensureTemplates makes the templates of the process configuration available,
// for a scan to call before it builds its engine. A missing template set is an
// error, never an empty scan: zero templates would match nothing, and the run
// would read as clean.
func ensureTemplates(ctx context.Context) error {
	cfg, err := egressConfigFromEnv(os.Getenv)
	if err != nil {
		return fmt.Errorf("ensureTemplates: %w", err)
	}
	if err := templateSet.ensure(ctx, cfg); err != nil {
		return fmt.Errorf("ensureTemplates: %w", err)
	}
	return nil
}

func (t *templateInstaller) ensure(ctx context.Context, cfg egressConfig) error {
	if cfg.operatorDir {
		return checkOperatorDir(cfg.templatesDir)
	}
	if cfg.templatesDir == "" {
		return fmt.Errorf("%w: no template directory", errTemplatesNotInstalled)
	}
	select {
	case t.sem <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("nuclei templates: %w", ctx.Err())
	}
	defer func() { <-t.sem }()

	if t.ready == cfg.templatesDir {
		return nil
	}
	ok, err := installed(cfg.templatesDir, cfg.release)
	if err != nil {
		return err
	}
	if !ok {
		if cfg.downloadDisabled {
			return fmt.Errorf("%w: release %s is not at %s and its download is off (%s or OFFLINE_MODE); set %s to a copy",
				errTemplatesNotInstalled, cfg.release.Version, cfg.templatesDir, TemplatesDownloadDisabledEnv, TemplatesDirEnv)
		}
		if err := t.install(ctx, cfg.templatesDir, cfg.release, t.client(cfg.templatesProxy)); err != nil {
			return cfg.withProxyHint(err)
		}
	}
	if err := t.installIgnoreFile(cfg.templatesDir); err != nil {
		return err
	}
	t.ready = cfg.templatesDir
	return nil
}

// checkOperatorDir refuses a NUCLEI_TEMPLATES_DIR that is missing or empty.
func checkOperatorDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("%w: %s=%s: %w", errTemplatesNotInstalled, TemplatesDirEnv, dir, err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("%w: %s=%s is empty", errTemplatesNotInstalled, TemplatesDirEnv, dir)
	}
	return nil
}

// installed reports whether dir holds release, verified when it was unpacked.
// It does not when the marker is absent or names another checksum. Any other
// failure to read the marker is returned: it says nothing about what dir
// holds, and dir may be a verified tree another process is scanning with.
func installed(dir string, release templateRelease) (bool, error) {
	got, err := os.ReadFile(filepath.Join(dir, templatesMarker))
	switch {
	case err == nil:
		return strings.TrimSpace(string(got)) == release.SHA256, nil
	case errors.Is(err, os.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
		return false, nil
	default:
		return false, fmt.Errorf("nuclei templates: %w", err)
	}
}

// withProxyHint adds to a failed download that HTTPS_PROXY or HTTP_PROXY is
// set and not used, when NUCLEI_TEMPLATES_PROXY is not set.
func (c egressConfig) withProxyHint(err error) error {
	if c.templatesProxy != nil || c.envProxyVar == "" || !errors.Is(err, errTemplatesDownload) {
		return err
	}
	return fmt.Errorf("%w (%s is set, but the templates download never uses it; set %s to download through a proxy)",
		err, c.envProxyVar, TemplatesProxyEnv)
}

// install downloads release, verifies its sha256 and unpacks it into dir.
// Every process installing under dir's parent holds the same exclusive lock
// while it does, and looks again once it has it: another process may have
// installed the release meanwhile. The tree is built in a staging directory
// beside dir, its marker written last, and renamed into place, so a reader
// finds dir absent, unverified or complete. A verified dir is never touched;
// an unverified one is moved aside before the rename, never deleted in place.
func (t *templateInstaller) install(ctx context.Context, dir string, release templateRelease, client *http.Client) error {
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("nuclei templates: %w", err)
	}
	unlock, err := lockTemplates(ctx, parent)
	if err != nil {
		return err
	}
	defer unlock()
	ok, err := installed(dir, release)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	removeTemplateLeftovers(parent)
	staging, err := t.stage(ctx, client, parent, release)
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	return switchTemplates(staging, dir)
}

// lockTemplates takes the exclusive install lock in parent, waiting while
// another process holds it until ctx ends. flock is per open file, so two
// installers in one process exclude each other too.
func lockTemplates(ctx context.Context, parent string) (unlock func(), err error) {
	f, err := os.OpenFile(filepath.Join(parent, templatesLockName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("nuclei templates: lock: %w", err)
	}
	fd := int(f.Fd())
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			_ = f.Close()
			return nil, fmt.Errorf("nuclei templates: lock: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, fmt.Errorf("nuclei templates: waiting for another install: %w", ctx.Err())
		case <-time.After(templatesLockPoll):
		}
	}
}

// removeTemplateLeftovers deletes the temporary files and trees of installs
// that crashed. Only the lock holder calls it, so none is in use. A leftover
// that cannot be removed only takes space, and the next install tries again.
func removeTemplateLeftovers(parent string) {
	leftovers, _ := filepath.Glob(filepath.Join(parent, templatesTempPrefix+"*"))
	for _, p := range leftovers {
		_ = os.RemoveAll(p)
	}
}

// stage downloads and verifies release and unpacks it into a new staging
// directory in parent, marker included, returning its path.
func (t *templateInstaller) stage(ctx context.Context, client *http.Client, parent string, release templateRelease) (string, error) {
	archive, err := os.CreateTemp(parent, templatesTempPrefix+"archive-*.tar.gz")
	if err != nil {
		return "", fmt.Errorf("nuclei templates: %w", err)
	}
	defer func() {
		_ = archive.Close()
		_ = os.Remove(archive.Name())
	}()
	if err := t.download(ctx, client, release, archive); err != nil {
		return "", err
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("nuclei templates: %w", err)
	}
	staging, err := os.MkdirTemp(parent, templatesTempPrefix+"staging-*")
	if err != nil {
		return "", fmt.Errorf("nuclei templates: %w", err)
	}
	if err := extractTemplates(archive, staging); err != nil {
		_ = os.RemoveAll(staging)
		return "", fmt.Errorf("nuclei templates %s: %w", release.Version, err)
	}
	if err := os.WriteFile(filepath.Join(staging, templatesMarker), []byte(release.SHA256+"\n"), 0o644); err != nil {
		_ = os.RemoveAll(staging)
		return "", fmt.Errorf("nuclei templates: %w", err)
	}
	return staging, nil
}

// switchTemplates renames the complete staging tree to dir. Whatever is at
// dir has no marker or another checksum's (install checked under the lock),
// and is moved aside first: rename does not replace a non-empty directory.
func switchTemplates(staging, dir string) error {
	_, err := os.Lstat(dir)
	switch {
	case err == nil:
		aside, err := os.MkdirTemp(filepath.Dir(dir), templatesTempPrefix+"replaced-*")
		if err != nil {
			return fmt.Errorf("nuclei templates: replace %s: %w", dir, err)
		}
		defer func() { _ = os.RemoveAll(aside) }()
		if err := os.Rename(dir, filepath.Join(aside, "tree")); err != nil {
			return fmt.Errorf("nuclei templates: replace %s: %w", dir, err)
		}
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("nuclei templates: %w", err)
	}
	if err := os.Rename(staging, dir); err != nil {
		return fmt.Errorf("nuclei templates: %w", err)
	}
	return nil
}

// checkTemplateRedirect is the archive client's redirect policy: https to
// templateArchiveHosts on the default port, and at most five hops.
func checkTemplateRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("nuclei templates: too many redirects")
	}
	if req.URL.Scheme != "https" || req.URL.Port() != "" || !templateArchiveHosts[req.URL.Hostname()] {
		return fmt.Errorf("nuclei templates: redirect to %s refused: not a GitHub archive host", req.URL.Redacted())
	}
	return nil
}

// download writes the release archive to w, refusing it unless its sha256 is
// the pinned one.
func (t *templateInstaller) download(ctx context.Context, client *http.Client, release templateRelease, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.archiveURL(release.Version), nil)
	if err != nil {
		return fmt.Errorf("nuclei templates: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w %s: %w", errTemplatesDownload, release.Version, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w %s: HTTP %d", errTemplatesDownload, release.Version, resp.StatusCode)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(resp.Body, maxTemplateArchiveBytes+1))
	if err != nil {
		return fmt.Errorf("%w %s: %w", errTemplatesDownload, release.Version, err)
	}
	if n > maxTemplateArchiveBytes {
		return fmt.Errorf("%w: %s is larger than %d bytes", errTemplatesArchive, release.Version, maxTemplateArchiveBytes)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != release.SHA256 {
		return fmt.Errorf("%w: %s: got %s, want %s", errTemplatesChecksum, release.Version, got, release.SHA256)
	}
	return nil
}

// extractTemplates unpacks a GitHub source archive (one top-level directory)
// into dest, dropping that directory and the repository's .git and .github
// trees. Only directories and regular files are accepted; a path that leaves
// dest, a link, a device or an entry over the limits rejects the archive.
// Writes go through os.Root, so nothing lands outside dest even if a check
// above it were wrong.
func extractTemplates(r io.Reader, dest string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("%w: %w", errTemplatesArchive, err)
	}
	defer func() { _ = gz.Close() }()
	root, err := os.OpenRoot(dest)
	if err != nil {
		return fmt.Errorf("extract: %w", err)
	}
	defer func() { _ = root.Close() }()

	tr := tar.NewReader(gz)
	var top string
	var entries, files int
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %w", errTemplatesArchive, err)
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		if entries++; entries > maxTemplateEntries {
			return fmt.Errorf("%w: more than %d entries", errTemplatesArchive, maxTemplateEntries)
		}
		rel, err := archivePath(hdr.Name, &top)
		if err != nil {
			return err
		}
		if rel == "" || skippedTemplatePath(rel) {
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(rel, 0o755); err != nil {
				return fmt.Errorf("extract %s: %w", rel, err)
			}
		case tar.TypeReg:
			if hdr.Size > maxTemplateFileBytes {
				return fmt.Errorf("%w: %s is larger than %d bytes", errTemplatesArchive, rel, maxTemplateFileBytes)
			}
			if total += hdr.Size; total > maxTemplateTreeBytes {
				return fmt.Errorf("%w: unpacks to more than %d bytes", errTemplatesArchive, maxTemplateTreeBytes)
			}
			if err := writeArchiveFile(root, rel, tr); err != nil {
				return err
			}
			files++
		default:
			return fmt.Errorf("%w: %s has unsupported type %q", errTemplatesArchive, hdr.Name, hdr.Typeflag)
		}
	}
	if files == 0 {
		return fmt.Errorf("%w: no files", errTemplatesArchive)
	}
	return nil
}

// archivePath is name relative to the archive's top-level directory, which it
// records in top on the first entry. "" is the top-level directory itself.
func archivePath(name string, top *string) (string, error) {
	clean := path.Clean(name)
	first, rest, _ := strings.Cut(clean, "/")
	if path.IsAbs(name) || first == ".." || first == "." || strings.Contains(name, `\`) {
		return "", fmt.Errorf("%w: unsafe path %q", errTemplatesArchive, name)
	}
	if *top == "" {
		*top = first
	}
	if first != *top {
		return "", fmt.Errorf("%w: %q is outside the top-level directory %q", errTemplatesArchive, name, *top)
	}
	if rest != "" && !filepath.IsLocal(rest) {
		return "", fmt.Errorf("%w: unsafe path %q", errTemplatesArchive, name)
	}
	return rest, nil
}

// skippedTemplatePath is a repository meta tree the SDK's installer leaves out
// too.
func skippedTemplatePath(rel string) bool {
	first, _, _ := strings.Cut(rel, "/")
	return first == ".git" || first == ".github"
}

func writeArchiveFile(root *os.Root, rel string, r io.Reader) error {
	if dir := path.Dir(rel); dir != "." {
		if err := root.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("extract %s: %w", rel, err)
		}
	}
	f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", errTemplatesArchive, rel, err)
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return fmt.Errorf("extract %s: %w", rel, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("extract %s: %w", rel, err)
	}
	return nil
}

// installIgnoreFile copies the release's .nuclei-ignore to where nuclei reads
// it. A release without one leaves nuclei's ignore list as it is.
func (t *templateInstaller) installIgnoreFile(dir string) error {
	src, err := os.ReadFile(filepath.Join(dir, config.NucleiIgnoreFileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("nuclei ignore file: %w", err)
	}
	dst := t.ignorePath()
	if cur, err := os.ReadFile(dst); err == nil && bytes.Equal(cur, src) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("nuclei ignore file: %w", err)
	}
	if err := writeFileAtomic(dst, src); err != nil {
		return fmt.Errorf("nuclei ignore file: %w", err)
	}
	return nil
}

// writeFileAtomic replaces path with data through a rename, so a process
// reading path while another writes it sees the old file or the new one,
// never a truncated one.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
