package nuclei

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/scan"
)

type tarEntry struct {
	name string
	typ  byte
	body string
	link string
}

func tarGz(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Typeflag: typ, Linkname: e.link, Mode: 0o644}
		if typ == tar.TypeXGlobalHeader {
			hdr = &tar.Header{Typeflag: typ, PAXRecords: map[string]string{"comment": "commit id"}}
		}
		if typ == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if typ == tar.TypeReg {
			_, err := tw.Write([]byte(e.body))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// goodArchive is shaped like a GitHub source archive of nuclei-templates.
func goodArchive(t *testing.T) []byte {
	return tarGz(t,
		tarEntry{typ: tar.TypeXGlobalHeader},
		tarEntry{name: "nuclei-templates-1.2.3/", typ: tar.TypeDir},
		tarEntry{name: "nuclei-templates-1.2.3/.github/workflows/ci.yml", body: "on: push\n"},
		tarEntry{name: "nuclei-templates-1.2.3/.nuclei-ignore", body: "tags:\n  - dos\n"},
		tarEntry{name: "nuclei-templates-1.2.3/http/", typ: tar.TypeDir},
		tarEntry{name: "nuclei-templates-1.2.3/http/exposure.yaml", body: "id: exposure\n"},
		tarEntry{name: "nuclei-templates-1.2.3/dns/takeover.yaml", body: "id: takeover\n"},
	)
}

// archiveServer serves body and counts the requests it gets.
func archiveServer(t *testing.T, body []byte) (*templateInstaller, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	ignore := filepath.Join(t.TempDir(), "config", ".nuclei-ignore")
	inst := &templateInstaller{
		client:     func(*url.URL) *http.Client { return srv.Client() },
		archiveURL: func(v string) string { return srv.URL + "/" + v + ".tar.gz" },
		ignorePath: func() string { return ignore },
		sem:        make(chan struct{}, 1),
	}
	return inst, &hits
}

// dirNames lists dir, sorted.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func downloadConfig(home string, release templateRelease) egressConfig {
	return egressConfig{templatesDir: release.installDir(home), release: release}
}

// assertInstalled checks that dir holds release, its marker read without error.
func assertInstalled(t *testing.T, dir string, release templateRelease) {
	t.Helper()
	ok, err := installed(dir, release)
	require.NoError(t, err)
	assert.True(t, ok, "%s holds release %s", dir, release.Version)
}

func TestTemplateInstall_VerifiesAndUnpacks(t *testing.T) {
	archive := goodArchive(t)
	release := templateRelease{Version: "v1.2.3", SHA256: sum(archive)}
	home := t.TempDir()
	inst, hits := archiveServer(t, archive)
	cfg := downloadConfig(home, release)

	require.NoError(t, inst.ensure(t.Context(), cfg))
	dir := cfg.templatesDir
	got, err := os.ReadFile(filepath.Join(dir, "http", "exposure.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "id: exposure\n", string(got))
	assert.FileExists(t, filepath.Join(dir, "dns", "takeover.yaml"))
	assert.NoDirExists(t, filepath.Join(dir, ".github"), "repository meta tree is left out")
	assertInstalled(t, dir, release)
	ignore, err := os.ReadFile(inst.ignorePath())
	require.NoError(t, err)
	assert.Equal(t, "tags:\n  - dos\n", string(ignore), "the release's ignore list is where nuclei reads it")

	assert.Equal(t, []string{templatesLockName, filepath.Base(dir)}, dirNames(t, home),
		"no archive or staging directory is left behind")

	require.NoError(t, inst.ensure(t.Context(), cfg))
	again, _ := archiveServer(t, nil)
	require.NoError(t, again.ensure(t.Context(), cfg), "a verified install is reused by the next process")
	assert.Equal(t, int32(1), hits.Load())
}

func TestTemplateInstall_ChecksumMismatchInstallsNothing(t *testing.T) {
	archive := goodArchive(t)
	release := templateRelease{Version: "v1.2.3", SHA256: sum([]byte("a different archive"))}
	home := t.TempDir()
	inst, _ := archiveServer(t, archive)

	err := inst.ensure(t.Context(), downloadConfig(home, release))
	require.ErrorIs(t, err, errTemplatesChecksum)
	assert.Equal(t, []string{templatesLockName}, dirNames(t, home), "an unverified archive is neither unpacked nor kept")
}

func TestTemplateInstall_ReplacesAnUnverifiedDirectory(t *testing.T) {
	archive := goodArchive(t)
	release := templateRelease{Version: "v1.2.3", SHA256: sum(archive)}
	home := t.TempDir()
	cfg := downloadConfig(home, release)
	require.NoError(t, os.MkdirAll(filepath.Join(cfg.templatesDir, "http"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(cfg.templatesDir, "http", "planted.yaml"), []byte("id: planted\n"), 0o644))
	inst, hits := archiveServer(t, archive)

	require.NoError(t, inst.ensure(t.Context(), cfg))
	assert.Equal(t, int32(1), hits.Load())
	assert.NoFileExists(t, filepath.Join(cfg.templatesDir, "http", "planted.yaml"))
	assert.FileExists(t, filepath.Join(cfg.templatesDir, "http", "exposure.yaml"))
}

func TestTemplateInstall_DownloadOffNeedsAnInstall(t *testing.T) {
	archive := goodArchive(t)
	release := templateRelease{Version: "v1.2.3", SHA256: sum(archive)}
	inst, hits := archiveServer(t, archive)
	cfg := downloadConfig(t.TempDir(), release)
	cfg.downloadDisabled = true

	err := inst.ensure(t.Context(), cfg)
	require.ErrorIs(t, err, errTemplatesNotInstalled)
	assert.ErrorContains(t, err, TemplatesDirEnv, "the error names the way out")
	assert.Zero(t, hits.Load())
}

func TestTemplateInstall_OperatorDirMustHoldTemplates(t *testing.T) {
	inst, hits := archiveServer(t, nil)
	empty := t.TempDir()
	require.ErrorIs(t, inst.ensure(t.Context(), egressConfig{templatesDir: filepath.Join(empty, "missing"), operatorDir: true}), errTemplatesNotInstalled)
	require.ErrorIs(t, inst.ensure(t.Context(), egressConfig{templatesDir: empty, operatorDir: true}), errTemplatesNotInstalled)
	require.NoError(t, os.WriteFile(filepath.Join(empty, "t.yaml"), []byte("id: t\n"), 0o644))
	require.NoError(t, inst.ensure(t.Context(), egressConfig{templatesDir: empty, operatorDir: true}))
	assert.Zero(t, hits.Load(), "an operator directory is never downloaded into")
}

func TestTemplateInstall_RefusesOversizedArchive(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.CopyN(w, zeroReader{}, maxTemplateArchiveBytes+1)
	}))
	t.Cleanup(srv.Close)
	inst := &templateInstaller{
		client:     func(*url.URL) *http.Client { return srv.Client() },
		archiveURL: func(string) string { return srv.URL },
		ignorePath: func() string { return filepath.Join(t.TempDir(), ".nuclei-ignore") },
		sem:        make(chan struct{}, 1),
	}
	home := t.TempDir()
	err := inst.ensure(t.Context(), downloadConfig(home, templateRelease{Version: "v1.2.3", SHA256: sum(nil)}))
	require.ErrorIs(t, err, errTemplatesArchive)
	assert.Equal(t, []string{templatesLockName}, dirNames(t, home))
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestExtractTemplates_RejectsUnsafeEntries(t *testing.T) {
	const top = "nuclei-templates-1.2.3/"
	cases := []struct {
		name  string
		entry tarEntry
	}{
		{"parent escape", tarEntry{name: "../evil.yaml", body: "x"}},
		{"escape after the top directory", tarEntry{name: top + "../../evil.yaml", body: "x"}},
		{"absolute path", tarEntry{name: "/tmp/evil.yaml", body: "x"}},
		{"second top-level directory", tarEntry{name: "other/evil.yaml", body: "x"}},
		{"backslash path", tarEntry{name: top + `..\..\evil.yaml`, body: "x"}},
		{"symlink", tarEntry{name: top + "link", typ: tar.TypeSymlink, link: "/etc/passwd"}},
		{"hard link", tarEntry{name: top + "hard", typ: tar.TypeLink, link: top + "http/exposure.yaml"}},
		{"device", tarEntry{name: top + "dev", typ: tar.TypeChar}},
		{"duplicate file", tarEntry{name: top + "http/exposure.yaml", body: "id: replaced\n"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			archive := tarGz(t,
				tarEntry{name: top, typ: tar.TypeDir},
				tarEntry{name: top + "http/exposure.yaml", body: "id: exposure\n"},
				tc.entry,
			)
			parent := t.TempDir()
			dest := filepath.Join(parent, "dest")
			require.NoError(t, os.Mkdir(dest, 0o755))

			err := extractTemplates(bytes.NewReader(archive), dest)
			require.ErrorIs(t, err, errTemplatesArchive)
			entries, err := os.ReadDir(parent)
			require.NoError(t, err)
			require.Len(t, entries, 1, "nothing is written beside the destination")
		})
	}
}

func TestExtractTemplates_RefusesOversizedFile(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "root/big.yaml", Typeflag: tar.TypeReg, Size: maxTemplateFileBytes + 1}))
	require.NoError(t, gz.Close())

	err := extractTemplates(bytes.NewReader(buf.Bytes()), t.TempDir())
	require.ErrorIs(t, err, errTemplatesArchive)
	assert.ErrorContains(t, err, "big.yaml")
}

func TestExtractTemplates_RefusesAnArchiveWithNoFiles(t *testing.T) {
	archive := tarGz(t, tarEntry{name: "root/", typ: tar.TypeDir})
	require.ErrorIs(t, extractTemplates(bytes.NewReader(archive), t.TempDir()), errTemplatesArchive)
}

func TestPinnedTemplatesAreWellFormed(t *testing.T) {
	assert.Regexp(t, releaseVersionRe, pinnedTemplates.Version)
	assert.Regexp(t, sha256HexRe, pinnedTemplates.SHA256)
}

// A scan with no templates in place must fail, not run zero templates and
// report the targets clean.
func TestScanFailsWithoutTemplates(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(TemplatesDownloadDisabledEnv, "true")
	_, err := New().Scan(t.Context(), []scan.Target{{URL: "https://example.com", AssetType: "load_balancer"}}, nil)
	require.ErrorIs(t, err, errTemplatesNotInstalled)
}
