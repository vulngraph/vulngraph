package updateinfo

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1" //nolint:gosec // the algorithm under test
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeRepo serves a mirror list, repomd.xml (with ETag) and a gzipped
// updateinfo from the recorded fixture.
type fakeRepo struct {
	gz          []byte
	algo        string // the repomd checksum type; sum must be that hash
	sum         string
	etag        string
	repomdCalls atomic.Int32
	infoCalls   atomic.Int32
	notModified atomic.Int32
}

func newFakeRepo(t *testing.T, fixture string) *fakeRepo {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + fixture)
	require.NoError(t, err)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err = zw.Write(raw)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	sum := sha256.Sum256(buf.Bytes())
	return &fakeRepo{gz: buf.Bytes(), algo: "sha256", sum: hex.EncodeToString(sum[:]), etag: `"v1"`}
}

func (f *fakeRepo) server(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /mirror.list", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "%s/core/snapshot-1/x86_64/\n", srv.URL)
	})
	mux.HandleFunc("GET /core/snapshot-1/x86_64/repodata/repomd.xml", func(w http.ResponseWriter, r *http.Request) {
		f.repomdCalls.Add(1)
		if r.Header.Get("If-None-Match") == f.etag {
			f.notModified.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", f.etag)
		fmt.Fprintf(w, `<?xml version="1.0"?><repomd><data type="primary"><location href="repodata/primary.xml.gz"/></data>`+
			`<data type="updateinfo"><checksum type="%s">%s</checksum><location href="repodata/updateinfo.xml.gz"/></data></repomd>`, f.algo, f.sum)
	})
	mux.HandleFunc("GET /core/snapshot-1/x86_64/repodata/updateinfo.xml.gz", func(w http.ResponseWriter, _ *http.Request) {
		f.infoCalls.Add(1)
		_, _ = w.Write(f.gz)
	})
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// testClient bypasses safenet (which blocks loopback) with the TLS test client.
func testClient(srv *httptest.Server) *Client {
	return &Client{http: srv.Client(), repo: map[string]*repoState{}}
}

func TestFetch_MirrorListRepomdUpdateinfo(t *testing.T) {
	repo := newFakeRepo(t, "al2023-updateinfo.xml")
	srv := repo.server(t)
	c := testClient(srv)
	src := Source{Ecosystem: "Amazon Linux:2023", Repos: []Repo{{MirrorList: srv.URL + "/mirror.list"}}}

	advs, err := c.Fetch(context.Background(), src)
	require.NoError(t, err)
	require.Len(t, advs, 2)

	// Second run: repomd answers 304 and updateinfo is not downloaded again.
	again, err := c.Fetch(context.Background(), src)
	require.NoError(t, err)
	require.Equal(t, advs, again)
	require.Equal(t, int32(1), repo.infoCalls.Load())
	require.Equal(t, int32(1), repo.notModified.Load())

	// A changed ETag with the same updateinfo checksum still skips the download.
	repo.etag = `"v2"`
	_, err = c.Fetch(context.Background(), src)
	require.NoError(t, err)
	require.Equal(t, int32(1), repo.infoCalls.Load(), "unchanged checksum, no re-download")
}

func TestFetch_ChecksumMismatchFails(t *testing.T) {
	repo := newFakeRepo(t, "al2-updateinfo.xml")
	repo.sum = "00" + repo.sum[2:]
	srv := repo.server(t)
	_, err := testClient(srv).Fetch(context.Background(),
		Source{Ecosystem: "Amazon Linux:2", Repos: []Repo{{MirrorList: srv.URL + "/mirror.list"}}})
	require.ErrorContains(t, err, "sha256 mismatch")
}

// Every repository of a release must be read; one failing fails the release, so
// the caller never reconciles against a partial advisory set.
func TestFetch_AnyRepoFailingFailsTheRelease(t *testing.T) {
	repo := newFakeRepo(t, "ol9-updateinfo.xml")
	srv := repo.server(t)
	_, err := testClient(srv).Fetch(context.Background(), Source{Ecosystem: "Oracle Linux:9", Repos: []Repo{
		{BaseURL: srv.URL + "/core/snapshot-1/x86_64/"},
		{BaseURL: srv.URL + "/missing/aarch64/"},
	}})
	require.Error(t, err)
}

// A sha1 repomd checksum (Oracle Linux 7, its UEK channels) is verified like a
// sha256 one: a mismatch fails the read instead of passing unverified.
func TestFetch_SHA1ChecksumIsVerified(t *testing.T) {
	repo := newFakeRepo(t, "ol8-uekr6-updateinfo.xml")
	sum := sha1.Sum(repo.gz) //nolint:gosec // the algorithm under test
	repo.algo, repo.sum = "sha1", hex.EncodeToString(sum[:])
	srv := repo.server(t)
	src := Source{Ecosystem: "Oracle Linux:7", Repos: []Repo{{BaseURL: srv.URL + "/core/snapshot-1/x86_64/", Stream: "5.4"}}}
	advs, err := testClient(srv).Fetch(context.Background(), src)
	require.NoError(t, err)
	require.Len(t, advs, 1)
	require.Equal(t, "5.4", advs[0].Stream, "a stream repository's advisories carry its line")

	bad := newFakeRepo(t, "ol8-uekr6-updateinfo.xml")
	bad.algo, bad.sum = "sha1", "00"+hex.EncodeToString(sum[:])[2:]
	badSrv := bad.server(t)
	_, err = testClient(badSrv).Fetch(context.Background(),
		Source{Ecosystem: "Oracle Linux:7", Repos: []Repo{{BaseURL: badSrv.URL + "/core/snapshot-1/x86_64/"}}})
	require.ErrorContains(t, err, "sha1 mismatch")
}

func TestParseRepomd(t *testing.T) {
	href, sum, err := parseRepomd(bytes.NewReader([]byte(`<repomd><data type="updateinfo"><checksum type="sha256">ABC</checksum><location href="repodata/x-updateinfo.xml.gz"/></data></repomd>`)))
	require.NoError(t, err)
	require.Equal(t, "repodata/x-updateinfo.xml.gz", href)
	require.Equal(t, "sha256:abc", sum)

	_, sum, err = parseRepomd(bytes.NewReader([]byte(`<repomd><data type="updateinfo"><checksum type="sha">DEF</checksum><location href="repodata/u.xml.gz"/></data></repomd>`)))
	require.NoError(t, err)
	require.Equal(t, "sha1:def", sum, "createrepo's \"sha\" is sha1 (Oracle Linux 7)")
	for _, bad := range []string{
		`<checksum type="md5">abc</checksum>`,
		`<checksum type="sha256"></checksum>`,
		``,
	} {
		_, _, err = parseRepomd(bytes.NewReader([]byte(`<repomd><data type="updateinfo">` + bad + `<location href="repodata/u.xml.gz"/></data></repomd>`)))
		require.Error(t, err, "an updateinfo that cannot be verified is refused, never read unverified: %s", bad)
	}

	_, _, err = parseRepomd(bytes.NewReader([]byte(`<repomd><data type="primary"/></repomd>`)))
	require.Error(t, err)
	_, _, err = parseRepomd(bytes.NewReader([]byte(`<repomd><data type="updateinfo"><location href="../../etc/passwd"/></data></repomd>`)))
	require.Error(t, err, "a location may not escape the repository")
}

func TestCapReaderFailsInsteadOfTruncating(t *testing.T) {
	r := &capReader{r: bytes.NewReader(make([]byte, 10)), left: 4}
	buf := make([]byte, 8)
	n, err := r.Read(buf)
	require.NoError(t, err)
	require.Equal(t, 4, n)
	_, err = r.Read(buf)
	require.Error(t, err)
}

func TestSources(t *testing.T) {
	for _, s := range append(ALASSources(), ELSASources()...) {
		require.NotEmpty(t, s.Repos, s.Ecosystem)
		require.NotEmpty(t, s.Feed, s.Ecosystem)
		require.Contains(t, s.AdvisoryURL("X-1"), "X-1")
	}
	require.Equal(t, "https://alas.aws.amazon.com/AL2023/ALAS2023-2026-2136.html", ALASSources()[1].AdvisoryURL("ALAS2023-2026-2136"))
	require.Len(t, ELSASources()[1].Repos, 7, "Oracle Linux 8: baseos + appstream on both archs, UEKR6 (x86_64) and UEKR7 (both)")
	for _, s := range append(ALASSources(), ELSASources()...) {
		for _, r := range s.Repos {
			if strings.Contains(r.key(), "UEK") || strings.Contains(r.key(), "/extras/kernel-") {
				require.NotEmpty(t, r.Stream, "a kernel channel is read as a stream: %s", r.key())
			} else {
				require.Empty(t, r.Stream, r.key())
			}
		}
	}
}
