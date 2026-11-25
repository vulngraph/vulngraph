package updateinfo

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha1" //nolint:gosec // verifying what Oracle Linux 7 repomd publishes, not choosing a hash
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/pkg/safenet"
)

const (
	// httpTimeout bounds one request; the largest file (Oracle Linux 8
	// appstream updateinfo) is ~7 MB compressed.
	httpTimeout = 5 * time.Minute
	// maxCompressed / maxExpanded cap one updateinfo download: a repository
	// that grows past them is a broken mirror, not data.
	maxCompressed = 128 << 20
	maxExpanded   = 512 << 20
	maxSmallFile  = 1 << 20 // mirror.list, repomd.xml
)

// Repo is one yum repository. Amazon Linux publishes a mirror list whose first
// line is the current base URL (the base moves with every release snapshot);
// Oracle's repositories have a fixed base.
type Repo struct {
	BaseURL    string
	MirrorList string
	// Stream is the kernel line a stream repository serves ("5.10", Amazon
	// Linux 2 kernel extras; "5.15", an Oracle UEK channel). Every line ships
	// the same package names (kernel, kernel-uek, perf, bpftool) at its own
	// version, so its advisories are scoped to it (ScopeToStream). Empty for a
	// release's core repositories.
	Stream string
}

func (r Repo) key() string {
	if r.MirrorList != "" {
		return r.MirrorList
	}
	return r.BaseURL
}

// Source is one release's advisory feed: every repository whose updateinfo
// together lists the release's advisories.
type Source struct {
	// Feed is the distro.Source* name ("alas", "elsa").
	Feed string
	// Ecosystem is the package coordinate the release's inventory carries
	// ("Amazon Linux:2023").
	Ecosystem string
	Repos     []Repo
	// URLPrefix + advisory id (+ URLSuffix) is the advisory's public page.
	URLPrefix, URLSuffix string
}

// AdvisoryURL is the public page of one advisory.
func (s Source) AdvisoryURL(id string) string { return s.URLPrefix + id + s.URLSuffix }

// Client fetches and caches updateinfo per repository. The cache is process
// memory: repomd.xml is re-requested every run with If-None-Match /
// If-Modified-Since (both CDNs honour them), and updateinfo itself is only
// downloaded when repomd's checksum for it changed — so a steady-state run
// costs one small conditional request per repository.
type Client struct {
	http *http.Client
	mu   sync.Mutex
	repo map[string]*repoState
}

type repoState struct {
	repomdURL    string
	etag         string
	lastModified string
	checksum     string
	advisories   []Advisory
}

// NewClient builds a client on a safenet HTTP client: the repositories are
// public internet hosts, and the mirror list names the next host to fetch.
func NewClient() *Client {
	return &Client{http: safenet.New(httpTimeout), repo: map[string]*repoState{}}
}

// Fetch returns a release's security advisories, merged across its
// repositories. Every repository must be read: a partial set would let the
// caller resolve findings whose advisory merely lives in the unread repository.
func (c *Client) Fetch(ctx context.Context, src Source) ([]Advisory, error) {
	lists := make([][]Advisory, 0, len(src.Repos))
	for _, r := range src.Repos {
		advs, err := c.fetchRepo(ctx, r)
		if err != nil {
			return nil, fmt.Errorf("Fetch %s: %w", src.Ecosystem, err)
		}
		if r.Stream != "" {
			advs = ScopeToStream(advs, r.Stream)
		}
		lists = append(lists, advs)
	}
	return merge(lists...), nil
}

func (c *Client) fetchRepo(ctx context.Context, r Repo) ([]Advisory, error) {
	base := r.BaseURL
	if r.MirrorList != "" {
		var err error
		if base, err = c.resolveMirror(ctx, r.MirrorList); err != nil {
			return nil, err
		}
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}

	c.mu.Lock()
	st := c.repo[r.key()]
	if st == nil {
		st = &repoState{}
		c.repo[r.key()] = st
	}
	prev := *st
	c.mu.Unlock()

	repomdURL := base + "repodata/repomd.xml"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, repomdURL, nil)
	if err != nil {
		return nil, fmt.Errorf("fetchRepo: %w", err)
	}
	if prev.repomdURL == repomdURL && prev.advisories != nil {
		if prev.etag != "" {
			req.Header.Set("If-None-Match", prev.etag)
		}
		if prev.lastModified != "" {
			req.Header.Set("If-Modified-Since", prev.lastModified)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetchRepo: repomd: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotModified && prev.advisories != nil {
		return prev.advisories, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetchRepo: repomd %s: unexpected status %d", repomdURL, resp.StatusCode)
	}
	href, sum, err := parseRepomd(io.LimitReader(resp.Body, maxSmallFile))
	if err != nil {
		return nil, fmt.Errorf("fetchRepo: %s: %w", repomdURL, err)
	}

	next := repoState{
		repomdURL:    repomdURL,
		etag:         resp.Header.Get("ETag"),
		lastModified: resp.Header.Get("Last-Modified"),
		checksum:     sum,
		advisories:   prev.advisories,
	}
	if prev.checksum == "" || prev.checksum != sum || prev.advisories == nil {
		if next.advisories, err = c.download(ctx, base+href, sum); err != nil {
			return nil, err
		}
	}
	c.mu.Lock()
	*st = next
	c.mu.Unlock()
	return next.advisories, nil
}

// resolveMirror reads a mirror list and returns its first https base URL.
func (c *Client) resolveMirror(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("resolveMirror: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("resolveMirror: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("resolveMirror %s: unexpected status %d", url, resp.StatusCode)
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, maxSmallFile))
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); strings.HasPrefix(line, "https://") {
			return line, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("resolveMirror %s: %w", url, err)
	}
	return "", fmt.Errorf("resolveMirror %s: no https mirror listed", url)
}

// parseRepomd finds the updateinfo record in repomd.xml: its location and the
// checksum of the (compressed) file as "algorithm:hex". A record whose checksum
// is missing or of an algorithm download cannot verify is refused: an
// unverified download can be truncated or tampered with and still parse into a
// short advisory list that reads as complete. Older repositories (Oracle Linux
// 7) publish sha1; createrepo spells it "sha" too.
func parseRepomd(r io.Reader) (href, checksum string, err error) {
	var doc struct {
		Data []struct {
			Type     string `xml:"type,attr"`
			Checksum struct {
				Type  string `xml:"type,attr"`
				Value string `xml:",chardata"`
			} `xml:"checksum"`
			Location struct {
				Href string `xml:"href,attr"`
			} `xml:"location"`
		} `xml:"data"`
	}
	if err := xml.NewDecoder(r).Decode(&doc); err != nil {
		return "", "", fmt.Errorf("parseRepomd: %w", err)
	}
	for _, d := range doc.Data {
		if d.Type != "updateinfo" {
			continue
		}
		if d.Location.Href == "" || strings.Contains(d.Location.Href, "..") || strings.HasPrefix(d.Location.Href, "/") {
			return "", "", fmt.Errorf("parseRepomd: bad updateinfo location %q", d.Location.Href)
		}
		algo := strings.ToLower(strings.TrimSpace(d.Checksum.Type))
		if algo == "sha" {
			algo = "sha1"
		}
		sum := strings.ToLower(strings.TrimSpace(d.Checksum.Value))
		if newHash(algo) == nil || sum == "" {
			return "", "", fmt.Errorf("parseRepomd: updateinfo checksum %q is unverifiable", d.Checksum.Type)
		}
		return d.Location.Href, algo + ":" + sum, nil
	}
	return "", "", errors.New("parseRepomd: repository publishes no updateinfo")
}

// download fetches, verifies and parses one updateinfo file. The checksum repomd
// lists ("algorithm:hex", parseRepomd) is checked over the compressed bytes
// after parsing: a truncated or tampered download fails instead of yielding a
// short advisory list.
func (c *Client) download(ctx context.Context, url, checksum string) ([]Advisory, error) {
	algo, wantSum, _ := strings.Cut(checksum, ":")
	h := newHash(algo)
	if h == nil || wantSum == "" {
		return nil, fmt.Errorf("download %s: unverifiable checksum %q", url, checksum)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: unexpected status %d", url, resp.StatusCode)
	}

	raw := io.TeeReader(io.LimitReader(resp.Body, maxCompressed+1), h)
	body := raw
	if strings.HasSuffix(url, ".gz") {
		gz, err := gzip.NewReader(raw)
		if err != nil {
			return nil, fmt.Errorf("download %s: %w", url, err)
		}
		defer func() { _ = gz.Close() }()
		body = gz
	} else if !strings.HasSuffix(url, ".xml") {
		return nil, fmt.Errorf("download %s: unsupported compression", url)
	}
	limited := &capReader{r: body, left: maxExpanded}
	advs, err := Parse(limited)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	// Drain so the hash covers the whole file (gzip may stop before trailing bytes).
	if _, err := io.Copy(io.Discard, raw); err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	if hex.EncodeToString(h.Sum(nil)) != wantSum {
		return nil, fmt.Errorf("download %s: %s mismatch with repomd", url, algo)
	}
	return advs, nil
}

// newHash is the hash for a repomd checksum type, or nil for one download
// cannot verify.
func newHash(algo string) hash.Hash {
	switch algo {
	case "sha1":
		return sha1.New()
	case "sha256":
		return sha256.New()
	case "sha512":
		return sha512.New()
	}
	return nil
}

// capReader fails, rather than truncates, past its limit: a silently short
// advisory list is exactly the degraded input that must not read as complete.
type capReader struct {
	r    io.Reader
	left int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, errors.New("updateinfo exceeds size cap")
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}
