package github

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// sbomConcurrency bounds the SBOM fan-out: one request per repo, at most this
// many in flight. 8 triggers secondary-rate-limit (429) bursts against the
// GitHub dependency-graph API — 3 stays well within the sustained-request limit
// while keeping wall-clock time reasonable.
const sbomConcurrency = 3

// purlEcosystems maps a purl type to the OSV ecosystem name. A purl
// type not listed here has no OSV feed coverage and is skipped.
var purlEcosystems = map[string]string{
	"npm":           "npm",
	"pypi":          "PyPI",
	"golang":        "Go",
	"maven":         "Maven",
	"cargo":         "crates.io",
	"composer":      "Packagist",
	"gem":           "RubyGems",
	"nuget":         "NuGet",
	"pub":           "Pub",
	"hex":           "Hex",
	"githubactions": "GitHub Actions",
}

// pkgCoords are the canonical coordinates of one dependency. Ecosystem and Name
// follow OSV conventions (e.g. Maven "group:artifact") so the intel feed can
// query them without translation.
type pkgCoords struct {
	Ecosystem string
	Name      string
	Version   string
	Purl      string
}

// collectPackages fetches the dependency-graph SBOM of every non-archived repo
// (bounded fan-out) and returns one "package" asset per distinct dependency
// plus a repo→package "depends_on" edge per occurrence. A repo whose SBOM is
// unavailable (dependency graph disabled, 404/403) is logged and skipped —
// package inventory degrades, collection never fails on it.
func (c *Collector) collectPackages(ctx context.Context, baseURL, token string, repos []repo) ([]asset.Asset, []asset.Edge) {
	logger := log.FromContext(ctx)
	now := time.Now()

	var (
		mu     sync.Mutex
		byPurl = map[string]asset.Asset{}
		edges  []asset.Edge
		wg     sync.WaitGroup
		sem    = make(chan struct{}, sbomConcurrency)
	)
	for _, r := range repos {
		if r.Archived {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error().Any("panic", rec).Str("repo", r.FullName).
						Msg("sbom collection panicked; repo skipped")
				}
			}()

			pkgs, err := c.fetchSBOM(ctx, baseURL, token, r.FullName)
			if err != nil {
				logger.Warn().Err(err).Str("repo", r.FullName).
					Msg("sbom unavailable; repo skipped")
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, p := range pkgs {
				if _, seen := byPurl[p.Purl]; !seen {
					byPurl[p.Purl] = asset.Asset{
						ID:       p.Purl,
						Name:     p.Name,
						Type:     "package",
						Provider: asset.ProviderGitHub,
						Region:   "global",
						Metadata: map[string]string{
							"ecosystem": p.Ecosystem,
							"package":   p.Name,
							"version":   p.Version,
						},
						DiscoveredAt: now,
						LastSeen:     now,
					}
				}
				edges = append(edges, asset.Edge{
					SrcID: r.FullName, SrcType: "github_repo",
					DstID: p.Purl, DstType: "package",
					EdgeType: "depends_on",
				})
			}
		}()
	}
	wg.Wait()

	assets := make([]asset.Asset, 0, len(byPurl))
	for _, a := range byPurl {
		assets = append(assets, a)
	}
	// Map iteration order is random; sorted output keeps ingest batches (and
	// tests) deterministic.
	sort.Slice(assets, func(i, j int) bool { return assets[i].ID < assets[j].ID })
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].SrcID != edges[j].SrcID {
			return edges[i].SrcID < edges[j].SrcID
		}
		return edges[i].DstID < edges[j].DstID
	})
	return assets, edges
}

// fetchSBOM downloads one repo's SPDX SBOM and returns the dependencies that
// carry a purl in an OSV-covered ecosystem.
func (c *Collector) fetchSBOM(ctx context.Context, baseURL, token, fullName string) ([]pkgCoords, error) {
	u := baseURL + "/repos/" + fullName + "/dependency-graph/sbom"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("fetchSBOM: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	var body struct {
		SBOM struct {
			Packages []struct {
				ExternalRefs []struct {
					ReferenceType    string `json:"referenceType"`
					ReferenceLocator string `json:"referenceLocator"`
				} `json:"externalRefs"`
			} `json:"packages"`
		} `json:"sbom"`
	}
	if err := c.doJSON(req, http.StatusOK, &body); err != nil {
		return nil, fmt.Errorf("fetchSBOM: %s: %w", fullName, err)
	}

	var out []pkgCoords
	for _, p := range body.SBOM.Packages {
		for _, ref := range p.ExternalRefs {
			if ref.ReferenceType != "purl" {
				continue
			}
			if coords, ok := parsePurl(ref.ReferenceLocator); ok {
				out = append(out, coords)
			}
			break // at most one purl per package
		}
	}
	return out, nil
}

// parsePurl extracts OSV-convention coordinates from a package URL
// (pkg:type/namespace/name@version). It reports ok=false for purls without a
// version or in ecosystems OSV does not cover.
func parsePurl(purl string) (pkgCoords, bool) {
	rest, found := strings.CutPrefix(purl, "pkg:")
	if !found {
		return pkgCoords{}, false
	}
	// Qualifiers and subpath are irrelevant to identity.
	rest, _, _ = strings.Cut(rest, "?")
	rest, _, _ = strings.Cut(rest, "#")

	at := strings.LastIndex(rest, "@")
	if at <= 0 || at == len(rest)-1 {
		return pkgCoords{}, false
	}
	path, version := rest[:at], rest[at+1:]

	typ, name, found := strings.Cut(path, "/")
	if !found || name == "" {
		return pkgCoords{}, false
	}
	eco, ok := purlEcosystems[strings.ToLower(typ)]
	if !ok {
		return pkgCoords{}, false
	}

	segs := strings.Split(name, "/")
	for i, s := range segs {
		if dec, err := url.PathUnescape(s); err == nil {
			segs[i] = dec
		}
	}
	// OSV names Maven packages "group:artifact"; every other ecosystem keeps the
	// purl path form (e.g. npm "@scope/name", Go "github.com/org/mod").
	sep := "/"
	if eco == "Maven" {
		sep = ":"
	}
	canonical := strings.Join(segs, sep)

	return pkgCoords{
		Ecosystem: eco,
		Name:      canonical,
		Version:   version,
		Purl:      "pkg:" + strings.ToLower(typ) + "/" + strings.Join(segs, "/") + "@" + goCanonicalVersion(eco, version),
	}, true
}

// goCanonicalVersion restores the leading "v" on Go module versions in the PURL,
// which is the package node's graph id.
//
// GitHub's dependency graph inconsistently emits Go module versions with and
// without the "v" prefix, while the image scanner (reading go.mod/buildinfo)
// only ever emits the v-prefixed form; without canonicalizing, the same module
// forks into two package nodes and image findings can't match their repo SBOM.
//
// Only the PURL is canonicalised, not the reported Version — Version feeds the
// OSV query, and OSV accepts both spellings, so rewriting it would just change
// what we report without fixing anything.
//
// Re-keying is self-healing: depends_on edges are re-derived from the SBOM
// every sweep, so they re-point within one cycle, and superseded package rows
// age out under the assets TTL.
func goCanonicalVersion(eco, version string) string {
	if eco != "Go" || version == "" || version[0] == 'v' {
		return version
	}
	// Only a version that actually starts with a digit is a semver missing its
	// prefix; anything else (a commit sha, "latest", a build id) is not a Go
	// module version and must pass through untouched.
	if version[0] < '0' || version[0] > '9' {
		return version
	}
	return "v" + version
}
