// Package github collects repositories from a GitHub App installation. Each
// repo becomes an asset; collection authenticates as the App, exchanges its JWT
// for an installation token, and pages the installation's repositories.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/pkg/log"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

const (
	defaultBaseURL = "https://api.github.com"
	httpTimeout    = 30 * time.Second
	perPage        = 100
)

// maxPages bounds every paginated GitHub list in this package (repos, GHAS
// alerts, ...) at 5,000 items (perPage * maxPages) — a generous ceiling, but a
// hard one: a self-host with a larger org than that silently truncates its
// inventory past it with no way to raise it, short of GITHUB_MAX_PAGES. Read
// once at process start, not per-connector: unlike cfg["base_url"], this
// isn't something one connector needs different from another.
var maxPages = envIntOr("GITHUB_MAX_PAGES", 50)

func envIntOr(key string, fallback int) int {
	if n, err := strconv.Atoi(os.Getenv(key)); err == nil && n > 0 {
		return n
	}
	return fallback
}

// Collector implements collect.Collector for GitHub. It is shared across
// concurrent sync workers, so Collect holds NO per-call state on the receiver —
// the per-connector base URL is a local threaded through each request.
type Collector struct {
	client *http.Client
	// baseURL is the default endpoint; a connector may override it per call via
	// cfg["base_url"] (GHES). Tests set it directly. It is never mutated by Collect.
	baseURL string
	// manifestTree lists candidate manifest file paths for a repo (default-branch
	// tree, *.yaml/*.yml, fixture paths skipped). Seam for tests.
	manifestTree func(ctx context.Context, baseURL, token string, r repo) []string
	// manifestFile fetches one file's content. Seam for tests; defaults to fetchFileContent.
	manifestFile func(ctx context.Context, baseURL, token string, r repo, path string) (string, bool)
	// workflowTree lists a repo's .github/workflows/*.{yml,yaml} blob paths
	// (default-branch tree, capped). Seam for tests.
	workflowTree func(ctx context.Context, baseURL, token string, r repo) []string
	// workflowFile fetches one file's content. Seam for tests; defaults to fetchFileContent.
	workflowFile func(ctx context.Context, baseURL, token string, r repo, path string) (string, bool)
	// tfStateFiles fetches a repo's *.tf file contents (filename -> content).
	// Seam for tests; defaults to fetchTerraformFiles (shared with collectIaC).
	tfStateFiles func(ctx context.Context, baseURL, token string, r repo) map[string]string
	// tfStateObj reads Terraform state objects from S3 (live AWS capability).
	// nil by default — TF-state ingest is a clean no-op until wired via
	// SetTFStateAWS (cmd/graph/worker.go passes the shared mcp.LiveAWSCallerImpl).
	tfStateObj tfStateReader
	// tfStateConn resolves an AWS account id to the connector that can read it.
	// nil by default; see tfStateObj.
	tfStateConn connByAccount
	// tfStateBucketAcct resolves a state bucket to ITS OWN AWS account id (the
	// s3_bucket asset's AccountID), so each bucket is read from the right
	// account rather than a single operator-configured one
	// (multi-account). nil by default — collectTFState then falls back to the
	// cfg["tfstate_aws_account_id"] single-account path. See SetTFStateAWS.
	tfStateBucketAcct bucketAccountResolver
	// harvestFiles returns the contents of a repo's candidate files, up to the
	// fetch cap (path -> content). Seam for tests; defaults to fetchHarvestFiles.
	harvestFiles func(ctx context.Context, baseURL, token string, r repo) map[string]string
	// priorRepoMeta returns the stored metadata of github_repo assets by ID, so
	// a repo whose CODEOWNERS read failed this sweep keeps its stored rules.
	// nil by default (nothing is carried forward); see SetPriorRepoMetadata.
	priorRepoMeta priorRepoMetadata
}

// priorRepoMetadata returns stored repo asset metadata keyed by repo ID
// (full name). Repos with no stored asset are absent.
type priorRepoMetadata func(ctx context.Context, repoIDs []string) (map[string]map[string]string, error)

// SetPriorRepoMetadata wires the stored-metadata lookup collectCodeowners uses
// to keep an unread repo's rules (cmd/graph/worker.go passes a closure over
// asset.Service.ByIDs).
func (c *Collector) SetPriorRepoMetadata(fn priorRepoMetadata) {
	c.priorRepoMeta = fn
}

// SetTFStateAWS wires the live S3 GetObject capability, the per-bucket
// account resolver, and the account→connector resolver that TF-state ingest
// needs. All are nil until this is called — cmd/graph/worker.go
// calls it once at startup with the shared mcp.LiveAWSCallerImpl, a closure
// over asset.Service.ByIDs, and connector.Service.ConnectorByAccountID. Left
// unwired (e.g. in tests that don't exercise it), collectTFState is a clean
// no-op (or falls back to the cfg-account path if only bucketAcct is nil).
func (c *Collector) SetTFStateAWS(obj tfStateReader, bucketAcct bucketAccountResolver, conn connByAccount) {
	c.tfStateObj = obj
	c.tfStateBucketAcct = bucketAcct
	c.tfStateConn = conn
}

func New() *Collector {
	c := &Collector{client: safenet.New(httpTimeout), baseURL: defaultBaseURL}
	c.manifestTree = c.listManifestPaths
	c.manifestFile = c.fetchFileContent
	c.workflowTree = c.listWorkflowPaths
	c.workflowFile = c.fetchFileContent
	c.tfStateFiles = c.fetchTerraformFiles
	c.harvestFiles = c.fetchHarvestFiles
	return c
}

// checkBaseURL requires a connector-supplied GHES base_url to be https: the
// App JWT and installation token ride every request. Plain http is allowed
// only to a loopback host (local testing).
func checkBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid base_url %q", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		h := u.Hostname()
		if ip := net.ParseIP(h); h == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return fmt.Errorf("base_url %q must use https", raw)
}

// Collect authenticates with the App credentials in cfg and returns one asset
// per repository the installation can see.
func (c *Collector) Collect(ctx context.Context, cfg map[string]string) (collect.Result, error) {
	appID := cfg["app_id"]
	installationID := cfg["installation_id"]
	baseURL := c.baseURL
	if base := cfg["base_url"]; base != "" {
		if err := checkBaseURL(base); err != nil {
			return collect.Result{}, fmt.Errorf("Collect: %w", err)
		}
		baseURL = base
	}

	jwtToken, err := appJWT(appID, cfg["private_key_pem"])
	if err != nil {
		return collect.Result{}, fmt.Errorf("Collect: %w", err)
	}
	instToken, err := c.installationToken(ctx, baseURL, installationID, jwtToken)
	if err != nil {
		return collect.Result{}, fmt.Errorf("Collect: %w", err)
	}
	repos, reposPartial, err := c.listRepos(ctx, baseURL, instToken)
	if err != nil {
		return collect.Result{}, fmt.Errorf("Collect: %w", err)
	}

	// Dependencies become graph nodes: each repo's SBOM yields package assets
	// and repo→package depends_on edges.
	pkgAssets, edges := c.collectPackages(ctx, baseURL, instToken, repos)

	// GHAS: code-scanning + secret-scanning alerts become findings that flow
	// through the enrichment → reasoning pipeline. Org-level list endpoints
	// with a per-repo fallback; skipped repos are counted and summarised.
	ghasFindings, ghasClosed := c.collectGHAS(ctx, baseURL, instToken, repos)

	// Branch protection: check whether each repo's default branch is protected.
	branchProtection := c.collectBranchProtection(ctx, baseURL, instToken, repos)

	// CODEOWNERS: stamped on each repo asset so owner resolution can route a
	// resource declared in this repo to the team owning the declaring file.
	codeowners, codeownersFile := c.collectCodeowners(ctx, baseURL, instToken, repos)

	// IaC: scan each repo's Terraform for misconfigurations (shift-left).
	// Best-effort per repo; findings are keyed to the github_repo asset.
	iacFindings := c.collectIaC(ctx, baseURL, instToken, repos)

	// k8s manifest IaC: parse plain manifests into declared_k8s_workload assets;
	// the K8sManifestOwnership correlate rule joins them to live k8s assets and
	// emits defined_in ownership edges.
	k8sDeclared := c.collectK8sManifests(ctx, baseURL, instToken, repos)

	// CI workflow IaC: parse every non-archived repo's .github/workflows/ for
	// declared cloud-identity intents (role-to-assume / service_account) into
	// declared_ci_access assets; the ci_access correlate rule later joins these
	// to live iam_role/gcp_service_account assets.
	workflowDeclared := c.collectWorkflows(ctx, baseURL, instToken, repos)

	// Generic repo harvest: sweep EVERY repo for the concrete identifiers written
	// in its files — cloud identities (role ARNs, service-account emails, GitHub
	// OIDC subjects) into declared_cloud_identity, and private-registry container
	// image paths into declared_image_build. The declared_identity_ownership and
	// image_ownership correlate rules join them to live assets. It takes no
	// configuration and no per-tool parser, so it reaches every org and tool —
	// and it is the only signal that links a running image back to its repo when
	// an image carries no OCI source/revision labels or build provenance.
	harvestDeclared := c.collectRepoHarvest(ctx, baseURL, instToken, repos)

	// Terraform state IaC: read each repo's S3-backed tfstate (when a static
	// backend block names it) and address-confirm state resources against the
	// repo's own .tf into declared_tf_resource assets; the tf_ownership
	// correlate rule later joins these to live assets by arn/id.
	tfStateDeclared, tfStateFindings := c.collectTFState(ctx, baseURL, instToken, repos, c.tfStateObj, c.tfStateBucketAcct, c.tfStateConn, cfg["tfstate_aws_account_id"])

	now := time.Now()
	assets := make([]asset.Asset, 0, len(repos)+len(pkgAssets))
	for _, r := range repos {
		meta := map[string]string{
			"visibility":     r.Visibility,
			"archived":       strconv.FormatBool(r.Archived),
			"language":       r.Language,
			"default_branch": r.DefaultBranch,
		}
		// Absent = we never observed the branch's protection state. Writing
		// "disabled" there would turn a missing App permission into a flood of false findings.
		if bp, ok := branchProtection[r.FullName]; ok {
			meta["branch_protection"] = bp
		}
		if co, ok := codeowners[r.FullName]; ok {
			meta[asset.MetaCodeowners] = co
		}
		if state, ok := codeownersFile[r.FullName]; ok {
			meta[asset.MetaCodeownersFile] = state
		}
		assets = append(assets, asset.Asset{
			ID:           r.FullName,
			Name:         r.Name,
			Type:         "github_repo",
			Provider:     asset.ProviderGitHub,
			Region:       "global",
			Endpoint:     r.HTMLURL,
			Metadata:     meta,
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	assets = append(assets, pkgAssets...)
	assets = append(assets, k8sDeclared...)
	assets = append(assets, workflowDeclared...)
	assets = append(assets, tfStateDeclared...)
	assets = append(assets, harvestDeclared...)
	findings := append(ghasFindings, iacFindings...)
	findings = append(findings, tfStateFindings...)
	// reposPartial: the repo list paged out early (rate-limit/5xx), so repos on
	// the un-fetched pages are missing from Assets — mark the result partial so
	// the sync worker does not mistake them for deleted.
	result := collect.Result{Assets: assets, Edges: edges, Findings: findings, Partial: reposPartial, ClosedFindings: ghasClosed}

	// The repo listing is the only enumeration in this collector that can ever
	// be claimed complete: it is the sole listing whose own loop (listRepos)
	// returns a page-read failure or a maxPages truncation as an explicit
	// signal rather than swallowing it and moving on. Every derived listing
	// below it (branch protection, GHAS, IaC, k8s/workflow/tfstate
	// declarations, the repo harvest) is deliberately best-effort per
	// repo — it counts and logs skips but folds them into the same success
	// path, so a nil error there is not the "no page failed" guarantee
	// MarkComplete requires. Claiming any of those would be exactly the
	// over-claim the contract forbids.
	//
	// Scope is keyed by installation, not org name (not reliably known here),
	// matching what actually bounds this listing's API surface.
	if !reposPartial {
		result.MarkComplete(installationID+"/github:repos", []string{"github_repo"}, len(repos))
	}

	return result, nil
}

// normalizePEM repairs a PEM key whose line breaks were flattened — e.g. set
// via `helm --set github.privateKey=...`, which strips newlines, leaving the
// whole key on one line that Go's PEM parser rejects. It rebuilds the header/
// footer and re-wraps the base64 body at 64 columns. A key that already has
// newlines is returned unchanged.
func normalizePEM(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, "\n") {
		return s
	}
	const beginTag, endTag = "-----BEGIN ", "-----END "
	if !strings.HasPrefix(s, beginTag) {
		return s
	}
	ei := strings.Index(s, endTag)
	if ei < 0 {
		return s
	}
	hdrClose := strings.Index(s[len(beginTag):], "-----")
	if hdrClose < 0 {
		return s
	}
	header := s[:len(beginTag)+hdrClose+len("-----")]
	footer := s[ei:]
	body := strings.Join(strings.Fields(s[len(header):ei]), "")

	var b strings.Builder
	b.WriteString(header)
	b.WriteByte('\n')
	for i := 0; i < len(body); i += 64 {
		b.WriteString(body[i:min(i+64, len(body))])
		b.WriteByte('\n')
	}
	b.WriteString(footer)
	b.WriteByte('\n')
	return b.String()
}

// appJWT builds the short-lived RS256 JWT that authenticates as the App itself.
func appJWT(appID, privateKeyPEM string) (string, error) {
	if appID == "" || privateKeyPEM == "" {
		return "", fmt.Errorf("appJWT: app_id and private_key_pem are required")
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(normalizePEM(privateKeyPEM)))
	if err != nil {
		return "", fmt.Errorf("appJWT: parse key: %w", err)
	}
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer:    appID,
		IssuedAt:  jwt.NewNumericDate(now.Add(-30 * time.Second)), // clock-skew slack
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),   // GitHub max is 10m
	})
	signed, err := tok.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("appJWT: sign: %w", err)
	}
	return signed, nil
}

func (c *Collector) installationToken(ctx context.Context, baseURL, installationID, jwtToken string) (string, error) {
	if installationID == "" {
		return "", fmt.Errorf("installationToken: installation_id is required")
	}
	url := baseURL + "/app/installations/" + installationID + "/access_tokens"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", fmt.Errorf("installationToken: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	var body struct {
		Token string `json:"token"`
	}
	if err := c.doJSON(req, http.StatusCreated, &body); err != nil {
		return "", fmt.Errorf("installationToken: %w", err)
	}
	if body.Token == "" {
		return "", fmt.Errorf("installationToken: empty token in response")
	}
	return body.Token, nil
}

type repo struct {
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	HTMLURL       string `json:"html_url"`
	Visibility    string `json:"visibility"`
	Archived      bool   `json:"archived"`
	Language      string `json:"language"`
	DefaultBranch string `json:"default_branch"`
}

// listRepos returns the installation's repos. The bool is true when the listing
// paged out early — either after retries (partial inventory) or because it hit
// maxPages with a still-full last page, so pages beyond the ceiling may exist
// and were never read. Either way the caller must mark the Result partial so
// absent repos are not mistaken for deleted, and must NOT claim this
// enumeration complete: a nil error here is not a completeness guarantee by
// itself, only "no page we read failed."
func (c *Collector) listRepos(ctx context.Context, baseURL, token string) ([]repo, bool, error) {
	var all []repo
	seen := map[string]bool{}
	for page := 1; page <= maxPages; page++ {
		url := fmt.Sprintf("%s/installation/repositories?per_page=%d&page=%d", baseURL, perPage, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, false, fmt.Errorf("listRepos: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")

		var body struct {
			Repositories *[]repo `json:"repositories"`
		}
		if err := c.doJSON(req, http.StatusOK, &body); err != nil {
			// A mid-pagination failure (after retries) returns the repos we
			// have instead of aborting the connector — one flaky late-page 502
			// must not throw away all the repos of a sync. Signalled partial so
			// the sync worker skips deletion reconciliation for the missing pages.
			if page > 1 {
				log.FromContext(ctx).Warn().Err(err).Int("page", page).Int("repos_collected", len(all)).
					Msg("listRepos: page failed after retries — continuing with partial repo list")
				return all, true, nil
			}
			return nil, false, fmt.Errorf("listRepos: page %d: %w", page, err)
		}
		if body.Repositories == nil {
			return nil, false, fmt.Errorf("listRepos: page %d omitted repositories", page)
		}
		for _, r := range *body.Repositories {
			owner, name, ok := strings.Cut(r.FullName, "/")
			if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
				return nil, false, fmt.Errorf("listRepos: page %d returned a repository without a valid full name", page)
			}
			if seen[r.FullName] {
				log.FromContext(ctx).Warn().Int("page", page).Msg("repository listing repeated an identity; treating the enumeration as partial")
				return all, true, nil
			}
			seen[r.FullName] = true
			all = append(all, r)
		}
		if len(*body.Repositories) < perPage {
			return all, false, nil // last page — genuinely exhausted, not truncated
		}
		if page == maxPages {
			// The ceiling was reached with a still-full last page: there is no
			// way to tell whether the installation has exactly maxPages*perPage
			// repos or many more beyond the ceiling. Either way this walk did
			// not read every page, so it is truncated, not complete.
			log.FromContext(ctx).Warn().Int("repos_collected", len(all)).Int("max_pages", maxPages).
				Msg("listRepos: hit maxPages ceiling with a full last page — repo list truncated")
			return all, true, nil
		}
	}
	return all, false, nil
}

// apiError carries the status of a failed GitHub call so callers can
// distinguish 404 not-enabled / 403 unlicensed / 403 rate-limited. GitHub
// signals primary-limit exhaustion as 403 with X-RateLimit-Remaining: 0 —
// that is starvation, not a licensing state, and must never be classified
// as "GHAS not enabled".
type apiError struct {
	status      int
	rateLimited bool
}

func (e *apiError) Error() string {
	if e.rateLimited {
		return fmt.Sprintf("unexpected status %d (rate limited)", e.status)
	}
	return fmt.Sprintf("unexpected status %d", e.status)
}

// doJSON sends req, requires wantStatus, and decodes the body into out.
// It tracks X-RateLimit-* headers to throttle proactively and retries
// 429 and transient 5xx responses.
func (c *Collector) doJSON(req *http.Request, wantStatus int, out any) error {
	// Derive the rate-limit bucket from the installation token so concurrent
	// syncs for different connectors track independently.
	token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	rs := getRateState(token)

	for attempt := 0; attempt < 3; attempt++ {
		// Wait proactively if we're near the rate limit ceiling.
		if err := rs.waitIfNeeded(req.Context()); err != nil {
			return fmt.Errorf("doJSON: rate limit wait: %w", err)
		}

		resp, err := c.client.Do(req)
		if err != nil {
			return fmt.Errorf("doJSON: %w", err)
		}
		// Always update rate state from response headers, even on error responses.
		rs.update(resp)

		if resp.StatusCode == http.StatusTooManyRequests {
			_ = resp.Body.Close()
			// Secondary rate limit — honour Retry-After or fall back to 60s.
			wait := 60 * time.Second
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if s, err := strconv.Atoi(ra); err == nil && s > 0 {
					wait = time.Duration(s) * time.Second
				}
			}
			select {
			case <-req.Context().Done():
				return req.Context().Err()
			case <-time.After(wait):
				req = retryClone(req)
				continue
			}
		}
		// Transient upstream failure — retry twice with short backoff (otherwise
		// a single 502 fails the request, and via listRepos the whole
		// connector sync).
		if resp.StatusCode >= 500 && attempt < 2 {
			_ = resp.Body.Close()
			select {
			case <-req.Context().Done():
				return req.Context().Err()
			case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
			}
			req = retryClone(req)
			continue
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != wantStatus {
			return fmt.Errorf("doJSON: %w", &apiError{
				status:      resp.StatusCode,
				rateLimited: resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0",
			})
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("doJSON: decode: %w", err)
		}
		return nil
	}
	return fmt.Errorf("doJSON: exceeded 3 retries on rate limit")
}

// retryClone prepares a request for another attempt. Cloning alone is not
// enough for a POST: Do consumed the body, and the clone carries the same
// drained reader, so a retried GraphQL query would go out with an empty body
// and 400. GetBody rewinds it.
func retryClone(req *http.Request) *http.Request {
	clone := req.Clone(req.Context())
	if req.GetBody != nil {
		if body, err := req.GetBody(); err == nil {
			clone.Body = body
		}
	}
	return clone
}
