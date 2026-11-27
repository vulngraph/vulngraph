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
	// sbomWait is a test clock seam; nil uses a context-aware timer.
	sbomWait func(context.Context, time.Duration) error
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
	workflowTree func(ctx context.Context, baseURL, token string, r repo) ([]string, bool)
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
	c.workflowTree = c.workflowPathsChecked
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
		return fmt.Errorf("invalid base_url")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("base_url must not contain credentials, query parameters or a fragment")
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
	return fmt.Errorf("base_url must use https")
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
	credential, err := c.installationTokenInfo(ctx, baseURL, installationID, jwtToken)
	if err != nil {
		return collect.Result{}, fmt.Errorf("Collect: %w", err)
	}
	instToken := credential.Token
	repos, reposPartial, err := c.listRepos(ctx, baseURL, instToken)
	if err != nil {
		return collect.Result{}, fmt.Errorf("Collect: %w", err)
	}

	// Dependencies become graph nodes: each repo's SBOM yields package assets
	// and repo→package depends_on edges.
	pkgAssets, edges, sbomCoverage := c.collectPackages(ctx, baseURL, instToken, repos)
	sbomPartial := false
	for _, coverage := range sbomCoverage {
		sbomPartial = sbomPartial || coverage == "unknown"
	}

	// GHAS: code-scanning + secret-scanning alerts become findings that flow
	// through the enrichment → reasoning pipeline. Org-level list endpoints
	// with a per-repo fallback; skipped repos are counted and summarised.
	ghasFindings, ghasClosed := c.collectGHAS(ctx, baseURL, instToken, repos)

	// Branch protection: check whether each repo's default branch is protected.
	branchProtection := c.collectBranchProtection(ctx, baseURL, instToken, repos)

	// CODEOWNERS: stamped on each repo asset so owner resolution can route a
	// resource declared in this repo to the team owning the declaring file.
	codeowners, codeownersFile := c.collectCodeowners(ctx, baseURL, instToken, repos)

	// CI workflow IaC: parse every non-archived repo's .github/workflows/ for
	// declared cloud-identity intents (role-to-assume / service_account) into
	// declared_ci_access assets; the ci_access correlate rule later joins these
	// to live iam_role/gcp_service_account assets.
	priorIDs := []string{visibilityID(baseURL, "inventory", installationID)}
	for _, r := range repos {
		priorIDs = append(priorIDs, r.FullName)
	}
	prior := map[string]map[string]string{}
	if c.priorRepoMeta != nil {
		prior, err = c.priorRepoMeta(ctx, priorIDs)
		if err != nil {
			return collect.Result{}, fmt.Errorf("Collect: prior GitHub visibility: %w", err)
		}
	}
	appInventory := c.collectAppInventory(ctx, baseURL, jwtToken, instToken, installationID, repos, reposPartial, prior[priorIDs[0]])
	sources := c.collectRepositorySources(ctx, baseURL, instToken, repos, prior, appInventory, cfg["tfstate_aws_account_id"])
	if sources.Failed {
		return collect.Result{}, fmt.Errorf("Collect: repository source scan panicked")
	}
	workflows := sources.Workflows
	for i := range appInventory.Assets {
		if appInventory.Assets[i].ID == appInventory.ID {
			appInventory.Assets[i].Metadata["collector_token_scope"] = "configured_installation_default"
			appInventory.Assets[i].Metadata["collector_token_permissions"] = jsonString(credential.Permissions)
			appInventory.Assets[i].Metadata["collector_token_repository_selection"] = credential.RepositorySelection
		}
	}

	now := time.Now()
	assets := make([]asset.Asset, 0, len(repos)+len(pkgAssets))
	for _, r := range repos {
		meta := map[string]string{
			"visibility":     r.Visibility,
			"sbom_coverage":  sbomCoverage[r.FullName],
			"archived":       strconv.FormatBool(r.Archived),
			"language":       r.Language,
			"default_branch": r.DefaultBranch,
		}
		for k, v := range workflows.Metadata[r.FullName] {
			meta[k] = v
		}
		meta["app_inventory_coverage"] = appInventory.Snapshot.Coverage
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
	assets = append(assets, sources.Assets...)
	assets = append(assets, workflows.Assets...)
	assets = append(assets, appInventory.Assets...)
	edges = append(edges, appInventory.Edges...)
	edges = append(edges, workflows.Edges...)
	findings := append(ghasFindings, sources.Findings...)
	findings = append(findings, workflows.Findings...)
	// reposPartial: the repo list paged out early (rate-limit/5xx), so repos on
	// the un-fetched pages are missing from Assets — mark the result partial so
	// the sync worker does not mistake them for deleted.
	result := collect.Result{Assets: assets, Edges: edges, Findings: findings, Partial: reposPartial || sbomPartial, ClosedFindings: ghasClosed}
	result.ClosedFindings = append(result.ClosedFindings, workflowClosures(baseURL, repos, prior, workflows, appInventory)...)

	// Only authoritative complete listings license retirement. Workflow and
	// installation scopes are independent, so a denied workflow file cannot
	// suppress a fully observed installation removal.
	if !reposPartial {
		result.MarkComplete(installationID+"/github:repos", []string{"github_repo"}, len(repos))
	}
	if !reposPartial && workflows.Complete {
		result.MarkComplete(installationID+"/github:workflows", []string{"github_workflow", "github_workflow_reference", "declared_ci_access"}, len(workflows.Assets))
	}
	if !reposPartial && workflows.Complete && appInventory.Snapshot.Coverage == "complete" {
		result.MarkComplete(installationID+"/github:tokens", []string{"github_app_token_scope"}, len(workflows.Assets))
	}
	if !reposPartial && appInventory.Snapshot.Coverage == "complete" {
		result.MarkComplete(installationID+"/github:installations", []string{"github_app_installation", "github_app_grant"}, len(appInventory.Snapshot.Installations)*2)
	}
	if err := ctx.Err(); err != nil {
		return collect.Result{}, fmt.Errorf("Collect: cancelled: %w", err)
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

type installationCredential struct {
	Token               string            `json:"token"`
	Permissions         map[string]string `json:"permissions"`
	RepositorySelection string            `json:"repository_selection"`
}

func (c *Collector) installationTokenInfo(ctx context.Context, baseURL, installationID, jwtToken string) (installationCredential, error) {
	if installationID == "" {
		return installationCredential{}, fmt.Errorf("installationToken: installation_id is required")
	}
	url := baseURL + "/app/installations/" + installationID + "/access_tokens"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return installationCredential{}, fmt.Errorf("installationToken: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	var body installationCredential
	if err := c.doJSON(req, http.StatusCreated, &body); err != nil {
		return installationCredential{}, fmt.Errorf("installationToken: %w", err)
	}
	if body.Token == "" {
		return installationCredential{}, fmt.Errorf("installationToken: empty token in response")
	}
	return body, nil
}

type repo struct {
	Owner         appAccount `json:"owner"`
	Name          string     `json:"name"`
	FullName      string     `json:"full_name"`
	HTMLURL       string     `json:"html_url"`
	Visibility    string     `json:"visibility"`
	Archived      bool       `json:"archived"`
	Language      string     `json:"language"`
	DefaultBranch string     `json:"default_branch"`
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
	expected := -1
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
			TotalCount   *int    `json:"total_count"`
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
		if body.TotalCount != nil {
			if *body.TotalCount < 0 || (expected >= 0 && expected != *body.TotalCount) {
				return all, true, nil
			}
			expected = *body.TotalCount
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
			return all, expected >= 0 && expected != len(all), nil // a mismatched total is incomplete
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
