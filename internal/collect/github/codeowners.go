package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

const (
	// coBatchSize is how many repositories one GraphQL query asks about. Each
	// asks for three blobs, so this stays well under the node-count budget the
	// branch-protection batch (100 repos × one rule) already lives in.
	coBatchSize = 50
	// coMaxBytes bounds the CODEOWNERS stored on a repo asset. A file past it is
	// dropped, never truncated: CODEOWNERS is last-match-wins, so cutting off the
	// tail would hand its paths to earlier, broader rules — a wrong owner, where
	// absence only means "fall back to the declaring repo".
	coMaxBytes = 32 << 10
)

// codeownersLocations are where GitHub looks for CODEOWNERS, in its own lookup
// order; the first present one is the file GitHub uses.
var codeownersLocations = []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"}

// collectCodeowners reads each non-archived repo's CODEOWNERS (default branch)
// and returns the compacted rules by repo full name, for the repo asset's
// asset.MetaCodeowners metadata. Owner resolution path-matches the file that
// declares a resource against these rules (ADR 089).
//
// Batched over GraphQL like collectBranchProtection: three REST content probes
// per repo — most of them 404s, since most repos have no CODEOWNERS — would
// spend the rate-limit budget the SBOM/GHAS/IaC harvests share. Best-effort: a
// rejected batch or an unreadable repo is skipped and logged. The repo asset row
// is rewritten whole every sweep, so an absent key would ERASE the rules stored
// last sweep: an unread repo instead keeps its previously stored rules
// (carryForwardCodeowners) — "not read" must not become "nobody owns it".
//
// The second result maps each repo whose lookup succeeded to "present" (a file
// was read) or "absent" (no file at any location) for asset.MetaCodeownersFile.
// Both values are written so a repo that gains a CODEOWNERS file closes the
// no-CODEOWNERS finding; unread repos are in neither.
func (c *Collector) collectCodeowners(ctx context.Context, baseURL, token string, repos []repo) (map[string]string, map[string]string) {
	targets := make([]repo, 0, len(repos))
	for _, r := range repos {
		if !r.Archived && r.DefaultBranch != "" && strings.Contains(r.FullName, "/") {
			targets = append(targets, r)
		}
	}
	out := map[string]string{}
	fileState := map[string]string{}
	var unread []string
	for start := 0; start < len(targets); start += coBatchSize {
		batch := targets[start:min(start+coBatchSize, len(targets))]
		got, none, failed, err := c.codeownersBatch(ctx, baseURL, token, batch)
		if err != nil {
			for _, r := range batch {
				unread = append(unread, r.FullName)
			}
			log.FromContext(ctx).Debug().Err(err).Int("repos", len(batch)).Msg("codeowners: batch skipped")
			continue
		}
		unread = append(unread, failed...)
		for name, rules := range got {
			out[name] = rules
			fileState[name] = "present"
		}
		for _, name := range none {
			fileState[name] = "absent"
		}
	}
	if len(unread) > 0 {
		kept := c.carryForwardCodeowners(ctx, out, unread)
		log.FromContext(ctx).Warn().Int("unread", len(unread)).Int("kept_previous", kept).Int("targets", len(targets)).
			Msg("codeowners: some repos unread this sweep; their previously stored rules are kept")
	}
	return out, fileState
}

// carryForwardCodeowners copies each unread repo's stored CODEOWNERS rules
// into out and returns how many it kept. Without the prior-metadata seam
// (SetPriorRepoMetadata), or when the lookup fails, nothing can be kept and the
// unread repos' keys stay absent.
func (c *Collector) carryForwardCodeowners(ctx context.Context, out map[string]string, unread []string) int {
	if c.priorRepoMeta == nil {
		return 0
	}
	prior, err := c.priorRepoMeta(ctx, unread)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Int("repos", len(unread)).
			Msg("codeowners: stored rules unreadable; unread repos lose their CODEOWNERS key this sweep")
		return 0
	}
	kept := 0
	for _, name := range unread {
		if rules := prior[name][asset.MetaCodeowners]; rules != "" {
			out[name] = rules
			kept++
		}
	}
	return kept
}

type coBlob struct {
	Text        *string `json:"text"`
	ByteSize    int     `json:"byteSize"`
	IsTruncated bool    `json:"isTruncated"`
}

type coResponse struct {
	Data   map[string]map[string]*coBlob `json:"data"`
	Errors []struct {
		Path    []any  `json:"path"`
		Message string `json:"message"`
	} `json:"errors"`
}

// codeownersBatch asks for every CODEOWNERS location of a batch of repos and
// returns the first present file per repo, compacted, plus the repos whose
// lookup failed individually (unread, as opposed to read and absent).
func (c *Collector) codeownersBatch(ctx context.Context, baseURL, token string, batch []repo) (map[string]string, []string, []string, error) {
	var q strings.Builder
	q.WriteString("query {")
	for i, r := range batch {
		owner, name, _ := strings.Cut(r.FullName, "/")
		fmt.Fprintf(&q, " r%d: repository(owner:%q, name:%q){", i, owner, name)
		for j, loc := range codeownersLocations {
			fmt.Fprintf(&q, " f%d: object(expression:%q){ ... on Blob { text byteSize isTruncated } }", j, "HEAD:"+loc)
		}
		q.WriteString(" }")
	}
	q.WriteString(" }")

	body, err := json.Marshal(map[string]string{"query": q.String()})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("codeownersBatch: encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, graphQLURL(baseURL), bytes.NewReader(body))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("codeownersBatch: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	var resp coResponse
	if err := c.doJSON(req, http.StatusOK, &resp); err != nil {
		return nil, nil, nil, fmt.Errorf("codeownersBatch: %w", err)
	}
	failed := map[string]bool{}
	for _, e := range resp.Errors {
		if len(e.Path) == 0 {
			return nil, nil, nil, fmt.Errorf("codeownersBatch: query rejected: %s", e.Message)
		}
		if alias, ok := e.Path[0].(string); ok {
			failed[alias] = true
		}
	}
	if resp.Data == nil {
		return nil, nil, nil, fmt.Errorf("codeownersBatch: query returned no data")
	}

	out := map[string]string{}
	var unread, none []string
	for i, r := range batch {
		alias := fmt.Sprintf("r%d", i)
		if failed[alias] {
			unread = append(unread, r.FullName)
			continue
		}
		if rules, ok := firstCodeowners(resp.Data[alias]); ok {
			out[r.FullName] = rules
		}
		if noCodeownersFile(resp.Data[alias]) {
			none = append(none, r.FullName)
		}
	}
	return out, none, unread, nil
}

// noCodeownersFile reports whether no CODEOWNERS location holds a file.
func noCodeownersFile(files map[string]*coBlob) bool {
	for j := range codeownersLocations {
		if b := files[fmt.Sprintf("f%d", j)]; b != nil && b.Text != nil {
			return false
		}
	}
	return true
}

// firstCodeowners picks the file GitHub would use — the first location present
// — and compacts it. A file that is oversized or truncated by the API is
// reported as unread rather than partially used.
func firstCodeowners(files map[string]*coBlob) (string, bool) {
	for j := range codeownersLocations {
		b := files[fmt.Sprintf("f%d", j)]
		if b == nil || b.Text == nil {
			continue
		}
		if b.IsTruncated || b.ByteSize > coMaxBytes {
			return "", false
		}
		rules := compactCodeowners(*b.Text)
		return rules, rules != ""
	}
	return "", false
}

// compactCodeowners drops blank lines and comment lines, so the stored metadata
// carries only rules.
func compactCodeowners(text string) string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}
