package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// Branch-protection states written to a repo's metadata. Anything not in this
// map is UNKNOWN and the key is omitted entirely.
const (
	branchProtectionEnabled  = "enabled"
	branchProtectionDisabled = "disabled"
)

const (
	// bpBatchSize is how many repositories one GraphQL query asks about. GitHub
	// charges GraphQL by node count (ceil(nodes/100)), so a 100-repo batch costs
	// exactly 1 point: even a very large estate costs only a few dozen points against
	// a 5,000 point/hour budget.
	bpBatchSize = 100

	// bpUniformNullFloor is the estate size above which "not one repository is
	// protected" is treated as a broken read rather than an observation. See
	// collectBranchProtection.
	bpUniformNullFloor = 50
)

// collectBranchProtection reports each non-archived repo's default-branch
// protection state, for repos where the state was actually OBSERVED. Repos
// whose state could not be read are absent from the map, and the caller then
// omits the metadata key entirely — a read failure must never be reported as
// "unprotected", since the finding lifecycle treats a missing signal as
// remediation and would close real no-branch-protection findings as fixed.
//
// It asks over GraphQL, 100 repositories per query, because the per-repo REST
// endpoint (one call per repo) starves against the shared rate-limit budget
// used by SBOM, GHAS, workflow and Terraform harvesting.
//
// Rulesets are deliberately NOT consulted: this collector reports classic
// branch protection, which is what branchProtectionRule returns; reading
// rulesets as well would cost extra calls per repository.
func (c *Collector) collectBranchProtection(ctx context.Context, baseURL, token string, repos []repo) map[string]string {
	targets := make([]repo, 0, len(repos))
	for _, r := range repos {
		if r.Archived || r.DefaultBranch == "" || !strings.Contains(r.FullName, "/") {
			continue
		}
		targets = append(targets, r)
	}

	result := make(map[string]string, len(targets))
	protected := 0
	drops := map[string]int{}
	for start := 0; start < len(targets); start += bpBatchSize {
		end := min(start+bpBatchSize, len(targets))
		batch := targets[start:end]

		states := c.branchProtectionSplit(ctx, baseURL, token, batch, drops)
		for name, state := range states {
			result[name] = state
			if state == branchProtectionEnabled {
				protected++
			}
		}
	}

	// Per-repo drops are the failure mode with no symptom. GitHub answers a
	// missing `administration: read` with data for the repository and a
	// FIELD-level error on branchProtectionRule, whose path starts with the
	// alias — so every repository is correctly refused, correctly not guessed at,
	// and silently discarded. `result` then stays empty, which is below the
	// uniform-null floor, so even that guard says nothing.
	//
	// Left unreported, a connector can end up with no repository carrying
	// branch_protection and not one line in the logs: correct fail-unknown
	// behaviour, but invisible. A read that observed NOTHING is an operational
	// fault, not an empty estate, and has to say so.
	if len(drops) > 0 {
		ev := log.FromContext(ctx).Warn()
		for reason, n := range drops {
			ev = ev.Int(reason, n)
		}
		ev.Int("observed", len(result)).Int("targets", len(targets)).
			Msg("branch-protection: some repos unobserved; keys omitted")
	}
	if len(result) == 0 && len(targets) > 0 {
		log.FromContext(ctx).Error().Int("targets", len(targets)).Interface("drops", drops).
			Msg("branch protection observed on NO repo of this installation — the App is missing administration:read, or every query was refused; findings for these repos will be scored on missing data")
	}

	// A token that cannot read protection does not error — GraphQL answers
	// branchProtectionRule: null, which is byte-identical to "this branch is
	// genuinely unprotected". The only thing that separates them is scale: across
	// thousands of repositories, a real estate always has some protected repos,
	// and a uniform zero is the signature of a missing `administration: read` App
	// permission. Taking it at face value would turn a permission gap into a
	// flood of false findings.
	//
	// Below bpUniformNullFloor repos the argument does not hold — a small
	// installation really can have nothing protected — so the answer stands.
	if protected == 0 && len(result) >= bpUniformNullFloor {
		log.FromContext(ctx).Error().Int("repos_read", len(result)).
			Msg("branch protection read as absent on EVERY repo — treating as a permission gap, not an estate of zero; check the App's administration:read permission")
		return map[string]string{}
	}
	return result
}

// branchProtectionSplit halves a batch only for an explicit GraphQL complexity,
// node-count or execution-time rejection. HTTP, permission and rate-limit failures
// stay unknown without multiplying requests. Recursion is bounded by batch size;
// repeated failures can still cost up to twice the number of repositories.
func (c *Collector) branchProtectionSplit(ctx context.Context, baseURL, token string, batch []repo, drops map[string]int) map[string]string {
	states, err := c.branchProtectionBatch(ctx, baseURL, token, batch, drops)
	if err == nil {
		return states
	}
	// Shrinking a query cannot repair a rejected credential, exhausted rate
	// limit, transport failure or cancelled context. Only a GraphQL query-level
	// rejection can benefit from splitting; HTTP retries already ran in doJSON.
	var splitErr *protectionSplitError
	if !errors.As(err, &splitErr) {
		drops["query_rejected"] += len(batch)
		return nil
	}
	if len(batch) == 1 {
		// Never a state — a failed read must not become "disabled".
		drops["query_rejected"]++
		log.FromContext(ctx).Debug().Err(err).Str("repo", batch[0].FullName).
			Msg("branch-protection unknown for repo; key omitted")
		return nil
	}
	log.FromContext(ctx).Debug().Err(err).Int("repos", len(batch)).
		Msg("branch-protection batch rejected; splitting")
	mid := len(batch) / 2
	out := map[string]string{}
	for _, half := range [][]repo{batch[:mid], batch[mid:]} {
		for name, state := range c.branchProtectionSplit(ctx, baseURL, token, half, drops) {
			out[name] = state
		}
	}
	return out
}

// queryLevelError reports a GraphQL failure that concerns the whole query rather
// than one aliased repository. Both signals matter: `data: null` means nothing
// was resolved, and an error without a `path` is by definition not about a single
// alias.
type protectionSplitError struct{ error }

func queryLevelError(out bpResponse) error {
	for _, e := range out.Errors {
		if len(e.Path) == 0 {
			err := fmt.Errorf("query rejected: %s", e.Message)
			message := strings.ToLower(e.Type + " " + e.Message)
			if strings.Contains(message, "complexity") || strings.Contains(message, "timeout") || strings.Contains(message, "timed out") || strings.Contains(message, "max_node_limit") {
				return &protectionSplitError{err}
			}
			return err
		}
	}
	if out.Data == nil {
		return fmt.Errorf("query returned no data")
	}
	return nil
}

// bpResponse is one GraphQL answer. Aliased repositories land in Data keyed by
// alias; a repository the token cannot resolve yields a null entry plus an
// Errors element naming its alias in Path, and the other aliases still carry
// real data — so failures are per-repo, not per-batch.
type bpResponse struct {
	Data   map[string]*bpRepo `json:"data"`
	Errors []struct {
		Type    string `json:"type"`
		Path    []any  `json:"path"`
		Message string `json:"message"`
	} `json:"errors"`
}

type bpRepo struct {
	NameWithOwner    string `json:"nameWithOwner"`
	DefaultBranchRef *struct {
		BranchProtectionRule *struct {
			ID string `json:"id"`
		} `json:"branchProtectionRule"`
	} `json:"defaultBranchRef"`
}

// branchProtectionBatch asks about one batch of repositories and returns the
// observed state for each alias that came back clean.
func (c *Collector) branchProtectionBatch(ctx context.Context, baseURL, token string, batch []repo, drops map[string]int) (map[string]string, error) {
	var q strings.Builder
	q.WriteString("query {")
	for i, r := range batch {
		owner, name, _ := strings.Cut(r.FullName, "/")
		fmt.Fprintf(&q, " r%d: repository(owner:%q, name:%q){ nameWithOwner defaultBranchRef{ branchProtectionRule{ id } } }", i, owner, name)
	}
	q.WriteString(" }")

	body, err := json.Marshal(map[string]string{"query": q.String()})
	if err != nil {
		return nil, fmt.Errorf("branchProtectionBatch: encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, graphQLURL(baseURL), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("branchProtectionBatch: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	var out bpResponse
	if err := c.doJSON(req, http.StatusOK, &out); err != nil {
		return nil, fmt.Errorf("branchProtectionBatch: %w", err)
	}

	// A GraphQL error carrying no `path` is not about one repository — it is the
	// whole query being rejected (complexity, timeout, secondary rate limit), and
	// GitHub reports it with HTTP 200 and `"data": null`. Read alias-by-alias that
	// is indistinguishable from "100 repositories each returned nothing": the
	// batch would return an empty map and a nil error, the caller would log
	// nothing, and branch_protection would stay absent on every repo of a large
	// connector while a tiny connector — small enough to never trip the limit —
	// worked fine.
	//
	// This is the same failure the uniform-null guard in collectBranchProtection
	// exists to catch, arriving one layer lower than that guard can see.
	if err := queryLevelError(out); err != nil {
		return nil, fmt.Errorf("branchProtectionBatch: %w", err)
	}

	// Any alias named in errors was not read — drop it rather than reading its
	// null data entry as "unprotected". The error TYPE is kept so the caller can
	// say which fault this was: FORBIDDEN across the estate is a missing
	// administration:read scope, NOT_FOUND is a repo the token cannot resolve, and
	// the two need different fixes.
	failed := map[string]string{}
	for _, e := range out.Errors {
		if len(e.Path) > 0 {
			if alias, ok := e.Path[0].(string); ok {
				failed[alias] = e.Type
			}
		}
	}

	states := make(map[string]string, len(batch))
	for i, r := range batch {
		alias := fmt.Sprintf("r%d", i)
		if reason, bad := failed[alias]; bad {
			drops[dropReason(reason)]++
			continue
		}
		got, ok := out.Data[alias]
		if !ok || got == nil {
			drops["no_data"]++
			continue
		}
		if got.DefaultBranchRef == nil {
			drops["no_default_branch"]++
			continue // nothing to protect: nothing observed
		}
		if got.DefaultBranchRef.BranchProtectionRule != nil {
			states[r.FullName] = branchProtectionEnabled
		} else {
			states[r.FullName] = branchProtectionDisabled
		}
	}
	return states, nil
}

// dropReason normalises a GraphQL error type into a log field name, so an
// unfamiliar type is still counted rather than silently folded into a bucket
// that suggests a cause it does not have.
func dropReason(errType string) string {
	switch errType {
	case "FORBIDDEN":
		return "forbidden"
	case "NOT_FOUND":
		return "not_found"
	case "":
		return "error_untyped"
	default:
		return "error_" + strings.ToLower(errType)
	}
}

// graphQLURL derives the GraphQL endpoint from a REST base URL. github.com
// serves it at /graphql off the same host; GHES serves REST at /api/v3 and
// GraphQL at /api/graphql, so the version segment is replaced rather than
// appended.
func graphQLURL(baseURL string) string {
	base := strings.TrimSuffix(baseURL, "/")
	if trimmed, ok := strings.CutSuffix(base, "/api/v3"); ok {
		return trimmed + "/api/graphql"
	}
	return base + "/graphql"
}
