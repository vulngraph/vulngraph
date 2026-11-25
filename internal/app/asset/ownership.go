package asset

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// EdgeTypeDefinedIn is the IaC ownership edge: resource → the repo declaring it.
// Emitted by the tf/k8s-manifest/image/declared-identity ownership correlators.
const EdgeTypeDefinedIn = "defined_in"

// OwnerSource names the tier an owner was resolved from. The zero value means
// resolution has not run (or could not complete) — it is NOT "unowned", which
// is OwnerSourceNone: an affirmative "every tier was consulted and none named an
// owner". Routing and filtering must keep the two apart.
type OwnerSource string

const (
	OwnerSourceTag        OwnerSource = "tag"        // an explicit owner/team tag on the resource
	OwnerSourceCodeowners OwnerSource = "codeowners" // the defining repo's CODEOWNERS, path-matched
	OwnerSourceIaC        OwnerSource = "iac"        // the repo that declares the resource (defined_in)
	OwnerSourceNone       OwnerSource = "none"       // resolved: nobody owns it
)

// Owner confidence values. Tag ownership is an operator's own statement (high);
// IaC-derived ownership inherits the defined_in edge's confidence.
const (
	OwnerConfidenceHigh   = "high"
	OwnerConfidenceMedium = "medium"
	OwnerConfidenceLow    = "low"
)

// Ownership is the single owner of an asset, with where it came from.
type Ownership struct {
	// Team is the normalised owner (NormalizeOwner). Empty unless Source is a
	// resolving tier.
	Team       string
	Source     OwnerSource
	Confidence string
	// Evidence is the exact claim, for an operator asking "why this team":
	// "tag:team", "codeowners:org/repo:/infra/", "defined_in:org/repo".
	Evidence string
}

// Resolved reports whether ownership resolution completed (owned or not).
func (o Ownership) Resolved() bool { return o.Source != "" }

// Unowned reports an affirmative "no tier named an owner".
func (o Ownership) Unowned() bool { return o.Source == OwnerSourceNone }

// DefaultOwnerTagKeys are the tag keys that name an owner, strongest first.
// Order matters: the first key present wins. Exact-case matches, because tag
// keys are case-sensitive on every provider and a team that tags both Owner and
// owner means two different things by them.
var DefaultOwnerTagKeys = []string{"owner", "Owner", "team", "Team", "app.kubernetes.io/part-of"}

// OwnerTagKeys returns the tag keys to consult: the operator's configured keys
// first (they know their own convention), then the defaults. Duplicates and
// blanks are dropped.
func OwnerTagKeys(configured []string) []string {
	out := make([]string, 0, len(configured)+len(DefaultOwnerTagKeys))
	seen := map[string]bool{}
	for _, k := range append(append([]string{}, configured...), DefaultOwnerTagKeys...) {
		k = strings.TrimSpace(k)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	return out
}

// TagOwner returns the raw value of the first owner tag present on a, and its
// key. keys nil means DefaultOwnerTagKeys. Raw (un-normalised) so a caller that
// shows the operator's own label — the remediation reasoner's provenance — reads
// exactly what was tagged.
func TagOwner(a Asset, keys []string) (value, key string) {
	if keys == nil {
		keys = DefaultOwnerTagKeys
	}
	for _, k := range keys {
		if v := strings.TrimSpace(a.Tags[k]); v != "" {
			return v, k
		}
	}
	return "", ""
}

// NormalizeOwner folds an owner label into the form owners are stored, filtered
// and routed on: trimmed and lower-cased, with a CODEOWNERS team handle reduced
// to the team name ("@acme/payments" → "payments") so it meets the same team's
// `team=payments` tag. A user handle loses only its "@".
func NormalizeOwner(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if strings.HasPrefix(v, "@") {
		v = strings.TrimPrefix(v, "@")
		if i := strings.LastIndex(v, "/"); i >= 0 {
			v = v[i+1:]
		}
	}
	return v
}

// OwnershipEvidence is the graph input ResolveOwnership weighs beyond the
// asset's own tags.
type OwnershipEvidence struct {
	DefinedIn []Edge           // defined_in edges out of the asset
	Repos     map[string]Asset // defining repos by id, for their CODEOWNERS
}

// ResolveOwnership is the single owner resolver. Tiers, strongest first:
//
//  1. an explicit owner tag (keys: OwnerTagKeys)
//  2. for a github_repo itself, its own CODEOWNERS catch-all rule
//  3. the repo declaring the resource (defined_in), refined to a team by that
//     repo's CODEOWNERS rule for the declaring file's path when one matches (a
//     claim with no path meets only the catch-all rule) —
//     a team is what routing needs, and CODEOWNERS can only be reached through
//     the defining repo, so it refines the IaC claim rather than competing with
//     it; with no matching rule the repo itself is the owner ("repo:org/name")
//  4. otherwise unowned (OwnerSourceNone)
//
// Pure: the caller fetches the evidence (Service.ResolveOwner).
func ResolveOwnership(a Asset, ev OwnershipEvidence, tagKeys []string) Ownership {
	if v, k := TagOwner(a, tagKeys); v != "" {
		return Ownership{Team: NormalizeOwner(v), Source: OwnerSourceTag, Confidence: OwnerConfidenceHigh, Evidence: "tag:" + k}
	}
	if a.Type == "github_repo" {
		if owner, pattern, ok := ParseCodeowners(a.Metadata[MetaCodeowners]).Owner(""); ok {
			return Ownership{
				Team: NormalizeOwner(owner), Source: OwnerSourceCodeowners, Confidence: OwnerConfidenceMedium,
				Evidence: "codeowners:" + a.ID + ":" + pattern,
			}
		}
	}
	e, ok := BestDefiningEdge(ev.DefinedIn)
	if !ok {
		return Ownership{Source: OwnerSourceNone}
	}
	conf := edgeConfidence(e)
	if repo, found := ev.Repos[e.DstID]; found {
		// A claim with no declaring path (tfstate knows addresses, not files) can
		// only meet the repo's catch-all rule, which says less than a path match:
		// it is capped at medium.
		path := e.Properties["path"]
		if owner, pattern, ok := ParseCodeowners(repo.Metadata[MetaCodeowners]).Owner(path); ok {
			c := conf
			if path == "" && c == OwnerConfidenceHigh {
				c = OwnerConfidenceMedium
			}
			return Ownership{
				Team: NormalizeOwner(owner), Source: OwnerSourceCodeowners, Confidence: c,
				Evidence: "codeowners:" + e.DstID + ":" + pattern,
			}
		}
	}
	return Ownership{
		Team: "repo:" + strings.ToLower(e.DstID), Source: OwnerSourceIaC, Confidence: conf,
		Evidence: "defined_in:" + e.DstID,
	}
}

// BestDefiningEdge picks the strongest defined_in claim: an identifier can
// appear in more than one repo (a shared module and the root module calling
// it), so a high-confidence declaration beats a referencing one. Ties break on
// the repo id so the answer does not depend on ClickHouse read order.
func BestDefiningEdge(edges []Edge) (Edge, bool) {
	cands := make([]Edge, 0, len(edges))
	for _, e := range edges {
		if e.DstID != "" {
			cands = append(cands, e)
		}
	}
	if len(cands) == 0 {
		return Edge{}, false
	}
	sort.SliceStable(cands, func(i, j int) bool {
		ri, rj := confidenceRank(cands[i]), confidenceRank(cands[j])
		if ri != rj {
			return ri > rj
		}
		return cands[i].DstID < cands[j].DstID
	})
	return cands[0], true
}

func confidenceRank(e Edge) int {
	switch e.Properties["confidence"] {
	case OwnerConfidenceHigh:
		return 3
	case OwnerConfidenceMedium:
		return 2
	case OwnerConfidenceLow:
		return 1
	}
	return 0
}

// edgeConfidence reads the claim's confidence; an edge that does not say is
// treated as low — it carries no evidence of being the declaring repo.
func edgeConfidence(e Edge) string {
	switch c := e.Properties["confidence"]; c {
	case OwnerConfidenceHigh, OwnerConfidenceMedium:
		return c
	}
	return OwnerConfidenceLow
}

// ResolveOwner fetches the evidence for a and resolves its owner. A failed
// graph read is returned as an error — never as OwnerSourceNone, which would
// route a resource whose owner we merely could not look up as "nobody's".
// tagKeys nil means DefaultOwnerTagKeys.
func (s *Service) ResolveOwner(ctx context.Context, a Asset, tagKeys []string) (Ownership, error) {
	if a.ID == "" {
		return Ownership{}, fmt.Errorf("ResolveOwner: %w", ErrNotFound)
	}
	if v, _ := TagOwner(a, tagKeys); v != "" {
		return ResolveOwnership(a, OwnershipEvidence{}, tagKeys), nil // no graph read needed
	}
	edges, err := s.repo.EdgesOut(ctx, a.ID, EdgeTypeDefinedIn)
	if err != nil {
		return Ownership{}, fmt.Errorf("ResolveOwner: defined_in: %w", err)
	}
	ev := OwnershipEvidence{DefinedIn: edges}
	if e, ok := BestDefiningEdge(edges); ok {
		repo, err := s.repo.GetAsset(ctx, e.DstID)
		switch {
		case err == nil:
			ev.Repos = map[string]Asset{repo.ID: repo}
		case errors.Is(err, ErrNotFound):
			// The repo is not in inventory: no CODEOWNERS to refine with, the
			// defined_in claim still stands.
		default:
			return Ownership{}, fmt.Errorf("ResolveOwner: defining repo: %w", err)
		}
	}
	return ResolveOwnership(a, ev, tagKeys), nil
}
