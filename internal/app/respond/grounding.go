package respond

// grounding.go — post-reasoning check that the plan's rationale is grounded in
// the context the model was actually shown. The reasoner's rationale is free
// text; nothing stops it citing an asset that isn't in the ContextPack. A
// hallucinated identifier in an audited decision a person may approve
// is a trust hole, so any cited infrastructure ID the model was never given
// escalates to human review via CoVe (fail-closed).
//
// Deliberately high-precision, not high-recall: only tokens matching well-known
// cloud resource-ID shapes (AWS `i-…`/`sg-…`/… and ARNs) are examined, and a
// token is a concern only when it appears nowhere in what the prompt exposed.
// A grounding check that cries wolf gets ignored — under-flagging is preferred
// to false positives on legitimate decisions.

import (
	"fmt"
	"regexp"
	"strings"
)

// assetIDRe matches unambiguous cloud resource identifiers — AWS type-prefixed
// IDs (i-, sg-, vol-, subnet-, vpc-, …) and ARNs. These shapes never occur in
// ordinary rationale prose, so a match is a real citation, not a false hit.
var assetIDRe = regexp.MustCompile(
	`\b(?:i|sg|vol|subnet|vpc|eni|ami|rtb|acl|igw|nat|snap|pcx|dopt|vgw|eipalloc)-[0-9a-f]{8,17}\b` +
		`|arn:[a-z0-9-]*:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:[^\s"']+`)

// groundingConcerns returns one concern per infrastructure ID cited in the
// plan's summary/rationale that does not appear anywhere the prompt exposed it.
// Empty when every cited ID is grounded (the common case).
func groundingConcerns(plan Plan, pack ContextPack) []string {
	corpus := groundingCorpus(pack)
	seen := map[string]bool{}
	var concerns []string
	for _, cited := range assetIDRe.FindAllString(plan.Summary+"\n"+plan.Rationale, -1) {
		if seen[cited] || strings.Contains(corpus, cited) {
			continue
		}
		seen[cited] = true
		concerns = append(concerns, fmt.Sprintf(
			"rationale cites %q, which is absent from the context the reasoner was given — possible hallucination", cited))
	}
	return concerns
}

// groundingCorpus concatenates every identifier the pack surfaces to the prompt
// (buildPrompt in package reason renders exactly these), so a substring check
// treats any ID the model could plausibly have seen as grounded. Generous by
// design: it is safer to miss a hallucination than to flag a real citation.
func groundingCorpus(pack ContextPack) string {
	var b strings.Builder
	write := func(ss ...string) {
		for _, s := range ss {
			if s != "" {
				b.WriteString(s)
				b.WriteByte('\n')
			}
		}
	}
	write(pack.Finding.ResourceID, pack.Provenance.SourceRepo, pack.Provenance.AccountID)
	if pack.CVE != nil {
		write(pack.CVE.CVEID)
	}
	for _, a := range pack.Blast.TopReachable {
		write(a.ID, a.Name)
	}
	write(pack.Blast.CanAssume...)
	if pack.Identity != nil {
		write(pack.Identity.ExecutesAsID)
		write(pack.Identity.AttachedRoleIDs...)
		write(pack.Identity.FederatedRepoIDs...)
	}
	if pack.SupplyChain != nil {
		write(pack.SupplyChain.RepoIDs...)
		for _, w := range pack.SupplyChain.Workloads {
			write(w.ID)
		}
	}
	return b.String()
}
