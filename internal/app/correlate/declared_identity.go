package correlate

import (
	"slices"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// Harvested identity kinds, as written into declared_cloud_identity
// Metadata["kind"] by the collector side (internal/collect/iac/identities.go).
//
// Restated here as literals rather than imported: correlate does not depend on
// internal/collect (the same hand-copied-contract convention tf_ownership.go
// follows for its metadata keys). The two sides are held
// together by TestDeclaredIdentityKindsMatchCollector, which fails if either
// drifts.
const (
	kindIamRole    = "iam_role"
	kindIamUser    = "iam_user"
	kindGCPSA      = "gcp_service_account"
	kindGitHubOIDC = "github_oidc_sub"
)

// DeclaredIdentityOwnership joins declared_cloud_identity intermediates — cloud
// identities harvested verbatim from ANY repo file by iac.HarvestIdentities — to
// the live identities they name, and emits ownership/federation edges.
//
// This is the generic replacement for per-tool, per-pinned-repo ownership rules.
// It needs no configuration and knows nothing about Terraform, CDK, Helm,
// CloudFormation or raw policy JSON: the identifier a repo writes down (a role
// ARN, a service-account email, a GitHub OIDC subject) is byte-identical to the
// live asset's ID, so the join is exact string equality. That is why it can be
// trusted at high confidence — there is no name reconstruction and nothing
// inferred.
//
// Two edge shapes, both reusing existing rels so this adds no Ladybug schema:
//
//   - defined_in (live identity → repo): this repo's text declares this identity.
//     Ownership — "who defines this role".
//   - federated_access (repo → live identity): a GitHub OIDC subject naming a
//     repo, found in a trust policy, means that repo's CI can assume the role the
//     policy belongs to.
//
// A harvested identity with no live match is skipped, not guessed at: it usually
// means the account is not collected, or the reference is stale. The count is
// surfaced by the caller as a coverage number rather than hidden.
type DeclaredIdentityOwnership struct{}

func (DeclaredIdentityOwnership) Name() string { return "declared_identity_ownership" }

func (DeclaredIdentityOwnership) InterestedIn() []string {
	return []string{"declared_cloud_identity", "iam_role", "iam_user", "gcp_service_account", "github_repo"}
}

func (DeclaredIdentityOwnership) Correlate(g Graph) []asset.Edge {
	var edges []asset.Edge
	seen := map[string]bool{}
	add := func(e asset.Edge) {
		k := e.SrcID + "|" + e.EdgeType + "|" + e.DstID
		if seen[k] {
			return
		}
		seen[k] = true
		edges = append(edges, e)
	}

	// Roles indexed by the file they were found in, so an OIDC subject can find
	// the role declared alongside it in one lookup instead of rescanning every
	// harvested identity (that inner rescan is quadratic in corpus size, and this
	// rule sees every repo in every org).
	rolesByFile := map[string][]string{}
	for _, d := range g.DeclaredIdentities() {
		v := d.Metadata["value"]
		if v == "" || d.Metadata["kind"] != kindIamRole {
			continue
		}
		k := d.Metadata["repo"] + "|" + d.Metadata["path"]
		if !slices.Contains(rolesByFile[k], v) {
			rolesByFile[k] = append(rolesByFile[k], v)
		}
	}
	// trustTarget is the role whose trust policy an OIDC subject in this file
	// belongs to. The harvest records which FILE a subject sits in, not which
	// role block, so pairing it with every role the file mentions would grant
	// one role's trust to every other role there (a principal ARN in another
	// statement, a second aws_iam_role resource). Only a file naming exactly
	// one role is unambiguous; anything else is skipped.
	trustTarget := func(file string) (string, bool) {
		if ids := rolesByFile[file]; len(ids) == 1 {
			return ids[0], true
		}
		return "", false
	}

	for _, d := range g.DeclaredIdentities() {
		repoID, value := d.Metadata["repo"], d.Metadata["value"]
		if repoID == "" || value == "" {
			continue
		}
		path := d.Metadata["path"]

		switch d.Metadata["kind"] {
		case kindIamRole, kindIamUser, kindGCPSA:
			// Ownership: the repo whose file names this identity declares it.
			if !g.IsPrincipal(value) {
				continue
			}
			add(asset.Edge{
				SrcID: value, SrcType: liveTypeFor(d.Metadata["kind"]),
				DstID: repoID, DstType: "github_repo",
				EdgeType: EdgeDefinedIn,
				Properties: map[string]string{
					"origin":     edgeOrigin,
					"rule":       "declared_identity_ownership",
					"provenance": "identifier_harvest",
					"confidence": "high", // exact identifier equality, nothing reconstructed
					"match":      "identifier",
					"path":       path,
				},
			})
		case kindGitHubOIDC:
			// Federation: a subject found in a trust policy grants the named repo's CI
			// the role that policy belongs to — see trustTarget. Without an
			// unambiguous co-located role there is nothing to point an edge at.
			subjectRepo, ok := g.RepoByFullName(value)
			if !ok {
				continue
			}
			roleARN, ok := trustTarget(repoID + "|" + path)
			if !ok || !g.IsPrincipal(roleARN) {
				continue
			}
			add(asset.Edge{
				SrcID: subjectRepo.ID, SrcType: "github_repo",
				DstID: roleARN, DstType: "iam_role",
				EdgeType: EdgeFederatedAccess,
				Properties: map[string]string{
					"origin":      edgeOrigin,
					"rule":        "declared_identity_ownership",
					"provenance":  "iac_trust_policy",
					"confidence":  "high",
					"path":        path,
					"declared_in": repoID,
				},
			})
		}
	}
	return edges
}

// liveTypeFor maps a harvested identity kind to the live asset type it joins.
func liveTypeFor(kind string) string {
	switch kind {
	case kindIamUser:
		return "iam_user"
	case kindGCPSA:
		return "gcp_service_account"
	default:
		return "iam_role"
	}
}
