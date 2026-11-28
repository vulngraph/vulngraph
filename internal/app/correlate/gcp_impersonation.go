package correlate

import (
	"iter"
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// gcpImpersonationPerms are the GCP IAM permissions that let a principal act as,
// or mint credentials for, another service account — the concrete
// lateral-movement primitives behind the aws-style can_assume edge. A project-
// level grant of any of these covers every SA in the project.
var gcpImpersonationPerms = []string{
	"iam.serviceAccounts.getAccessToken", // short-lived OAuth token for the target SA
	"iam.serviceAccounts.getOpenIdToken",
	"iam.serviceAccounts.signBlob",
	"iam.serviceAccounts.signJwt",
	"iam.serviceAccounts.implicitDelegation",
	"iam.serviceAccounts.actAs", // deploy-as: attach the target SA to a workload
	"iam.serviceAccounts.*",     // wildcard covers all of the above
}

// maxImpersonationTargetsPerSA caps the fan-out from one privileged SA. A
// project-wide impersonation grant is O(N) targets per source (every other SA
// in the project); capping keeps a large project from generating an N² edge
// mesh, mirroring the gcp_firewall O(N²) lesson. Truncation is deterministic
// (targets sorted by ID) and logged by the caller via the returned count.
const maxImpersonationTargetsPerSA = 500

// GCPImpersonation links a service account that can impersonate or act-as other
// service accounts to those targets with a can_assume edge — the GCP counterpart
// to IAMCanAssume (which is AWS-trust-policy only). Impersonation reach is what
// blast-radius / escalation BFS traverses; without this edge a compromised SA
// with token-creator rights looks isolated in the graph.
//
// Slice 1 (this rule) uses the SA's project-level effective permissions
// (Metadata["permissions"], resolved by the GCP IAM collector): a project-wide
// grant fans out to every SA in the same project. A future slice can read
// per-SA IAM policies (ServiceAccounts.GetIamPolicy) to emit precise
// member→SA edges instead of the project-wide approximation.
type GCPImpersonation struct{}

func (GCPImpersonation) Name() string { return "gcp_impersonation" }

func (GCPImpersonation) InterestedIn() []string {
	return []string{"gcp_service_account"}
}

func (r GCPImpersonation) Correlate(g Graph) []asset.Edge { return slices.Collect(r.Edges(g)) }

func (GCPImpersonation) Edges(g Graph) iter.Seq[asset.Edge] {
	return func(yield func(asset.Edge) bool) {
		sas := g.GCPServiceAccounts()
		if len(sas) < 2 {
			return // impersonation needs a source and a distinct target
		}

		// Group SAs by project so a project-level grant only reaches same-project SAs.
		// An SA with an unknown project (empty AccountID) is NEVER bucketed: doing so
		// would collapse every such SA into one "" bucket and fan a project-level
		// grant out across ALL projects. Fail-safe: no edge beats a cross-project edge.
		byProject := map[string][]asset.Asset{}
		for _, sa := range sas {
			if sa.AccountID == "" {
				continue
			}
			byProject[sa.AccountID] = append(byProject[sa.AccountID], sa)
		}

		// Sort each oversized project once. Sorting and copying its entire account
		// set for every privileged source defeats the otherwise bounded fan-out.
		for _, project := range byProject {
			if len(project) > maxImpersonationTargetsPerSA+1 {
				slices.SortFunc(project, func(a, b asset.Asset) int { return strings.Compare(a.ID, b.ID) })
			}
		}

		for _, src := range sas {
			if src.AccountID == "" || !canImpersonate(src.Metadata["permissions"]) {
				continue
			}
			technique := impersonationTechnique(src.Metadata["permissions"])

			count := 0
			for _, dst := range byProject[src.AccountID] {
				if dst.ID == src.ID {
					continue
				}
				if count >= maxImpersonationTargetsPerSA {
					break
				}
				count++
				if !yield(asset.Edge{
					SrcID: src.ID, SrcType: "gcp_service_account",
					DstID: dst.ID, DstType: "gcp_service_account",
					EdgeType: EdgeCanAssume,
					Properties: map[string]string{
						"origin":    edgeOrigin,
						"rule":      "gcp_impersonation",
						"technique": technique,
						"scope":     "project",
					},
				}) {
					return
				}
			}
		}
	}
}

// canImpersonate reports whether a permissions CSV grants any impersonation or
// act-as primitive.
func canImpersonate(permsCSV string) bool {
	for perm := range strings.SplitSeq(permsCSV, ",") {
		if slices.Contains(gcpImpersonationPerms, strings.TrimSpace(perm)) {
			return true
		}
	}
	return false
}

// impersonationTechnique labels the edge by the strongest primitive present:
// token creation (direct credential theft) over act-as (deploy-as).
func impersonationTechnique(permsCSV string) string {
	actAs := false
	for perm := range strings.SplitSeq(permsCSV, ",") {
		switch strings.TrimSpace(perm) {
		case "iam.serviceAccounts.actAs":
			actAs = true
		case "iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.getOpenIdToken",
			"iam.serviceAccounts.signBlob", "iam.serviceAccounts.signJwt",
			"iam.serviceAccounts.implicitDelegation", "iam.serviceAccounts.*":
			return "token_creator"
		}
	}
	if actAs {
		return "act_as"
	}
	return "token_creator"
}
