package correlate

import (
	"iter"
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/awspolicy"
)

// irsaSubjectPrefix is the fixed prefix of an EKS IRSA trust subject. The full
// value is "system:serviceaccount:<namespace>:<serviceaccount>".
const irsaSubjectPrefix = "system:serviceaccount:"

// saIDInfix is the middle of a collected k8s_service_account asset ID. The
// collector builds them as "<cluster>/namespace/<ns>/serviceaccount/<name>"
// (collect/kubernetes/rbac.go), and only the cluster segment is unknown to an
// IAM trust policy — so the suffix after the cluster is the join key.
const saIDInfix = "/namespace/"

// IRSATrust links a Kubernetes ServiceAccount to the AWS IAM role it can assume
// through EKS IAM Roles for Service Accounts, closing the K8s→AWS half of the
// federated-identity graph. It is the mirror of GCPWorkloadIdentity (GKE
// Workload Identity, driven from the SA's annotation); IRSA has no annotation on
// the AWS side of the trust, so this rule is driven from the ROLE:
// iam_role.metadata.federated_provider holds the OIDC provider ARN
// (collect/aws/iam.go trustFederation), matched against eks_cluster.metadata
// .oidc_provider_arn for the cluster that issues it, and the trust policy's
// sub condition holds "system:serviceaccount:<namespace>:<serviceaccount>".
//
// # Why this emits nothing for a cluster whose ServiceAccounts are not collected
//
// Synthesising the ServiceAccount node (the way the `internet` sentinel is
// synthesised) was considered and rejected: a collected SA's ID is prefixed by
// the k8s connector's operator-supplied cluster_name, which is NOT the EKS
// cluster name and appears nowhere in an IAM trust policy, so any ID minted
// from the AWS side would never match the real asset — a permanently dangling
// edge, worse than a missing one. It would also buy no reachability: the pods
// of a cluster whose ServiceAccounts are dark are dark in the same sweep, so a
// synthesised SA node would have no inbound edge while inflating inventory and
// corrupting the coverage signal that says the cluster is dark. Matching
// against collected assets instead makes this rule self-completing: the
// moment an EKS cluster's ServiceAccounts are collected under ANY
// cluster_name, the suffix join fires with no code change.
//
// # Why federated_access and not executes_as
//
// federated_access already carries this shape — GKE Workload Identity's
// SA→cloud-role edges land there via the K8sWorkload→IamRole reroute — so
// reusing it needs no new rel table or SchemaVersion bump.
//
// Reach is carried separately. Reach is a property of the edge TYPE, so
// making federated_access Reach would promote every github_repo→role edge
// with it. Instead the SA's eks.amazonaws.com/role-arn annotation is its
// exec_role, and the ExecutesAs rule turns that into a Reach executes_as edge
// (pod -[executes_as]-> SA -[executes_as]-> role); GCPWorkloadIdentity emits
// the same pair for GKE.
type IRSATrust struct{}

func (IRSATrust) Name() string { return "irsa_trust" }

func (IRSATrust) InterestedIn() []string {
	return []string{"iam_role", "k8s_service_account", "eks_cluster"}
}

func (r IRSATrust) Correlate(g Graph) []asset.Edge { return slices.Collect(r.Edges(g)) }

func (IRSATrust) Edges(g Graph) iter.Seq[asset.Edge] {
	return func(yield func(asset.Edge) bool) {
		saBySuffix := serviceAccountsBySuffix(g.K8sServiceAccounts())
		if len(saBySuffix) == 0 {
			return
		}
		clusterByProvider := eksClusterNamesByProvider(g.EKSClusters())

		for _, role := range g.IAMRoles() {
			provider := role.Metadata["federated_provider"]
			if provider == "" {
				continue
			}
			cluster, isEKS := clusterByProvider[provider]
			if !isEKS {
				continue
			}
			linked := map[string]bool{}
			for _, grant := range irsaGrants(role, provider) {
				for _, sub := range grant.subjects {
					var matched []asset.Asset
					if strings.ContainsAny(sub, "*?") {
						// A StringLike wildcard ("prod:*", "*") trusts every SA it matches
						// in the issuing cluster — each of them really can assume the role.
						matched = serviceAccountsMatching(g.K8sServiceAccounts(), cluster, sub)
					} else {
						ns, name, ok := strings.Cut(sub, ":")
						if !ok || ns == "" || name == "" {
							continue
						}
						if sa, ok := resolveServiceAccount(saBySuffix, cluster, ns, name); ok {
							matched = append(matched, sa)
						}
					}
					for _, sa := range matched {
						if linked[sa.ID] || grant.excludes(sa) {
							continue
						}
						linked[sa.ID] = true
						if !yield(irsaEdge(sa, role, sub)) {
							return
						}
					}
				}
			}
		}
	}
}

// irsaEdge builds the SA → role federated_access edge for one trust subject.
func irsaEdge(sa, role asset.Asset, sub string) asset.Edge {
	return asset.Edge{
		SrcID: sa.ID, SrcType: "k8s_service_account",
		DstID: role.ID, DstType: "iam_role",
		EdgeType: EdgeFederatedAccess,
		Properties: map[string]string{
			"origin":     edgeOrigin,
			"rule":       "irsa_trust",
			"trust_type": "eks_irsa",
			"subject":    irsaSubjectPrefix + sub,
			"provenance": "trust_policy",
		},
	}
}

// serviceAccountsMatching returns the collected ServiceAccounts of the issuing
// cluster whose "<namespace>:<name>" matches a wildcard trust subject. The
// cluster is identified as in resolveServiceAccount: SAs whose ID prefix is
// the EKS cluster name win; failing that, the matches are used only if they
// all come from ONE collected cluster, since the same namespace/name in two
// clusters cannot be told apart from the trust policy alone.
func serviceAccountsMatching(sas []asset.Asset, cluster, pattern string) []asset.Asset {
	byCluster := map[string][]asset.Asset{}
	for _, sa := range sas {
		subject, ok := serviceAccountSubject(sa)
		if !ok || !ciem.WildcardMatch(pattern, subject) {
			continue
		}
		prefix := sa.ID[:strings.Index(sa.ID, saIDInfix)]
		byCluster[prefix] = append(byCluster[prefix], sa)
	}
	if m := byCluster[cluster]; cluster != "" && len(m) > 0 {
		return m
	}
	if len(byCluster) == 1 {
		for _, m := range byCluster {
			return m
		}
	}
	return nil
}

// serviceAccountsBySuffix indexes collected ServiceAccounts by the part of their
// ID an IAM trust policy can reconstruct — "namespace/<ns>/serviceaccount/<name>"
// — so the unknown cluster prefix does not block the join.
func serviceAccountsBySuffix(sas []asset.Asset) map[string][]asset.Asset {
	out := make(map[string][]asset.Asset, len(sas))
	for _, sa := range sas {
		if i := strings.Index(sa.ID, saIDInfix); i > 0 {
			suffix := sa.ID[i+1:]
			out[suffix] = append(out[suffix], sa)
		}
	}
	return out
}

// eksClusterNamesByProvider maps each collected EKS cluster's OIDC provider ARN
// (and raw issuer URL) to the cluster's name, so a role's federated_provider
// identifies the cluster by string equality.
func eksClusterNamesByProvider(clusters []asset.Asset) map[string]string {
	out := make(map[string]string, len(clusters)*2)
	for _, c := range clusters {
		for _, key := range []string{c.Metadata["oidc_provider_arn"], c.Metadata["oidc_issuer"]} {
			if key != "" {
				out[key] = c.Name
			}
		}
	}
	return out
}

// resolveServiceAccount picks the collected ServiceAccount a trust subject
// refers to. The cluster segment of an SA's ID is the k8s connector's
// cluster_name, which need not equal the EKS cluster name, so an exact prefix
// match is preferred but not required: a suffix unique across the whole
// inventory is unambiguous on its own. An ambiguous suffix (the same
// namespace/name in several collected clusters, none matching the EKS name)
// resolves to nothing — a wrong cross-cluster edge is a fabricated attack path.
func resolveServiceAccount(saBySuffix map[string][]asset.Asset, cluster, ns, name string) (asset.Asset, bool) {
	suffix := "namespace/" + ns + "/serviceaccount/" + name
	candidates := saBySuffix[suffix]
	if len(candidates) == 0 {
		return asset.Asset{}, false
	}
	if cluster != "" {
		want := cluster + "/" + suffix
		for _, sa := range candidates {
			if sa.ID == want {
				return sa, true
			}
		}
	}
	if len(candidates) == 1 {
		return candidates[0], true
	}
	return asset.Asset{}, false
}

// irsaGrant is what one trust statement lets assume the role, as
// "<namespace>:<serviceaccount>" patterns: the subjects its matching sub
// conditions admit, less those its negated sub conditions keep out.
type irsaGrant struct {
	subjects []string
	excluded []irsaExclusion
}

// irsaExclusion is one negated sub value; like is true for StringNotLike,
// whose value is a wildcard pattern rather than a literal.
type irsaExclusion struct {
	pattern string
	like    bool
}

// excludes reports whether a negated sub condition of the grant keeps sa out.
func (g irsaGrant) excludes(sa asset.Asset) bool {
	subject, ok := serviceAccountSubject(sa)
	if !ok {
		return false
	}
	for _, x := range g.excluded {
		if x.pattern == subject || (x.like && ciem.WildcardMatch(x.pattern, subject)) {
			return true
		}
	}
	return false
}

// irsaGrants returns one irsaGrant per trust statement granted to the given
// OIDC provider. The provider match is per-STATEMENT: a role may federate
// several providers, and attributing one statement's subjects to another
// statement's provider would invent a trust that does not exist.
//
// A statement with no matching sub condition admits every service account in
// the issuing cluster (subject "*"): the cluster's issuer signs a token for
// each of them, and an aud check alone does not narrow that. Its negated sub
// conditions still keep their service accounts out. An operator is read as
// on a key the token always carries, so StringLikeIfExists is StringLike.
func irsaGrants(role asset.Asset, provider string) []irsaGrant {
	var out []irsaGrant
	for _, pol := range decodePolicies(role.Metadata["policies"]) {
		if pol.Type != "trust" && pol.Type != "" {
			continue
		}
		for _, stmt := range trustStatements(pol.Document) {
			if !strings.EqualFold(stmt.Effect, "Allow") || !grantsProvider(stmt, provider) {
				continue
			}
			out = append(out, statementIRSAGrant(stmt))
		}
	}
	return out
}

func statementIRSAGrant(stmt trustStatement) irsaGrant {
	var g irsaGrant
	for op, condMap := range stmt.Condition {
		matching, negated := awspolicy.PresentKeyOperator(op)
		if !matching && !negated {
			continue
		}
		like := strings.Contains(strings.ToLower(op), "like")
		for key, val := range condMap {
			if !strings.HasSuffix(strings.ToLower(key), ":sub") {
				continue
			}
			for _, sub := range conditionStrings(val) {
				rest, ok := strings.CutPrefix(sub, irsaSubjectPrefix)
				switch {
				case !ok:
				case matching && !slices.Contains(g.subjects, rest):
					g.subjects = append(g.subjects, rest)
				case negated:
					g.excluded = append(g.excluded, irsaExclusion{pattern: rest, like: like})
				}
			}
		}
	}
	if len(g.subjects) == 0 {
		g.subjects = []string{"*"}
	}
	return g
}

// serviceAccountSubject returns a collected ServiceAccount's
// "<namespace>:<name>", the form an IRSA sub carries after its prefix.
func serviceAccountSubject(sa asset.Asset) (string, bool) {
	i := strings.Index(sa.ID, saIDInfix)
	if i <= 0 {
		return "", false
	}
	ns, name, ok := strings.Cut(sa.ID[i+len(saIDInfix):], "/serviceaccount/")
	return ns + ":" + name, ok
}

// grantsProvider reports whether a trust statement federates the given OIDC
// provider ARN.
func grantsProvider(stmt trustStatement, provider string) bool {
	for _, f := range federatedPrincipals(stmt.Principal) {
		if f == provider {
			return true
		}
	}
	return false
}
