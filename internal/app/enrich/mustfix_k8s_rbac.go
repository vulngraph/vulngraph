package enrich

import (
	"context"
	"fmt"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// maxRBACBindings bounds the inbound-binding fan-out walked for one Role or
// ClusterRole. A built-in ClusterRole like `view` is bound hundreds of times;
// the subject verdict never changes after the first external subject, so the
// walk is capped rather than exhaustive.
const maxRBACBindings = 100

// rbacSubjectBlastThreshold: a grant that reaches more than a handful of
// distinct subjects is a real blast radius in its own right, the RBAC analogue
// of mustFixBlastThreshold. Deliberately the same number — the two are the same
// judgement ("more than a handful") applied to different edge types.
const rbacSubjectBlastThreshold = mustFixBlastThreshold

// RBACBindingResolver returns the RoleBinding/ClusterRoleBinding assets that
// bind a given Role or ClusterRole, so a permission set can be scored by WHO
// actually holds it. Satisfied by asset.Service over the `binds` edges the
// kubernetes collector emits (RoleBinding→Role, RoleBinding→ClusterRole).
// Nil disables the lookup: a Role then scores on its own metadata alone, which
// is fail-open (no subject evidence never promotes).
type RBACBindingResolver interface {
	EdgesInto(ctx context.Context, dstID, edgeType string) ([]asset.Edge, error)
	ByIDs(ctx context.Context, ids []string) ([]asset.Asset, error)
}

// isK8sRBACGrant reports whether a finding is a Kubernetes RBAC
// privilege-grant finding — a Role/ClusterRole that confers a dangerous
// capability, or a RoleBinding/ClusterRoleBinding that hands one out.
//
// The predicate is deliberately (type AND resource type), not a check_id
// substring and not type alone. `type = "rbac"` alone is NOT sufficient: the
// pod-hardening checks k8s-privileged-container and k8s-dangerous-capabilities
// also carry it, on k8s_pod/k8s_deployment. Those are workload-hardening
// misconfigurations, not permission grants, and sweeping them into the privesc
// machinery is the mistake a Title-contains-"privilege escalation" match would
// make with k8s-container-allow-privilege-escalation (see isPrivesc).
//
// Keying on the resource TYPE rather than a list of check ids means a new RBAC
// check added to internal/checks is covered the day it ships, with no list to
// forget to update.
func isK8sRBACGrant(f finding.Finding) bool {
	return f.Type == "rbac" && graphschema.IsK8sRBACType(f.ResourceType)
}

// assessK8sRBACMustFix classifies a Kubernetes RBAC finding's urgency.
//
// It exists for the same reason assessSupplyChainMustFix and
// assessGHASSecretsMustFix do: the general reach/blast path in assessMustFix is
// a category mismatch for this resource. reach.InternetHops runs a network
// reachability BFS, and a Role is not a network node — it is not in
// graphstore.assetTypeToNode at all, so InternetHops never resolves and
// BlastRadiusCount always returns 0, leaving every RBAC finding to fall through
// classifyMustFix to "".
//
// The question that actually decides an RBAC grant's urgency is WHO HOLDS IT,
// and the answer is already collected — RoleBinding/ClusterRoleBinding assets
// carry a `subjects` list of "Kind/Name" pairs (internal/collect/kubernetes
// rbac.go), and `binds` edges connect a binding to the role it grants. So:
//
//   - a grant held by an identity from OUTSIDE the cluster (a Google Group, a
//     cloud service account, an AWS role, a human User) is elevated: it can be
//     exercised by anyone who holds that identity, with no cluster foothold
//     needed first.
//   - a grant held only by in-cluster ServiceAccounts is contained: exercising
//     it requires already running in the cluster — real lateral movement, not a
//     front door. This is the honest RBAC reading of the same
//     "internal/lateral risk only" bucket classifyMustFix already uses.
//   - a grant reaching many distinct subjects is elevated on blast alone.
//   - a Role or ClusterRole that NOTHING binds is contained: a dangerous
//     permission set nobody holds is a latent hygiene problem, not an urgent
//     one — a demotion this file can make because it is evidence-based rather
//     than a guess.
//
// Fail-open throughout, exactly like its siblings: a nil resolver, a lookup
// error, or a binding with no parseable subjects leaves the class blank rather
// than inventing urgency. Nothing here can reach MustFix — that tier requires
// the positive internet-reachability evidence this resource type can never
// produce, and quietly redefining the bar for one resource type would make the
// tier mean two different things.
func assessK8sRBACMustFix(ctx context.Context, f finding.Finding, seed asset.Asset, binds RBACBindingResolver) (class, reason string) {
	subjects, platform, known := rbacSubjects(ctx, f, seed, binds)
	if !known {
		return "", "" // no subject evidence at all — fail open
	}
	if len(subjects) == 0 {
		return MustFixContained, "no RoleBinding grants this role to any subject — unused permission set"
	}

	external := externalRBACSubjects(subjects, platform)
	switch {
	case len(external) > 0:
		return MustFixElevated, fmt.Sprintf(
			"granted to %s — an identity outside the cluster, exercisable without a cluster foothold",
			strings.Join(external, ", "))
	case len(subjects) >= rbacSubjectBlastThreshold:
		return MustFixElevated, fmt.Sprintf(
			"granted to %d in-cluster subjects — broad lateral blast radius", len(subjects))
	default:
		return MustFixContained, fmt.Sprintf(
			"granted only to %d in-cluster ServiceAccount(s) — requires an existing cluster foothold",
			len(subjects))
	}
}

// rbacSubjects resolves the subject set for an RBAC finding. A binding carries
// its subjects directly; a Role/ClusterRole gets them from the bindings that
// reference it. known=false means "could not determine at all" and must never be
// read as "no subjects" — that distinction is the difference between a fail-open
// blank and a positive "nothing binds this" demotion.
//
// platform is the subjects the collector recorded as the cluster provider's own
// control-plane Users (binding platform_subjects: set only on a cluster known
// to be that provider's), which are in-cluster identities, not external ones.
func rbacSubjects(ctx context.Context, f finding.Finding, seed asset.Asset, binds RBACBindingResolver) (subjects []string, platform map[string]bool, known bool) {
	platform = map[string]bool{}
	if graphschema.IsK8sRBACBindingType(f.ResourceType) {
		raw, ok := seed.Metadata["subjects"]
		if !ok {
			return nil, nil, false // binding asset without the field — treat as unknown
		}
		for _, s := range splitRBACSubjects(seed.Metadata["platform_subjects"]) {
			platform[s] = true
		}
		return splitRBACSubjects(raw), platform, true
	}

	// Role / ClusterRole: walk the inbound binds edges.
	if binds == nil {
		return nil, nil, false
	}
	edges, err := binds.EdgesInto(ctx, f.ResourceID, "binds")
	if err != nil {
		return nil, nil, false
	}
	ids := make([]string, 0, len(edges))
	seen := map[string]struct{}{}
	for _, e := range edges {
		if e.SrcID == "" {
			continue
		}
		if _, dup := seen[e.SrcID]; dup {
			continue
		}
		seen[e.SrcID] = struct{}{}
		ids = append(ids, e.SrcID)
		if len(ids) >= maxRBACBindings {
			break
		}
	}
	if len(ids) == 0 {
		// The edges resolved cleanly and there are none: this role is genuinely
		// unbound. That IS knowledge, and it is the demotion this path exists to
		// make.
		return nil, platform, true
	}
	bindingAssets, err := binds.ByIDs(ctx, ids)
	if err != nil {
		return nil, nil, false
	}
	uniq := map[string]struct{}{}
	for _, b := range bindingAssets {
		for _, s := range splitRBACSubjects(b.Metadata["subjects"]) {
			uniq[s] = struct{}{}
		}
		for _, s := range splitRBACSubjects(b.Metadata["platform_subjects"]) {
			platform[s] = true
		}
	}
	if len(uniq) == 0 {
		// Bindings exist but none names a subject — that is a collection gap, not
		// evidence of an unheld role, so it must not demote.
		return nil, nil, false
	}
	out := make([]string, 0, len(uniq))
	for s := range uniq {
		out = append(out, s)
	}
	return out, platform, true
}

// splitRBACSubjects parses the collector's comma-separated "Kind/Name" subject
// list. Empty entries are dropped so a trailing comma never counts as a subject.
func splitRBACSubjects(raw string) []string {
	var out []string
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// externalRBACSubjects returns the subjects that are NOT in-cluster
// ServiceAccounts or the provider's own control-plane Users (platform) —
// Users, Groups, and any subject naming a cloud identity. Capped in the
// returned list so the reason string stays readable; the caller only branches
// on whether it is empty.
func externalRBACSubjects(subjects []string, platform map[string]bool) []string {
	var out []string
	for _, s := range subjects {
		if !isExternalRBACSubject(s) || platform[s] {
			continue
		}
		if len(out) < 3 {
			out = append(out, s)
		}
	}
	return out
}

// isExternalRBACSubject reports whether an RBAC subject can be held from
// outside the cluster. Kubernetes RBAC subject kinds are ServiceAccount, User
// and Group (rbac/v1 SubjectKind); only ServiceAccount is an in-cluster
// principal. A "User" whose name is a cloud service-account email or an AWS
// role ARN is how GKE Workload Identity and EKS IAM mapping name cloud
// principals, so those are external too — that is the case worth catching, not
// an edge case.
func isExternalRBACSubject(s string) bool {
	kind, name, ok := strings.Cut(s, "/")
	if !ok {
		// No kind prefix — cannot tell, and guessing "external" would promote on
		// absence of evidence. Treat as in-cluster.
		return false
	}
	switch kind {
	case "User", "Group":
		return true
	case "ServiceAccount":
		// A ServiceAccount subject is in-cluster by definition; the name is a
		// plain SA name, never a cloud identity.
		return false
	default:
		// Unknown kind: only call it external when the name is unmistakably a
		// cloud principal.
		return strings.Contains(name, ".iam.gserviceaccount.com") ||
			strings.HasPrefix(name, "arn:aws:iam:")
	}
}
