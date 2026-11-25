package correlate

import (
	"sync"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// PendingVerify is a workflow-declared AWS role in an account with no matching
// live iam_role node — a candidate for the out-of-band verify_ci_role live
// GetRole job. GCP targets are never queued here: there is no equivalent
// live-verify job for GCP service accounts.
type PendingVerify struct {
	RepoID       string
	TargetARN    string
	AccountID    string
	WorkflowPath string
}

// CIAccess joins declared_ci_access assets (parsed from .github/workflows by
// the IaC/GitHub collectors) to live iam_role / gcp_service_account
// nodes, emitting federated_access edges (repo -> role/SA) with provenance
// gh_workflow. AWS targets with no live iam_role match are accumulated in
// pending for later live verification rather than dropped silently; GCP
// targets with no live match are simply skipped.
//
// Matching reuses the same live-node existence check as GCPWorkloadIdentity
// (g.IsPrincipal): iam_role asset IDs are the role ARN, and gcp_service_account
// asset IDs are "serviceAccount:<email>" (internal/collect/gcp/iam.go), so both
// targets can be checked for presence without a dedicated index.
//
// mu guards pending. cmd/graph/worker.go constructs one *CIAccess and shares
// it two ways: registered as a correlate.Rule (Correlate is invoked from
// inside correlate.Service's generic per-rule loop) and held directly as
// jobs.Deps.CIAccessPending (PendingLiveVerify is called from
// jobs/correlate.go's workFull right after that same loop finishes). Rule's
// interface has no room to carry AWS-target-with-no-live-match output back to
// the caller as a value, so it leaves the loop through a field instead, making
// CIAccess the one Rule in this package with a genuine reason to hold state
// across the two reads.
//
// The mutex makes concurrent access memory-safe, but does NOT make the two
// call sites safe from cross-run contamination if correlateWorkers
// (internal/jobs/client.go) is ever raised above 1: a second sweep's Correlate
// call could reset+repopulate pending between this sweep's Correlate returning
// and its PendingLiveVerify read. That is safe today only because
// correlateWorkers=1 serializes every correlate job to completion before the
// next starts.
type CIAccess struct {
	mu      sync.Mutex
	pending []PendingVerify
}

func (*CIAccess) Name() string { return "ci_access" }

func (*CIAccess) InterestedIn() []string {
	return []string{"declared_ci_access", "iam_role", "gcp_service_account"}
}

// PendingLiveVerify returns a copy of the AWS role targets that had no live
// iam_role match in the most recent Correlate run — candidates for the
// verify_ci_role job. A copy is returned so callers cannot mutate
// the rule's internal state.
func (r *CIAccess) PendingLiveVerify() []PendingVerify {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]PendingVerify, len(r.pending))
	copy(out, r.pending)
	return out
}

// Correlate runs on every full sweep AND every PartialCorrelate. In production
// correlateWorkers=1 (internal/jobs/client.go) serializes every correlate job
// to completion before the next starts, so Correlate is never invoked
// concurrently on the same rule instance today — see the mu doc on CIAccess
// for what the lock does and does not guarantee if that ever changes.
// pending is rebuilt into a local slice and committed at the END of every
// call so PendingLiveVerify reflects only the latest sweep's unmatched AWS
// targets, not an unbounded accumulation across sweeps. This requires
// Correlate to actually run every sweep, including one over an empty view —
// Service.Correlate must not short-circuit before the rule loop.
func (r *CIAccess) Correlate(g Graph) []asset.Edge {
	// Built into locals first, so the lock is held only for the final commit —
	// not for the whole scan of g.DeclaredCIAccess() — while still making the
	// reset-then-repopulate visible to PendingLiveVerify as one atomic step
	// rather than a window where pending briefly reads as nil mid-Correlate.
	var edges []asset.Edge
	var pending []PendingVerify
	for _, d := range g.DeclaredCIAccess() {
		repoID := d.Metadata["repo"]
		if repoID == "" {
			continue
		}

		switch d.Metadata["provider"] {
		case "aws":
			arn := d.Metadata["target_arn"]
			if arn == "" {
				continue
			}
			if g.IsPrincipal(arn) {
				edges = append(edges, ciAccessEdge(repoID, arn, "iam_role", d.Metadata["workflow_path"]))
			} else {
				pending = append(pending, PendingVerify{
					RepoID: repoID, TargetARN: arn, AccountID: d.Metadata["account_id"],
					WorkflowPath: d.Metadata["workflow_path"],
				})
			}
		case "gcp":
			sa := d.Metadata["target_sa"]
			if sa == "" {
				continue
			}
			saID := "serviceAccount:" + sa
			if g.IsPrincipal(saID) {
				edges = append(edges, ciAccessEdge(repoID, saID, "gcp_service_account", d.Metadata["workflow_path"]))
			}
		}
	}

	r.mu.Lock()
	r.pending = pending
	r.mu.Unlock()

	return edges
}

func ciAccessEdge(repoID, targetID, targetType, workflowPath string) asset.Edge {
	return asset.Edge{
		SrcID: repoID, SrcType: "github_repo",
		DstID: targetID, DstType: targetType,
		EdgeType: EdgeFederatedAccess,
		Properties: map[string]string{
			"origin":        edgeOrigin,
			"rule":          "ci_access",
			"provenance":    "gh_workflow",
			"confidence":    "high",
			"workflow_path": workflowPath,
		},
	}
}
