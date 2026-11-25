package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/smithy-go"
	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/correlate"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// VerifyCIRoleArgs live-verifies one workflow-declared AWS role that the batch
// correlate sweep found no live iam_role node for this pass (correlate.
// PendingVerify). A batch miss is ambiguous — the role may exist but
// sync hasn't ingested it yet, or the declaring account may not be monitored
// at all — so this job makes a direct, out-of-band IAM GetRole call to resolve
// it definitively.
type VerifyCIRoleArgs struct {
	RepoID       string `json:"repo_id"`
	TargetARN    string `json:"target_arn"`
	AccountID    string `json:"account_id"`
	WorkflowPath string `json:"workflow_path"`
}

func (VerifyCIRoleArgs) Kind() string { return "verify_ci_role" }

// InsertOpts: this is a single live IAM read, not a cloud mutation, so
// re-running it after a transient failure is harmless and a bounded retry (3,
// matching SyncConnectorArgs) fits.
// Queued on queueSync: like a connector sync, this is an I/O-bound call
// against a cloud API using connector-stored credentials. Unique while
// queued/running so a repeat correlate sweep can't pile a second job onto the
// same (repo, ARN, account, workflow) target before the first one runs.
func (VerifyCIRoleArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       queueSync,
		MaxAttempts: 3,
		UniqueOpts:  river.UniqueOpts{ByArgs: true, ByState: uniqueStates},
	}
}

// liveRoleGetter is the slice of mcp.LiveAWSCallerImpl the job needs.
type liveRoleGetter interface {
	GetRole(ctx context.Context, connectorID, roleARN string) (map[string]any, error)
}

// connectorAccountLookup finds the connector that can reach an AWS account.
// *connector.Service satisfies it via ConnectorByAccountID.
type connectorAccountLookup interface {
	ConnectorByAccountID(ctx context.Context, accountID string) (connectorID string, ok bool, err error)
}

// roleAssetWriter materializes a live-verified role as an asset and links it
// to the declaring repo. *asset.Service satisfies it via Ingest.
type roleAssetWriter interface {
	Ingest(ctx context.Context, assets []asset.Asset, edges []asset.Edge) error
}

// unmonitoredFindingWriter records the unmonitored-account finding.
// *finding.Service satisfies it via RecordObserved.
type unmonitoredFindingWriter interface {
	RecordObserved(ctx context.Context, findings []finding.Finding) error
}

// VerifyCIRoleWorker runs the live-verify job. run() is the testable core,
// decoupled from River so it can be driven directly with fakes.
type VerifyCIRoleWorker struct {
	river.WorkerDefaults[VerifyCIRoleArgs]
	live     liveRoleGetter
	conn     connectorAccountLookup
	roles    roleAssetWriter
	findings unmonitoredFindingWriter
}

// NewVerifyCIRoleWorker builds a VerifyCIRoleWorker from its narrow deps.
func NewVerifyCIRoleWorker(live liveRoleGetter, conn connectorAccountLookup, roles roleAssetWriter, findings unmonitoredFindingWriter) *VerifyCIRoleWorker {
	return &VerifyCIRoleWorker{live: live, conn: conn, roles: roles, findings: findings}
}

// Timeout bounds one live IAM read plus two writes; a hung cloud call must not
// hold a sync-queue slot.
func (w *VerifyCIRoleWorker) Timeout(_ *river.Job[VerifyCIRoleArgs]) time.Duration {
	return 2 * time.Minute
}

func (w *VerifyCIRoleWorker) Work(ctx context.Context, job *river.Job[VerifyCIRoleArgs]) error {
	return w.run(ctx, job.Args)
}

func (w *VerifyCIRoleWorker) run(ctx context.Context, a VerifyCIRoleArgs) error {
	connID, ok, err := w.conn.ConnectorByAccountID(ctx, a.AccountID)
	if err != nil {
		return fmt.Errorf("verify_ci_role: connector lookup: %w", err)
	}
	if !ok {
		// No connector monitors this account at all — a real blind spot, not a
		// transient miss, so it is worth surfacing as a finding rather than
		// silently dropping (this is the whole point of the live-verify path:
		// a batch miss on an unmonitored account would otherwise never resolve).
		workflow := "CI workflow"
		if a.WorkflowPath != "" {
			workflow = fmt.Sprintf("CI workflow (%s)", a.WorkflowPath)
		}
		f := finding.Finding{
			ID:       dbutil.DeterministicID("unmonitored_federation", a.RepoID, a.TargetARN),
			Source:   "ci_access",
			Type:     "unmonitored_federation",
			Severity: finding.SeverityLow,
			Title:    "CI workflow federates to an unmonitored cloud account",
			Description: fmt.Sprintf(
				"repo %s %s assumes role %s in account %s, which has no configured connector — this account's IAM posture is invisible to Vulngraph.",
				a.RepoID, workflow, a.TargetARN, a.AccountID),
			ResourceType: "github_repo",
			ResourceID:   a.RepoID,
			CheckID:      "unmonitored_federation",
			DetectedAt:   time.Now(),
		}
		if err := w.findings.RecordObserved(ctx, []finding.Finding{f}); err != nil {
			return fmt.Errorf("verify_ci_role: write unmonitored finding: %w", err)
		}
		return nil
	}

	fields, err := w.live.GetRole(ctx, connID, a.TargetARN)
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchEntity" {
			// The role the workflow declares genuinely doesn't exist (renamed,
			// deleted, or a stale/erroneous ARN in the workflow file) — nothing to
			// link. Not an error: the sweep should not retry this ARN forever.
			log.FromContext(ctx).Debug().Str("target_arn", a.TargetARN).Str("repo", a.RepoID).
				Msg("verify_ci_role: role does not exist — dropped")
			return nil
		}
		return fmt.Errorf("verify_ci_role: GetRole: %w", err)
	}

	roleName, _ := fields["role_name"].(string)
	path, _ := fields["path"].(string)
	now := time.Now()
	roleAsset := asset.Asset{
		ID:           a.TargetARN,
		Name:         roleName,
		Type:         "iam_role",
		Provider:     asset.ProviderAWS,
		Region:       "global",
		AccountID:    a.AccountID,
		Metadata:     map[string]string{"path": path, "verified_live": "true"},
		DiscoveredAt: now,
		LastSeen:     now,
	}
	edge := asset.Edge{
		SrcID: a.RepoID, SrcType: "github_repo",
		DstID: a.TargetARN, DstType: "iam_role",
		EdgeType: correlate.EdgeFederatedAccess,
		Properties: map[string]string{
			"origin":        "correlate",
			"rule":          "ci_access",
			"provenance":    "gh_workflow+live",
			"confidence":    "high",
			"workflow_path": a.WorkflowPath,
		},
	}
	if err := w.roles.Ingest(ctx, []asset.Asset{roleAsset}, []asset.Edge{edge}); err != nil {
		return fmt.Errorf("verify_ci_role: ingest role+edge: %w", err)
	}
	return nil
}
