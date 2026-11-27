package jobs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// assetReader loads stored organization-policy evidence for the sweep.
type assetReader interface {
	ByIDs(ctx context.Context, ids []string) ([]asset.Asset, error)
}

// analyzeIAM runs the CIEM engine over a sweep and stamps each identity's
// privilege tier onto assets in place. It runs BEFORE the fingerprint, diff and
// ingest so the tier is part of the persisted asset and of its content hash: a
// tier change re-checks the principal, and the posture checks — which only see
// collector output — can read it.
//
// The returned input is what the engine saw (the sweep plus the accounts' SCP
// sets), which the escalation-edge writer resolves edge endpoints against.
// partial is true when the organization-evidence read failed. Candidates remain
// visible, but the coverage and tier are unknown and cannot resolve findings.
func analyzeIAM(ctx context.Context, store assetReader, assets []asset.Asset) ([]asset.Asset, ciem.AnalysisResult, bool, error) {
	// SCPs are collected only by the management connector, so a member
	// account's own sweep doesn't carry them. Fetch the aws_scp_set asset for
	// each account present in this sweep and hand them to CIEM so it can cap
	// effective permissions. A missing SCP asset leaves applicability unknown.
	input := assets
	scps, remote, err := fetchSCPAssets(ctx, store, assets)
	partial := err != nil
	if partial {
		log.FromContext(ctx).Warn().Err(err).Int("accounts", len(remote)).
			Msg("ciem: scp asset fetch failed — organization coverage unknown; retaining permission candidates")
	} else if len(scps) > 0 {
		input = append(append([]asset.Asset(nil), assets...), scps...)
	}
	result := ciem.AnalyzeIAMAssets(ctx, input)
	// Scores belong to this observation, just like the tier. Apply them before
	// the one inventory write: re-inserting ScoredAssets afterward would put
	// its older observation fields and last_seen over a concurrent newer sync.
	scores := make(map[string]uint8, len(result.ScoredAssets))
	for _, a := range result.ScoredAssets {
		scores[a.ID] = a.RiskScore
	}
	for i := range assets {
		if score, ok := scores[assets[i].ID]; ok {
			assets[i].RiskScore = score
		}
	}
	ciem.StampAWSOrganizationCoverage(assets, result.OrganizationPolicyCoverage)
	ciem.StampTiers(assets, result.Tiers)
	return input, result, partial, nil
}

// ciemEscalationEdges builds one can_escalate_to edge per (source, target) pair
// of the detected CIEM paths. These are IamRole→IamRole edges that power the
// deep CIEM Cypher queries:
//
//	MATCH (a:IamRole)-[:CanEscalateTo]->(b:IamRole) …
//
// Targets come from PrivescResult.TargetPrincipals — concrete principal ARNs
// resolved from the granting policy's resource scopes. The older single
// TargetPrincipal field only ever held the AnyPrincipal sentinel or "", both
// of which are skipped, so a writer reading it produces no edges at all.
//
// dst is looked up in the analysed asset set rather than trusted: an edge to an
// id that is not an asset is dropped at Ladybug load with no signal. A target in
// another account (swept separately) is therefore skipped and counted in
// dangling, not written blind.
func ciemEscalationEdges(input []asset.Asset, paths []ciem.PrivescResult) (edges []asset.Edge, dangling int) {
	if len(paths) == 0 {
		return nil, 0
	}
	knownType := make(map[string]string, len(input))
	for _, a := range input {
		knownType[a.ID] = a.Type
	}
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		if p.SourcePrincipal == "" {
			continue
		}
		srcType, ok := knownType[p.SourcePrincipal]
		if !ok {
			continue
		}
		for _, target := range p.TargetPrincipals {
			dstType, ok := knownType[target]
			if !ok {
				dangling++
				continue
			}
			if target == p.SourcePrincipal {
				continue // self-escalation is a node property, not an edge (BFS ignores self-loops)
			}
			key := p.SourcePrincipal + "|" + target
			if seen[key] {
				continue // dedup: one edge per (src, dst) pair
			}
			seen[key] = true
			edges = append(edges, asset.Edge{
				SrcID:    p.SourcePrincipal,
				SrcType:  srcType,
				DstID:    target,
				DstType:  dstType,
				EdgeType: "can_escalate_to",
				Properties: map[string]string{
					"rule":  p.Rule.ID,
					"steps": joinSteps(p.Steps),
				},
			})
		}
	}
	return edges, dangling
}

// ciemFindings maps CIEM engine privesc findings onto finding.Finding. Only
// principals in `targets` are included (matching the CSPM changed-asset cadence
// so unchanged assets keep their enriched scores). Source/Type/CheckID are the
// values PrivescCount, ToxicCombo, and enrich bucketing key on — the engine is
// the single source of these findings.
func ciemFindings(fs []ciem.PrivescFinding, targets map[string]bool, now time.Time) []finding.Finding {
	out := make([]finding.Finding, 0, len(fs))
	for _, f := range fs {
		if targets != nil && !targets[f.PrincipalID] {
			continue
		}
		out = append(out, finding.Finding{
			ID:           dbutil.DeterministicID(f.RuleID, f.PrincipalID),
			Source:       "cspm",
			Type:         "ciem_privesc",
			Severity:     finding.Severity(f.Severity),
			Title:        "Privilege escalation: " + f.Technique,
			Description:  f.Description,
			ResourceType: f.PrincipalType,
			ResourceID:   f.PrincipalID,
			ResourceName: f.PrincipalName,
			CheckID:      f.RuleID,
			Remediation:  "Remove or scope the permissions enabling " + f.Technique + "; apply least privilege and a permissions boundary.",
			DetectedAt:   now,
		})
	}
	return out
}

// fetchSCPAssets loads the aws_scp_set asset for every distinct AWS account
// in the sweep that does not carry its own (the management connector's sweep
// does). remote is the set of accounts read from the store — on an error,
// the accounts whose SCP coverage is unknown. An absent asset remains absent;
// the shared evaluator recognizes that as unknown, never as an exemption.
func fetchSCPAssets(ctx context.Context, store assetReader, assets []asset.Asset) (scps []asset.Asset, remote map[string]bool, err error) {
	inSweep := map[string]bool{}
	for _, a := range assets {
		if a.Type == "aws_scp_set" {
			inSweep[a.AccountID] = true
		}
	}
	remote = map[string]bool{}
	var ids []string
	for _, a := range assets {
		if a.Provider != asset.ProviderAWS || a.AccountID == "" || inSweep[a.AccountID] || remote[a.AccountID] {
			continue
		}
		remote[a.AccountID] = true
		ids = append(ids, "aws_scp:"+a.AccountID)
	}
	if len(ids) == 0 {
		return nil, remote, nil
	}
	scps, err = store.ByIDs(ctx, ids)
	if err != nil {
		return nil, remote, fmt.Errorf("fetchSCPAssets: %w", err)
	}
	return scps, remote, nil
}

// joinSteps formats a CIEM technique's attack steps as a compact string for
// the edge properties map. Used to annotate can_escalate_to edges with the
// human-readable path so Cypher queries can surface it.
func joinSteps(steps []string) string {
	if len(steps) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(steps[0])
	for i := 1; i < len(steps) && i < 5; i++ { // cap at 5 to stay compact
		b.WriteString(" → ")
		b.WriteString(steps[i])
	}
	return b.String()
}
