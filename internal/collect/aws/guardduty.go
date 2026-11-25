package aws

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// gdBatch is GetFindings' max ids per call.
const gdBatch = 50

// gdMaxAge and gdMaxPages bound what one sweep pulls per detector. GuardDuty
// keeps findings for 90 days, and a noisy detector can hold tens of thousands;
// listing is sorted most-severe first, so the page cap (gdMaxPages × gdBatch
// ids) keeps the findings that matter and bounds the sync's cost.
const (
	gdMaxAge   = 90 * 24 * time.Hour
	gdMaxPages = 20
)

// guardDutyAPI is the slice of GuardDuty the collector uses (mockable in tests).
type guardDutyAPI interface {
	ListDetectors(context.Context, *guardduty.ListDetectorsInput, ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error)
	ListFindings(context.Context, *guardduty.ListFindingsInput, ...func(*guardduty.Options)) (*guardduty.ListFindingsOutput, error)
	GetFindings(context.Context, *guardduty.GetFindingsInput, ...func(*guardduty.Options)) (*guardduty.GetFindingsOutput, error)
}

// collectGuardDuty pulls active GuardDuty findings for one region and maps them
// to platform findings (source "aws_guardduty"). GuardDuty is regional and its
// findings are provider-computed threat detections we cannot self-generate, so
// they enter as findings, not assets — and link to the resource they name (an
// EC2 instance id matches an ec2_instance asset, so blast radius/provenance
// apply). Read access comes from the SecurityAudit policy the assumed
// read-only collection role already carries.
//
// The bool reports that the returned findings are EVERY active finding in the
// region — see collectGuardDutyFindings.
func collectGuardDuty(ctx context.Context, cfg map[string]string, region string, now time.Time) ([]finding.Finding, bool, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, false, fmt.Errorf("collectGuardDuty: %w", err)
	}
	return collectGuardDutyFindings(ctx, guardduty.NewFromConfig(awsCfg), region, now)
}

// collectGuardDutyFindings lists and maps the region's active findings.
//
// The bool is true only when the listing is provably exhaustive: every
// detector's ListFindings ran out of pages before gdMaxPages, and every
// GetFindings batch succeeded (any error returns early, so a nil error already
// covers that). Only then does a finding's absence mean GuardDuty no longer
// considers it active. A region with no detector is complete with nothing in
// it: GuardDuty deletes a detector's findings when the detector is removed, so
// none can still be active there.
func collectGuardDutyFindings(ctx context.Context, client guardDutyAPI, region string, now time.Time) ([]finding.Finding, bool, error) {
	detectors, err := client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return nil, false, fmt.Errorf("collectGuardDutyFindings: list detectors: %w", err)
	}
	// AWS allows one detector per account per region, so a second page never
	// arrives in practice; it is still not read, so the listing cannot claim it.
	complete := detectors.NextToken == nil || *detectors.NextToken == ""

	// GuardDuty emits a separate finding per (resource, threat-type,
	// time-window/domain), so one infected host can yield many findings of
	// the same type. Collapse to ONE finding per (resource, type) carrying an
	// occurrence count — the actionable unit is "this host has this threat",
	// not each event. Keeps the most-severe representative.
	grouped := map[string]*finding.Finding{}
	counts := map[string]int{}
	var order []string
	for _, det := range detectors.DetectorIds {
		ids, exhaustive, err := listFindingIDs(ctx, client, det, now)
		if err != nil {
			return nil, false, err
		}
		complete = complete && exhaustive
		for start := 0; start < len(ids); start += gdBatch {
			end := min(start+gdBatch, len(ids))
			got, err := client.GetFindings(ctx, &guardduty.GetFindingsInput{
				DetectorId: awssdk.String(det),
				FindingIds: ids[start:end],
			})
			if err != nil {
				return nil, false, fmt.Errorf("collectGuardDutyFindings: get findings: %w", err)
			}
			for i := range got.Findings {
				f := mapGuardDutyFinding(got.Findings[i], region, now)
				key := f.ResourceID + "\x00" + f.CheckID
				counts[key]++
				if g, ok := grouped[key]; !ok {
					fc := f
					grouped[key] = &fc
					order = append(order, key)
				} else if gdSeverityRank(f.Severity) > gdSeverityRank(g.Severity) {
					*g = f // keep the most-severe representative for this (resource, type)
				}
			}
		}
	}

	out := make([]finding.Finding, 0, len(order))
	for _, key := range order {
		g := grouped[key]
		// Stable per (resource, type) so repeats collapse across sweeps too.
		g.ID = dbutil.DeterministicID("aws_guardduty", g.ResourceID, g.CheckID)
		if n := counts[key]; n > 1 {
			if g.Metadata == nil {
				g.Metadata = map[string]string{}
			}
			g.Metadata["occurrences"] = strconv.Itoa(n)
			g.Title = fmt.Sprintf("%s (×%d)", g.Title, n)
		}
		out = append(out, *g)
	}
	return out, complete, nil
}

// eksClusterCoverageCheckID identifies the coverage finding below. It is NOT a
// checks.Registry check: the registry evaluates one asset at a time, and the
// whole point here is a resource that has NO asset.
const eksClusterCoverageCheckID = "aws-eks-cluster-not-inventoried"

// uninventoriedEKSClusterFindings reports EKS clusters that GuardDuty is
// producing findings about and that this account's inventory does not
// contain.
//
// GuardDuty names the cluster by ARN (guardDutyResource, EksClusterDetails.Arn),
// and collectEKS mints exactly that ARN as the eks_cluster asset ID, so this
// is an exact join, not a guess from a finding title. A cluster missing an
// asset is not "clean", it is unexamined — every posture check, the graph,
// blast radius and reachability all start from an asset.
//
// eksListedRegions is the set of regions where ListClusters actually
// succeeded this sweep. Absence of an asset only means something when we
// looked: a throttled or Access-Denied EKS listing must not be reported as a
// missing cluster (same rule as result.Partial, applied per region since EKS
// is regional).
func uninventoriedEKSClusterFindings(
	findings []finding.Finding, assets []asset.Asset,
	eksListedRegions map[string]bool, now time.Time,
) []finding.Finding {
	inventoried := map[string]bool{}
	for _, a := range assets {
		if a.Type == "eks_cluster" {
			inventoried[a.ID] = true
		}
	}

	type coverage struct {
		region   string
		count    int
		severity finding.Severity
		types    []string
	}
	byARN := map[string]*coverage{}
	var order []string
	for _, f := range findings {
		if f.Source != "aws_guardduty" || f.ResourceType != "eks_cluster" || f.ResourceID == "" {
			continue
		}
		if !eksListedRegions[f.Region] || inventoried[f.ResourceID] {
			continue
		}
		c, ok := byARN[f.ResourceID]
		if !ok {
			c = &coverage{region: f.Region, severity: finding.SeverityMedium}
			byARN[f.ResourceID] = c
			order = append(order, f.ResourceID)
		}
		c.count++
		if gdSeverityRank(f.Severity) > gdSeverityRank(c.severity) {
			c.severity = f.Severity
		}
		if !slices.Contains(c.types, f.CheckID) {
			c.types = append(c.types, f.CheckID)
		}
	}

	out := make([]finding.Finding, 0, len(order))
	for _, arn := range order {
		c := byARN[arn]
		name := arn
		if _, after, ok := strings.Cut(arn, ":cluster/"); ok {
			name = after
		}
		sort.Strings(c.types)
		out = append(out, finding.Finding{
			ID:           dbutil.DeterministicID(eksClusterCoverageCheckID, arn),
			Source:       "aws_guardduty",
			Type:         "coverage",
			Severity:     c.severity,
			Title:        fmt.Sprintf("EKS cluster %s has GuardDuty findings but is not in inventory", name),
			Description:  "GuardDuty is reporting threat detections against this EKS cluster, but the cluster does not exist as a collected asset — ListClusters succeeded in this region and did not return it. Nothing that starts from an asset can see this cluster: no posture check evaluates it, no graph node represents it, and no workload inventory is joined to it. Its silence in every other view is absence of collection, not absence of risk.",
			Remediation:  "Confirm whether the cluster still exists. If it does, the collecting role cannot see it (cross-account cluster, or an eks:DescribeCluster/ListClusters permission gap in that account) — grant it and re-sync so the cluster and its workloads are inventoried. If it was deleted, archive the GuardDuty findings that still name it.",
			ResourceType: "eks_cluster",
			ResourceID:   arn,
			ResourceName: name,
			Region:       c.region,
			CheckID:      eksClusterCoverageCheckID,
			DetectedAt:   now,
			Metadata: map[string]string{
				"guardduty_findings":     strconv.Itoa(c.count),
				"guardduty_max_severity": string(c.severity),
				"guardduty_types":        strings.Join(c.types, ","),
			},
		})
	}
	return out
}

// gdSeverityRank orders severities so the collapse keeps the most severe.
func gdSeverityRank(s finding.Severity) int {
	switch s {
	case finding.SeverityCritical:
		return 4
	case finding.SeverityHigh:
		return 3
	case finding.SeverityMedium:
		return 2
	case finding.SeverityLow:
		return 1
	default:
		return 0
	}
}

// listFindingIDs pages through a detector's ACTIVE finding ids: archived
// findings (suppressed by a rule or archived by an operator) are excluded, as
// are findings not updated within gdMaxAge. Without the criteria every archived
// finding was ingested as a live threat. Most severe first, capped at
// gdMaxPages pages. The bool reports whether the listing ran out of pages
// before the cap; false means the cap cut it short.
func listFindingIDs(ctx context.Context, client guardDutyAPI, detectorID string, now time.Time) ([]string, bool, error) {
	criteria := &gdtypes.FindingCriteria{Criterion: map[string]gdtypes.Condition{
		"service.archived": {Equals: []string{"false"}},
		"updatedAt":        {GreaterThanOrEqual: awssdk.Int64(now.Add(-gdMaxAge).UnixMilli())},
	}}
	var ids []string
	var token *string
	for range gdMaxPages {
		page, err := client.ListFindings(ctx, &guardduty.ListFindingsInput{
			DetectorId:      awssdk.String(detectorID),
			FindingCriteria: criteria,
			SortCriteria:    &gdtypes.SortCriteria{AttributeName: awssdk.String("severity"), OrderBy: gdtypes.OrderByDesc},
			MaxResults:      awssdk.Int32(gdBatch),
			NextToken:       token,
		})
		if err != nil {
			return nil, false, fmt.Errorf("listFindingIDs: %w", err)
		}
		ids = append(ids, page.FindingIds...)
		if page.NextToken == nil || *page.NextToken == "" {
			return ids, true, nil
		}
		token = page.NextToken
	}
	log.FromContext(ctx).Warn().Str("detector_id", detectorID).Int("ids", len(ids)).
		Msg("guardduty: active finding listing capped; the least severe findings beyond the cap are not ingested this sweep")
	return ids, false, nil
}

// mapGuardDutyFinding maps one GuardDuty finding to a platform finding. The ID
// set here is provisional: the caller replaces it with a per-(resource, type)
// DeterministicID once same-type findings are merged.
func mapGuardDutyFinding(f gdtypes.Finding, region string, now time.Time) finding.Finding {
	resourceID, resourceType := guardDutyResource(f.Resource, awssdk.ToString(f.AccountId), region)
	gdType := awssdk.ToString(f.Type)
	return finding.Finding{
		ID:           dbutil.DeterministicID("aws_guardduty", awssdk.ToString(f.Id)),
		Source:       "aws_guardduty",
		Type:         "threat",
		Severity:     guardDutySeverity(f.Severity),
		Title:        awssdk.ToString(f.Title),
		Description:  awssdk.ToString(f.Description),
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Region:       region,
		CheckID:      gdType, // e.g. "Recon:EC2/PortProbeUnprotectedPort"
		Remediation:  "Investigate the GuardDuty detection and contain the affected resource per your IR runbook.",
		DetectedAt:   now,
	}
}

// guardDutySeverity maps GuardDuty's 1.0–10.0 scale to the platform severity.
// GuardDuty bands: 9.0–10.0 Critical (Extended Threat Detection attack
// sequences), 7.0–8.9 High, 4.0–6.9 Medium, 1.0–3.9 Low.
func guardDutySeverity(sev *float64) finding.Severity {
	s := awssdk.ToFloat64(sev)
	switch {
	case s >= 9:
		return finding.SeverityCritical
	case s >= 7:
		return finding.SeverityHigh
	case s >= 4:
		return finding.SeverityMedium
	default:
		return finding.SeverityLow
	}
}

// guardDutyResource extracts the platform resource id + type from a GuardDuty
// resource so the finding links to the asset it concerns. The id is built in
// the same ARN/ID scheme our own collectors use for that resource kind, so
// the join against graph.assets actually resolves. Falls back to the raw
// GuardDuty resource type only when the specific detail struct isn't
// populated — that placeholder can never match a real asset. The ECS
// container case is a documented exception; see its comment below.
func guardDutyResource(r *gdtypes.Resource, accountID, region string) (id, typ string) {
	if r == nil {
		return "", ""
	}
	switch {
	// Container-level cases MUST be checked before the EksClusterDetails/
	// EcsClusterDetails cluster-level cases below: an EKS or ECS container
	// finding populates BOTH the cluster detail struct and ContainerDetails, and
	// a container-level finding is the more specific resource — falling through
	// to the cluster ARN would silently collapse every container finding in a
	// cluster onto one asset.
	case r.ContainerDetails != nil && r.ContainerDetails.Name != nil &&
		r.KubernetesDetails != nil && r.KubernetesDetails.KubernetesWorkloadDetails != nil &&
		r.EksClusterDetails != nil && r.EksClusterDetails.Name != nil &&
		strings.EqualFold(awssdk.ToString(r.KubernetesDetails.KubernetesWorkloadDetails.Type), "Pod"):
		// EKS-sourced container finding: GuardDuty's KubernetesWorkloadDetails
		// carries the pod's namespace/name directly, so we can build the exact
		// k8s_pod container ID scheme (kubernetes.go's podAsset:
		// "<cluster>/pod/<ns>/<pod>/container/<name>") and the join resolves —
		// provided the k8s connector's cfg["cluster_name"] matches the real EKS
		// cluster name (nothing enforces this; the two collectors run
		// independently). If it doesn't match, falls through to the fallback below.
		wl := r.KubernetesDetails.KubernetesWorkloadDetails
		return fmt.Sprintf("%s/pod/%s/%s/container/%s",
			awssdk.ToString(r.EksClusterDetails.Name),
			awssdk.ToString(wl.Namespace),
			awssdk.ToString(wl.Name),
			awssdk.ToString(r.ContainerDetails.Name),
		), "container"
	case r.ContainerDetails != nil && r.ContainerDetails.Id != nil:
		// ECS-sourced (or otherwise parent-less) container finding. GuardDuty
		// keys ECS container findings by the running TASK, but our ecs.go
		// collector only promotes containers from the task DEFINITION under
		// the owning ecs_service — a different granularity with no reliable
		// way to resolve task ARN back to the owning service. Documented gap:
		// this can't join to graph.assets, so the container id at least
		// distinguishes findings from each other.
		return awssdk.ToString(r.ContainerDetails.Id), "container"
	case r.InstanceDetails != nil && r.InstanceDetails.InstanceId != nil:
		return awssdk.ToString(r.InstanceDetails.InstanceId), "ec2_instance"
	case r.AccessKeyDetails != nil && r.AccessKeyDetails.UserName != nil:
		return accessKeyPrincipal(r.AccessKeyDetails, accountID, region)
	case len(r.S3BucketDetails) > 0 && r.S3BucketDetails[0].Name != nil:
		return awssdk.ToString(r.S3BucketDetails[0].Name), "s3_bucket"
	case r.RdsDbInstanceDetails != nil && r.RdsDbInstanceDetails.DbInstanceArn != nil:
		return awssdk.ToString(r.RdsDbInstanceDetails.DbInstanceArn), "rds_instance"
	case r.RdsDbInstanceDetails != nil && r.RdsDbInstanceDetails.DbInstanceIdentifier != nil:
		// RDS Protection findings (e.g. login-attempt/probe detections) frequently
		// populate DbInstanceIdentifier but leave DbInstanceArn empty. Rebuild the
		// ARN in RDS's own convention (identifiers are case-insensitive, always
		// lowercase in the real ARN) so this still joins graph.assets instead of
		// falling through to the unlinkable "RDSDBInstance" placeholder below.
		return fmt.Sprintf("arn:%s:rds:%s:%s:db:%s", partitionFor(region), region, accountID,
			strings.ToLower(awssdk.ToString(r.RdsDbInstanceDetails.DbInstanceIdentifier))), "rds_instance"
	case r.EksClusterDetails != nil && r.EksClusterDetails.Arn != nil:
		return awssdk.ToString(r.EksClusterDetails.Arn), "eks_cluster"
	case r.EcsClusterDetails != nil && r.EcsClusterDetails.Arn != nil:
		return awssdk.ToString(r.EcsClusterDetails.Arn), "ecs_cluster"
	case r.LambdaDetails != nil && r.LambdaDetails.FunctionArn != nil:
		return awssdk.ToString(r.LambdaDetails.FunctionArn), "lambda_function"
	}
	return awssdk.ToString(r.ResourceType), awssdk.ToString(r.ResourceType)
}

// accessKeyPrincipal rebuilds the ARN of the principal an access-key finding
// names, because iam_user/iam_role assets are keyed by ARN (collectUsers,
// collectRoles) and the bare user name never joined. GuardDuty reports no IAM
// path, so a principal created under a path ("/ops/") still misses — the
// common path-less principal joins. Unknown account or principal kinds with no
// IAM asset (federated users, AWS services) keep the bare name.
func accessKeyPrincipal(d *gdtypes.AccessKeyDetails, accountID, region string) (id, typ string) {
	name := awssdk.ToString(d.UserName)
	if accountID == "" {
		return name, "iam_user"
	}
	prefix := "arn:" + partitionFor(region) + ":iam::" + accountID + ":"
	switch awssdk.ToString(d.UserType) {
	case "IAMUser":
		return prefix + "user/" + name, "iam_user"
	case "Root":
		return prefix + "root", "iam_user"
	case "AssumedRole":
		return prefix + "role/" + name, "iam_role"
	}
	return name, "iam_user"
}
