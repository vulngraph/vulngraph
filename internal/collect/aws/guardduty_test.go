package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

var gdNow = time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)

type fakeGuardDuty struct {
	detectors []string
	ids       []string
	findings  []gdtypes.Finding
}

func (f *fakeGuardDuty) ListDetectors(context.Context, *guardduty.ListDetectorsInput, ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
	return &guardduty.ListDetectorsOutput{DetectorIds: f.detectors}, nil
}

func (f *fakeGuardDuty) ListFindings(context.Context, *guardduty.ListFindingsInput, ...func(*guardduty.Options)) (*guardduty.ListFindingsOutput, error) {
	return &guardduty.ListFindingsOutput{FindingIds: f.ids}, nil
}

func (f *fakeGuardDuty) GetFindings(context.Context, *guardduty.GetFindingsInput, ...func(*guardduty.Options)) (*guardduty.GetFindingsOutput, error) {
	return &guardduty.GetFindingsOutput{Findings: f.findings}, nil
}

// pagingGuardDuty records the ListFindings request and pages forever.
type pagingGuardDuty struct {
	fakeGuardDuty
	last  *guardduty.ListFindingsInput
	pages int
}

func (p *pagingGuardDuty) ListFindings(_ context.Context, in *guardduty.ListFindingsInput, _ ...func(*guardduty.Options)) (*guardduty.ListFindingsOutput, error) {
	p.last = in
	p.pages++
	return &guardduty.ListFindingsOutput{FindingIds: []string{"f"}, NextToken: awssdk.String("more")}, nil
}

// Archived findings are not live threats: the listing must filter them out,
// bound the age, sort most-severe first, and stop at the page cap.
func TestListFindingIDs_ActiveOnlyAndCapped(t *testing.T) {
	p := &pagingGuardDuty{}
	ids, exhaustive, err := listFindingIDs(context.Background(), p, "det-1", gdNow)
	require.NoError(t, err)
	require.Equal(t, gdMaxPages, p.pages, "listing stops at the page cap")
	require.Len(t, ids, gdMaxPages)
	require.False(t, exhaustive, "a capped listing must not report itself exhaustive")

	crit := p.last.FindingCriteria.Criterion
	require.Equal(t, []string{"false"}, crit["service.archived"].Equals)
	require.Equal(t, gdNow.Add(-gdMaxAge).UnixMilli(), awssdk.ToInt64(crit["updatedAt"].GreaterThanOrEqual))
	require.Equal(t, "severity", awssdk.ToString(p.last.SortCriteria.AttributeName))
	require.Equal(t, gdtypes.OrderByDesc, p.last.SortCriteria.OrderBy)
}

func TestCollectGuardDutyFindings_MapsToPlatformFinding(t *testing.T) {
	client := &fakeGuardDuty{
		detectors: []string{"det-1"},
		ids:       []string{"f1"},
		findings: []gdtypes.Finding{{
			Id:          awssdk.String("f1"),
			Type:        awssdk.String("UnauthorizedAccess:EC2/SSHBruteForce"),
			Severity:    awssdk.Float64(8.0),
			Title:       awssdk.String("SSH brute force against i-123"),
			Description: awssdk.String("An EC2 instance is being brute-forced over SSH."),
			Resource:    &gdtypes.Resource{InstanceDetails: &gdtypes.InstanceDetails{InstanceId: awssdk.String("i-123")}},
		}},
	}

	out, _, err := collectGuardDutyFindings(context.Background(), client, "eu-west-1", gdNow)
	require.NoError(t, err)
	require.Len(t, out, 1)

	f := out[0]
	require.Equal(t, "aws_guardduty", f.Source)
	require.Equal(t, "threat", f.Type)
	require.Equal(t, finding.SeverityHigh, f.Severity)
	require.Equal(t, "UnauthorizedAccess:EC2/SSHBruteForce", f.CheckID)
	require.Equal(t, "i-123", f.ResourceID, "links to the ec2_instance asset")
	require.Equal(t, "ec2_instance", f.ResourceType)
	require.Equal(t, "eu-west-1", f.Region)
	require.NotEmpty(t, f.ID)

	// Deterministic: same GuardDuty id → same platform id (idempotent upsert).
	again, _, _ := collectGuardDutyFindings(context.Background(), client, "eu-west-1", gdNow)
	require.Equal(t, f.ID, again[0].ID)
}

func TestCollectGuardDutyFindings_RDSFindingUsesRealARN(t *testing.T) {
	// Realistic GuardDuty GetFindings response for an RDS anomalous-login
	// finding — Resource.ResourceType is the bare "RDSDBInstance" enum string,
	// with the actual identifier only reachable via RdsDbInstanceDetails.
	client := &fakeGuardDuty{
		detectors: []string{"det-1"},
		ids:       []string{"f1"},
		findings: []gdtypes.Finding{{
			Id:          awssdk.String("f1"),
			Type:        awssdk.String("CredentialAccess:RDS/AnomalousBehavior.SuccessfulLogin"),
			Severity:    awssdk.Float64(5.0),
			Title:       awssdk.String("Anomalous login to prod-orders"),
			Description: awssdk.String("A login was made against an RDS instance from an unusual location."),
			Resource: &gdtypes.Resource{
				ResourceType: awssdk.String("RDSDBInstance"),
				RdsDbInstanceDetails: &gdtypes.RdsDbInstanceDetails{
					DbInstanceIdentifier: awssdk.String("prod-orders"),
					DbInstanceArn:        awssdk.String("arn:aws:rds:eu-west-1:111111111111:db:prod-orders"),
					Engine:               awssdk.String("postgres"),
				},
			},
		}},
	}

	out, _, err := collectGuardDutyFindings(context.Background(), client, "eu-west-1", gdNow)
	require.NoError(t, err)
	require.Len(t, out, 1)

	f := out[0]
	require.Equal(t, "arn:aws:rds:eu-west-1:111111111111:db:prod-orders", f.ResourceID, "must be the real ARN, not the bare resource-type placeholder")
	require.NotEqual(t, "RDSDBInstance", f.ResourceID)
	require.Equal(t, "rds_instance", f.ResourceType)
}

func TestCollectGuardDutyFindings_CollapsesByResourceAndType(t *testing.T) {
	res := func(id string) *gdtypes.Resource {
		return &gdtypes.Resource{InstanceDetails: &gdtypes.InstanceDetails{InstanceId: awssdk.String(id)}}
	}
	gd := func(id, typ, host string, sev float64) gdtypes.Finding {
		return gdtypes.Finding{Id: awssdk.String(id), Type: awssdk.String(typ),
			Severity: awssdk.Float64(sev), Title: awssdk.String("Phishing domain from " + host), Resource: res(host)}
	}
	client := &fakeGuardDuty{
		detectors: []string{"det-1"},
		ids:       []string{"a", "b", "c", "d"},
		findings: []gdtypes.Finding{
			gd("a", "Trojan:EC2/PhishingDomainRequest!DNS", "i-1", 5.0),
			gd("b", "Trojan:EC2/PhishingDomainRequest!DNS", "i-1", 8.0), // same (resource,type) → collapse
			gd("c", "Trojan:EC2/PhishingDomainRequest!DNS", "i-1", 4.0), // "
			gd("d", "Trojan:EC2/PhishingDomainRequest!DNS", "i-2", 5.0), // different host → separate
		},
	}
	out, _, err := collectGuardDutyFindings(context.Background(), client, "eu-west-1", gdNow)
	require.NoError(t, err)
	require.Len(t, out, 2, "3 findings on i-1 collapse to 1; i-2 stays separate")

	byRes := map[string]finding.Finding{}
	for _, f := range out {
		byRes[f.ResourceID] = f
	}
	require.Equal(t, "3", byRes["i-1"].Metadata["occurrences"])
	require.Contains(t, byRes["i-1"].Title, "(×3)")
	require.Equal(t, finding.SeverityHigh, byRes["i-1"].Severity, "keeps the most-severe representative (8.0)")
	require.Empty(t, byRes["i-2"].Metadata["occurrences"], "single occurrence → count left unset")
	require.NotContains(t, byRes["i-2"].Title, "×")
}

func TestCollectGuardDutyFindings_NoDetectors(t *testing.T) {
	out, complete, err := collectGuardDutyFindings(context.Background(), &fakeGuardDuty{}, "us-east-1", gdNow)
	require.NoError(t, err)
	require.Empty(t, out)
	require.True(t, complete, "no detector means no active findings can exist in the region")
}

// erroringGuardDuty fails whichever call is named.
type erroringGuardDuty struct {
	fakeGuardDuty
	failList, failGet bool
	detectorsToken    *string
}

func (e *erroringGuardDuty) ListDetectors(context.Context, *guardduty.ListDetectorsInput, ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
	return &guardduty.ListDetectorsOutput{DetectorIds: e.detectors, NextToken: e.detectorsToken}, nil
}

func (e *erroringGuardDuty) ListFindings(ctx context.Context, in *guardduty.ListFindingsInput, opts ...func(*guardduty.Options)) (*guardduty.ListFindingsOutput, error) {
	if e.failList {
		return nil, errors.New("throttled")
	}
	return e.fakeGuardDuty.ListFindings(ctx, in, opts...)
}

func (e *erroringGuardDuty) GetFindings(ctx context.Context, in *guardduty.GetFindingsInput, opts ...func(*guardduty.Options)) (*guardduty.GetFindingsOutput, error) {
	if e.failGet {
		return nil, errors.New("access denied")
	}
	return e.fakeGuardDuty.GetFindings(ctx, in, opts...)
}

// The sync worker closes stored GuardDuty findings a complete listing did not
// return, so completeness must be claimed only for a listing that read every
// page and every batch — never for a capped, failed, or unread one.
func TestCollectGuardDutyFindings_Completeness(t *testing.T) {
	one := fakeGuardDuty{
		detectors: []string{"det-1"},
		ids:       []string{"f1"},
		findings: []gdtypes.Finding{{
			Id: awssdk.String("f1"), Type: awssdk.String("Recon:EC2/PortProbeUnprotectedPort"),
			Resource: &gdtypes.Resource{InstanceDetails: &gdtypes.InstanceDetails{InstanceId: awssdk.String("i-1")}},
		}},
	}

	t.Run("every page read: complete", func(t *testing.T) {
		out, complete, err := collectGuardDutyFindings(context.Background(), &one, "eu-west-1", gdNow)
		require.NoError(t, err)
		require.Len(t, out, 1)
		require.True(t, complete)
	})
	t.Run("page cap hit: not complete", func(t *testing.T) {
		p := &pagingGuardDuty{fakeGuardDuty: one}
		out, complete, err := collectGuardDutyFindings(context.Background(), p, "eu-west-1", gdNow)
		require.NoError(t, err)
		require.NotEmpty(t, out, "a capped listing still ingests what it read")
		require.False(t, complete)
	})
	t.Run("ListFindings error: not complete", func(t *testing.T) {
		_, complete, err := collectGuardDutyFindings(context.Background(), &erroringGuardDuty{fakeGuardDuty: one, failList: true}, "eu-west-1", gdNow)
		require.Error(t, err)
		require.False(t, complete)
	})
	t.Run("GetFindings error: not complete", func(t *testing.T) {
		_, complete, err := collectGuardDutyFindings(context.Background(), &erroringGuardDuty{fakeGuardDuty: one, failGet: true}, "eu-west-1", gdNow)
		require.Error(t, err)
		require.False(t, complete)
	})
	t.Run("unread detector page: not complete", func(t *testing.T) {
		e := &erroringGuardDuty{fakeGuardDuty: one, detectorsToken: awssdk.String("more")}
		_, complete, err := collectGuardDutyFindings(context.Background(), e, "eu-west-1", gdNow)
		require.NoError(t, err)
		require.False(t, complete)
	})
}

func TestGuardDutySeverity(t *testing.T) {
	// 9.0-10.0 is GuardDuty's Critical band (Extended Threat Detection attack
	// sequences); folding it into High hid the most severe detections.
	require.Equal(t, finding.SeverityCritical, guardDutySeverity(awssdk.Float64(9.0)))
	require.Equal(t, finding.SeverityCritical, guardDutySeverity(awssdk.Float64(10.0)))
	require.Equal(t, finding.SeverityHigh, guardDutySeverity(awssdk.Float64(7.0)))
	require.Equal(t, finding.SeverityHigh, guardDutySeverity(awssdk.Float64(8.9)))
	require.Equal(t, finding.SeverityMedium, guardDutySeverity(awssdk.Float64(5.0)))
	require.Equal(t, finding.SeverityLow, guardDutySeverity(awssdk.Float64(2.0)))
	require.Equal(t, finding.SeverityLow, guardDutySeverity(nil))
}

func TestGuardDutyResource(t *testing.T) {
	id, typ := guardDutyResource(&gdtypes.Resource{InstanceDetails: &gdtypes.InstanceDetails{InstanceId: awssdk.String("i-9")}}, "", "")
	require.Equal(t, "i-9", id)
	require.Equal(t, "ec2_instance", typ)

	// Access-key findings name the principal; the iam_user/iam_role assets are
	// keyed by ARN, so the ARN is rebuilt in the region's partition.
	for _, tt := range []struct {
		name, userType, userName, account, region, wantID, wantType string
	}{
		{"iam user", "IAMUser", "deployer", "111111111111", "eu-west-1", "arn:aws:iam::111111111111:user/deployer", "iam_user"},
		{"govcloud user", "IAMUser", "deployer", "111111111111", "us-gov-west-1", "arn:aws-us-gov:iam::111111111111:user/deployer", "iam_user"},
		{"root", "Root", "Root", "111111111111", "eu-west-1", "arn:aws:iam::111111111111:root", "iam_user"},
		{"assumed role", "AssumedRole", "deploy-role", "111111111111", "cn-north-1", "arn:aws-cn:iam::111111111111:role/deploy-role", "iam_role"},
		{"unknown account keeps the name", "IAMUser", "deployer", "", "eu-west-1", "deployer", "iam_user"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			id, typ := guardDutyResource(&gdtypes.Resource{AccessKeyDetails: &gdtypes.AccessKeyDetails{
				UserName: awssdk.String(tt.userName), UserType: awssdk.String(tt.userType),
			}}, tt.account, tt.region)
			require.Equal(t, tt.wantID, id)
			require.Equal(t, tt.wantType, typ)
		})
	}

	id, typ = guardDutyResource(&gdtypes.Resource{S3BucketDetails: []gdtypes.S3BucketDetail{{Name: awssdk.String("logs-bucket")}}}, "", "")
	require.Equal(t, "logs-bucket", id)
	require.Equal(t, "s3_bucket", typ)

	// Bug (fixed here): RDS/EKS/ECS findings were falling through to the
	// bare resource-type name ("RDSDBInstance", "EKSCluster", "ECSCluster") as
	// the id, so every finding of that kind was indistinguishable and could
	// never match a graph.assets row. Extract the real ARN from the type-
	// specific detail struct instead, in the same scheme our own collectors
	// use (rds.go/eks.go/ecs.go) so the asset join resolves.
	id, typ = guardDutyResource(&gdtypes.Resource{
		ResourceType:         awssdk.String("RDSDBInstance"),
		RdsDbInstanceDetails: &gdtypes.RdsDbInstanceDetails{DbInstanceArn: awssdk.String("arn:aws:rds:eu-west-1:111111111111:db:prod-orders")},
	}, "111111111111", "eu-west-1")
	require.Equal(t, "arn:aws:rds:eu-west-1:111111111111:db:prod-orders", id)
	require.Equal(t, "rds_instance", typ)

	// RDS Protection findings (e.g. login-attempt/probe detections) frequently
	// leave DbInstanceArn empty and only populate DbInstanceIdentifier. Without
	// this, every such finding fell through to the bare "RDSDBInstance"
	// placeholder — unlinkable to any asset.
	id, typ = guardDutyResource(&gdtypes.Resource{
		ResourceType:         awssdk.String("RDSDBInstance"),
		RdsDbInstanceDetails: &gdtypes.RdsDbInstanceDetails{DbInstanceIdentifier: awssdk.String("Prod-Orders")},
	}, "111111111111", "eu-west-1")
	require.Equal(t, "arn:aws:rds:eu-west-1:111111111111:db:prod-orders", id, "rebuilt ARN lowercases the identifier to match the real AWS convention")
	require.Equal(t, "rds_instance", typ)

	id, _ = guardDutyResource(&gdtypes.Resource{
		RdsDbInstanceDetails: &gdtypes.RdsDbInstanceDetails{DbInstanceIdentifier: awssdk.String("orders")},
	}, "111111111111", "us-gov-east-1")
	require.Equal(t, "arn:aws-us-gov:rds:us-gov-east-1:111111111111:db:orders", id, "rebuilt ARN carries the region's partition")

	id, typ = guardDutyResource(&gdtypes.Resource{
		ResourceType:      awssdk.String("EKSCluster"),
		EksClusterDetails: &gdtypes.EksClusterDetails{Arn: awssdk.String("arn:aws:eks:eu-west-1:111111111111:cluster/prod")},
	}, "", "")
	require.Equal(t, "arn:aws:eks:eu-west-1:111111111111:cluster/prod", id)
	require.Equal(t, "eks_cluster", typ)

	id, typ = guardDutyResource(&gdtypes.Resource{
		ResourceType:      awssdk.String("ECSCluster"),
		EcsClusterDetails: &gdtypes.EcsClusterDetails{Arn: awssdk.String("arn:aws:ecs:eu-west-1:111111111111:cluster/prod")},
	}, "", "")
	require.Equal(t, "arn:aws:ecs:eu-west-1:111111111111:cluster/prod", id)
	require.Equal(t, "ecs_cluster", typ)

	// Same fallthrough bug also affected Lambda — fixed alongside RDS/EKS/ECS.
	id, typ = guardDutyResource(&gdtypes.Resource{
		ResourceType:  awssdk.String("Lambda"),
		LambdaDetails: &gdtypes.LambdaDetails{FunctionArn: awssdk.String("arn:aws:lambda:eu-west-1:111111111111:function:process-orders")},
	}, "", "")
	require.Equal(t, "arn:aws:lambda:eu-west-1:111111111111:function:process-orders", id)
	require.Equal(t, "lambda_function", typ)

	// ECS-sourced (or otherwise parent-less) container finding: no reliable join
	// to graph.assets exists (task-scoped GuardDuty id vs our service-scoped
	// container asset), so this stays an honest non-join — the container id at
	// least distinguishes findings instead of every one collapsing onto the
	// literal string "Container".
	id, typ = guardDutyResource(&gdtypes.Resource{
		ResourceType:     awssdk.String("Container"),
		ContainerDetails: &gdtypes.Container{Id: awssdk.String("c-abc123")},
	}, "", "")
	require.Equal(t, "c-abc123", id)
	require.Equal(t, "container", typ)

	// EKS-sourced container finding: KubernetesWorkloadDetails carries the pod's
	// namespace/name, so this DOES join — the id matches kubernetes.go's
	// podAsset container ID scheme exactly.
	id, typ = guardDutyResource(&gdtypes.Resource{
		ResourceType:      awssdk.String("Container"),
		ContainerDetails:  &gdtypes.Container{Name: awssdk.String("app")},
		EksClusterDetails: &gdtypes.EksClusterDetails{Arn: awssdk.String("arn:aws:eks:eu-west-1:1:cluster/prod"), Name: awssdk.String("prod")},
		KubernetesDetails: &gdtypes.KubernetesDetails{
			KubernetesWorkloadDetails: &gdtypes.KubernetesWorkloadDetails{
				Type: awssdk.String("Pod"), Namespace: awssdk.String("billing"), Name: awssdk.String("api-7f9c4"),
			},
		},
	}, "", "")
	require.Equal(t, "prod/pod/billing/api-7f9c4/container/app", id, "matches kubernetes.go podAsset's container ID scheme")
	require.Equal(t, "container", typ)

	// EKS cluster-level finding (no ContainerDetails) still resolves to the
	// eks_cluster asset — the container-first ordering must not break this.
	id, typ = guardDutyResource(&gdtypes.Resource{
		ResourceType:      awssdk.String("EKSCluster"),
		EksClusterDetails: &gdtypes.EksClusterDetails{Arn: awssdk.String("arn:aws:eks:eu-west-1:1:cluster/prod"), Name: awssdk.String("prod")},
	}, "", "")
	require.Equal(t, "arn:aws:eks:eu-west-1:1:cluster/prod", id)
	require.Equal(t, "eks_cluster", typ)

	// Genuinely unmodeled shape (no detail struct at all) still falls back to
	// the raw resource type — the placeholder of last resort, not a silent bug.
	id, typ = guardDutyResource(&gdtypes.Resource{ResourceType: awssdk.String("CloudFormationStack")}, "", "")
	require.Equal(t, "CloudFormationStack", id)
	require.Equal(t, "CloudFormationStack", typ)

	id, typ = guardDutyResource(nil, "", "")
	require.Empty(t, id)
	require.Empty(t, typ)
}

// gdClusterFinding is a mapped GuardDuty finding naming an EKS cluster.
func gdClusterFinding(arn, region, gdType string, sev finding.Severity) finding.Finding {
	return finding.Finding{
		Source: "aws_guardduty", Type: "threat", Severity: sev,
		ResourceType: "eks_cluster", ResourceID: arn, Region: region, CheckID: gdType,
	}
}

func TestUninventoriedEKSClusterFindings(t *testing.T) {
	const (
		euARN = "arn:aws:eks:eu-west-1:111:cluster/example-eu-cluster"
		usARN = "arn:aws:eks:us-east-1:111:cluster/example-us-cluster"
	)
	now := time.Now()
	listed := map[string]bool{"eu-west-1": true, "us-east-1": true}

	t.Run("one finding per uninventoried cluster, severity lifted", func(t *testing.T) {
		got := uninventoriedEKSClusterFindings([]finding.Finding{
			gdClusterFinding(euARN, "eu-west-1", "Policy:Kubernetes/AdminAccessToDefaultServiceAccount", finding.SeverityLow),
			gdClusterFinding(euARN, "eu-west-1", "Impact:Kubernetes/SuccessfulAnonymousAccess", finding.SeverityHigh),
			gdClusterFinding(euARN, "eu-west-1", "Impact:Kubernetes/SuccessfulAnonymousAccess", finding.SeverityMedium),
		}, nil, listed, now)

		require.Len(t, got, 1, "many GuardDuty findings on one cluster are one coverage gap")
		f := got[0]
		require.Equal(t, "aws-eks-cluster-not-inventoried", f.CheckID)
		require.Equal(t, euARN, f.ResourceID)
		require.Equal(t, "eks_cluster", f.ResourceType)
		require.Equal(t, "example-eu-cluster", f.ResourceName)
		require.Equal(t, "eu-west-1", f.Region)
		require.Equal(t, finding.SeverityHigh, f.Severity, "graded by the worst detection GuardDuty reported")
		require.Equal(t, "3", f.Metadata["guardduty_findings"])
		require.Equal(t, "Impact:Kubernetes/SuccessfulAnonymousAccess,Policy:Kubernetes/AdminAccessToDefaultServiceAccount",
			f.Metadata["guardduty_types"])
	})

	t.Run("low-severity detections still surface at medium", func(t *testing.T) {
		got := uninventoriedEKSClusterFindings(
			[]finding.Finding{gdClusterFinding(euARN, "eu-west-1", "Recon:Kubernetes/MaliciousIPCaller", finding.SeverityLow)},
			nil, listed, now)
		require.Len(t, got, 1)
		require.Equal(t, finding.SeverityMedium, got[0].Severity,
			"an unexamined cluster is a coverage gap regardless of how the detections are graded")
	})

	t.Run("stays silent when the cluster IS inventoried", func(t *testing.T) {
		got := uninventoriedEKSClusterFindings(
			[]finding.Finding{gdClusterFinding(euARN, "eu-west-1", "Recon:Kubernetes/MaliciousIPCaller", finding.SeverityHigh)},
			[]asset.Asset{{ID: euARN, Type: "eks_cluster"}}, listed, now)
		require.Empty(t, got)
	})

	t.Run("stays silent when the region's EKS listing failed", func(t *testing.T) {
		// Absence is only evidence where we looked. A throttled or AccessDenied
		// ListClusters must never be reported as a missing cluster.
		got := uninventoriedEKSClusterFindings(
			[]finding.Finding{gdClusterFinding(euARN, "eu-west-1", "Recon:Kubernetes/MaliciousIPCaller", finding.SeverityHigh)},
			nil, map[string]bool{"us-east-1": true}, now)
		require.Empty(t, got)
	})

	t.Run("only GuardDuty eks_cluster findings are considered", func(t *testing.T) {
		got := uninventoriedEKSClusterFindings([]finding.Finding{
			{Source: "cspm", ResourceType: "eks_cluster", ResourceID: euARN, Region: "eu-west-1"},
			{Source: "aws_guardduty", ResourceType: "ec2_instance", ResourceID: "i-1", Region: "eu-west-1"},
			{Source: "aws_guardduty", ResourceType: "eks_cluster", ResourceID: "", Region: "eu-west-1"},
		}, nil, listed, now)
		require.Empty(t, got)
	})

	t.Run("distinct clusters produce distinct, stable findings", func(t *testing.T) {
		in := []finding.Finding{
			gdClusterFinding(euARN, "eu-west-1", "Recon:Kubernetes/MaliciousIPCaller", finding.SeverityMedium),
			gdClusterFinding(usARN, "us-east-1", "Recon:Kubernetes/MaliciousIPCaller", finding.SeverityMedium),
		}
		got := uninventoriedEKSClusterFindings(in, nil, listed, now)
		require.Len(t, got, 2)
		require.NotEqual(t, got[0].ID, got[1].ID)
		again := uninventoriedEKSClusterFindings(in, nil, listed, now.Add(time.Hour))
		require.Equal(t, got[0].ID, again[0].ID, "re-sweeps upsert the same row")
	})
}
