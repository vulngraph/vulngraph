package checks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

var fixedTime = time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

func TestCheck_AppliesMatchesProviderAndType(t *testing.T) {
	c := Check{Provider: asset.ProviderAWS, AssetType: "ec2_instance"}
	require.True(t, c.applies(asset.Asset{Provider: asset.ProviderAWS, Type: "ec2_instance"}))
	require.False(t, c.applies(asset.Asset{Provider: asset.ProviderAWS, Type: "security_group"}))
	require.False(t, c.applies(asset.Asset{Provider: asset.ProviderGCP, Type: "ec2_instance"}))
}

func TestCheck_AppliesAnyTypeWhenBlank(t *testing.T) {
	c := Check{Provider: asset.ProviderAWS, AssetType: ""}
	require.True(t, c.applies(asset.Asset{Provider: asset.ProviderAWS, Type: "anything"}))
	require.False(t, c.applies(asset.Asset{Provider: asset.ProviderGCP, Type: "anything"}))
}

func TestRun_EmitsFindingPerViolation(t *testing.T) {
	r := Default()
	assets := []asset.Asset{
		{ID: "i-1", Type: "ec2_instance", Provider: asset.ProviderAWS, PublicIP: "1.2.3.4", Region: "eu-west-1", Metadata: map[string]string{"http_tokens": "required", "iam_instance_profile": "test-profile", "state": "running"}},
		{ID: "i-2", Type: "ec2_instance", Provider: asset.ProviderAWS, Metadata: map[string]string{"http_tokens": "required", "iam_instance_profile": "test-profile", "state": "running"}}, // private, no finding
		{ID: "g-1", Type: "gce_instance", Provider: asset.ProviderGCP, PublicIP: "34.1.1.1", Metadata: map[string]string{"oslogin": "true", "project_ssh_keys_blocked": "true", "serial_port_enabled": "false", "status": "RUNNING"}},
		{ID: "org/repo", Type: "github_repo", Provider: asset.ProviderGitHub, Metadata: map[string]string{"visibility": "public", "branch_protection": "enabled"}},
		{ID: "org/priv", Type: "github_repo", Provider: asset.ProviderGitHub, Metadata: map[string]string{"visibility": "private", "branch_protection": "enabled"}},
	}

	findings := r.Run(assets, fixedTime)
	require.Len(t, findings, 4)

	byResource := map[string]finding.Finding{}
	for _, f := range findings {
		if f.CheckID == "aws-ec2-internet-facing-with-instance-profile" {
			continue
		}
		byResource[f.ResourceID] = f
		require.Equal(t, "cspm", f.Source)
		require.Equal(t, fixedTime, f.DetectedAt)
		require.NotEmpty(t, f.ID)
		require.NotEmpty(t, f.CheckID)
	}
	require.Equal(t, "aws-ec2-public-ip", byResource["i-1"].CheckID)
	require.Equal(t, finding.SeverityMedium, byResource["i-1"].Severity)
	require.Equal(t, "gcp-gce-public-ip", byResource["g-1"].CheckID)
	require.Equal(t, "github-public-repo", byResource["org/repo"].CheckID)
	require.Equal(t, finding.SeverityLow, byResource["org/repo"].Severity)
}

func TestRun_PublicBucketChecks(t *testing.T) {
	r := Default()
	assets := []asset.Asset{
		{ID: "open-s3", Type: "s3_bucket", Provider: asset.ProviderAWS, Metadata: map[string]string{"public": "true", "public_access": asset.PublicAccessConfirmed, "versioning": "enabled", "logging": "enabled", "encryption": "aws:kms", "mfa_delete": "Enabled"}},
		// Possible-tier (unblocked but no public policy/ACL) must NOT fire the exposure check.
		{ID: "possible-s3", Type: "s3_bucket", Provider: asset.ProviderAWS, Metadata: map[string]string{"public": "true", "public_access": asset.PublicAccessPossible, "versioning": "enabled", "logging": "enabled", "encryption": "aws:kms", "mfa_delete": "Enabled"}},
		{ID: "safe-s3", Type: "s3_bucket", Provider: asset.ProviderAWS, Metadata: map[string]string{"public": "false", "versioning": "enabled", "logging": "enabled", "encryption": "aws:kms", "mfa_delete": "Enabled"}},
		{ID: "open-gcs", Type: "gcs_bucket", Provider: asset.ProviderGCP, Metadata: map[string]string{"public": "true", "versioning": "true", "logging_bucket": "test-logs", "uniform_access": "true"}},
		{ID: "safe-gcs", Type: "gcs_bucket", Provider: asset.ProviderGCP, Metadata: map[string]string{"public": "false", "versioning": "true", "logging_bucket": "test-logs", "uniform_access": "true"}},
	}

	byResource := map[string]finding.Finding{}
	for _, f := range r.Run(assets, fixedTime) {
		byResource[f.ResourceID] = f
	}
	// Confirmed-public S3 + possible-tier S3 + public GCS all surface; the
	// possible-tier bucket is graded down to low, the confirmed one stays high.
	require.Len(t, byResource, 3, "confirmed + possible S3 and public GCS all violate")
	require.Equal(t, "aws-s3-public-bucket", byResource["open-s3"].CheckID)
	require.Equal(t, finding.SeverityHigh, byResource["open-s3"].Severity)
	require.Equal(t, "aws-s3-public-bucket", byResource["possible-s3"].CheckID)
	require.Equal(t, finding.SeverityLow, byResource["possible-s3"].Severity, "unblocked-but-not-public bucket is low severity")
	require.Equal(t, "gcp-gcs-public-bucket", byResource["open-gcs"].CheckID)
	require.NotContains(t, byResource, "safe-s3")
	require.NotContains(t, byResource, "safe-gcs")
}

func TestRun_DeterministicIDStableAcrossRuns(t *testing.T) {
	r := Default()
	a := []asset.Asset{{ID: "i-1", Type: "ec2_instance", Provider: asset.ProviderAWS, PublicIP: "1.2.3.4", Metadata: map[string]string{"http_tokens": "required", "iam_instance_profile": "test-profile", "state": "running"}}}

	first := r.Run(a, fixedTime)
	second := r.Run(a, fixedTime.Add(time.Hour))
	require.NotEmpty(t, first)
	require.Equal(t, len(first), len(second), "same assets must produce the same number of findings across runs")
	// Verify the public-IP finding ID is stable across runs (deterministic upsert).
	findByCheck := func(findings []finding.Finding, checkID string) (finding.Finding, bool) {
		for _, f := range findings {
			if f.CheckID == checkID {
				return f, true
			}
		}
		return finding.Finding{}, false
	}
	f1, ok1 := findByCheck(first, "aws-ec2-public-ip")
	f2, ok2 := findByCheck(second, "aws-ec2-public-ip")
	require.True(t, ok1 && ok2)
	require.Equal(t, f1.ID, f2.ID, "same check+resource must yield the same ID for idempotent upsert")
}

func TestRun_EC2PublicIPLifecycleGuard(t *testing.T) {
	r := NewRegistry()
	r.Register(awsEC2PublicIP)
	r.Register(gcpGCEPublicIP)
	findings := r.Run([]asset.Asset{
		{ID: "i-run", Type: "ec2_instance", Provider: asset.ProviderAWS, PublicIP: "1.2.3.4", Metadata: map[string]string{"state": "running"}},
		{ID: "i-stop", Type: "ec2_instance", Provider: asset.ProviderAWS, PublicIP: "1.2.3.5", Metadata: map[string]string{"state": "stopped"}},
		{ID: "g-run", Type: "gce_instance", Provider: asset.ProviderGCP, PublicIP: "34.1.1.1", Metadata: map[string]string{"status": "RUNNING"}},
		{ID: "g-term", Type: "gce_instance", Provider: asset.ProviderGCP, PublicIP: "34.1.1.2", Metadata: map[string]string{"status": "TERMINATED"}},
	}, fixedTime)

	fired := map[string]finding.Finding{}
	for _, f := range findings {
		fired[f.ResourceID] = f
	}
	require.Equal(t, finding.SeverityMedium, fired["i-run"].Severity, "running EC2 with public IP fires")
	// FSBP EC2.9: a stopped instance only keeps a public IPv4 through an
	// Elastic IP, and is exposed again when it starts — reported, graded down.
	require.Equal(t, finding.SeverityLow, fired["i-stop"].Severity, "stopped EC2 keeping a public IP fires at Low")
	require.Equal(t, "Stopped EC2 instance keeps a public IP", fired["i-stop"].Title)
	require.Contains(t, fired, "g-run", "running GCE with public IP fires")
	require.NotContains(t, fired, "g-term", "terminated GCE must not fire")
}

func TestRun_EIPUnassociatedIgnoresENIAttached(t *testing.T) {
	r := NewRegistry()
	r.Register(awsEIPUnassociated)
	findings := r.Run([]asset.Asset{
		// Truly unassociated (the collector writes all three keys, empty) → fires.
		{ID: "eip-free", Type: "elastic_ip", Provider: asset.ProviderAWS, Metadata: eipMeta("", "", "")},
		// Attached only to a network interface (no instance) → must NOT fire.
		{ID: "eip-eni", Type: "elastic_ip", Provider: asset.ProviderAWS, Metadata: eipMeta("eipassoc-2", "", "eni-abc")},
		// Attached to an instance → must NOT fire.
		{ID: "eip-inst", Type: "elastic_ip", Provider: asset.ProviderAWS, Metadata: eipMeta("eipassoc-1", "i-123", "eni-def")},
		// Nothing observed (no keys at all) → must NOT fire.
		{ID: "eip-unread", Type: "elastic_ip", Provider: asset.ProviderAWS, Metadata: map[string]string{}},
	}, fixedTime)

	fired := map[string]bool{}
	for _, f := range findings {
		fired[f.ResourceID] = true
	}
	require.True(t, fired["eip-free"], "a truly unassociated EIP still fires")
	require.False(t, fired["eip-eni"], "an ENI-attached EIP must not fire")
	require.False(t, fired["eip-inst"], "an instance-attached EIP must not fire")
	require.False(t, fired["eip-unread"], "an EIP whose association was never read must not fire")
}

// eipMeta is the metadata the elastic IP collector writes: all three keys,
// empty when the address has no such association.
func eipMeta(association, instance, eni string) map[string]string {
	return map[string]string{"association_id": association, "instance_id": instance, "network_interface_id": eni}
}

func TestK8sPodSecurity_PSALabelAndSystemNamespaceGate(t *testing.T) {
	r := NewRegistry()
	r.Register(k8sPrivilegedContainer)
	priv := func(id, ns, psa string) asset.Asset {
		m := map[string]string{"privileged": "true", "namespace": ns, "phase": "Running"}
		if psa != "" {
			m["ns_psa_enforce"] = psa
		}
		return asset.Asset{ID: id, Type: "k8s_pod", Provider: asset.ProviderKubernetes, Metadata: m}
	}
	findings := r.Run([]asset.Asset{
		priv("app", "payments", ""),                  // ordinary namespace → fires
		priv("cni", "kube-system", ""),               // static system namespace → exempt
		priv("infra", "observability", "privileged"), // PSA-privileged (unlisted name) → exempt
		priv("web", "team-a", "restricted"),          // PSA restricted → still fires
	}, fixedTime)

	fired := map[string]bool{}
	for _, f := range findings {
		fired[f.ResourceID] = true
	}
	require.True(t, fired["app"], "privileged pod in an ordinary namespace fires")
	require.False(t, fired["cni"], "static system namespace is exempt")
	require.False(t, fired["infra"], "a namespace enforcing the privileged PSA is exempt regardless of name")
	require.True(t, fired["web"], "a restricted-PSA namespace still fires")
}

func TestRun_DataExfilAndGKEChecks(t *testing.T) {
	r := NewRegistry()
	r.Register(awsRDSSnapshotPublic)
	r.Register(azureDiskInternetExportable)
	r.Register(gkePublicEndpoint)
	r.Register(gkeLegacyABAC)
	findings := r.Run([]asset.Asset{
		{ID: "snap-pub", Type: "rds_snapshot", Provider: asset.ProviderAWS, Metadata: map[string]string{"public": "true"}},
		{ID: "snap-priv", Type: "rds_snapshot", Provider: asset.ProviderAWS, Metadata: map[string]string{"public": "false"}},
		{ID: "disk-open", Type: "azure_disk", Provider: asset.ProviderAzure, Metadata: map[string]string{"internet_exportable": "true"}},
		{ID: "disk-safe", Type: "azure_disk", Provider: asset.ProviderAzure, Metadata: map[string]string{"internet_exportable": "false"}},
		{ID: "gke-pub", Type: "gke_cluster", Provider: asset.ProviderGCP, Metadata: map[string]string{"public_endpoint": "true", "authorized_networks": "false", "legacy_abac": "true"}},
		{ID: "gke-safe", Type: "gke_cluster", Provider: asset.ProviderGCP, Metadata: map[string]string{"public_endpoint": "false", "authorized_networks": "true", "legacy_abac": "false"}},
	}, fixedTime)

	got := map[string]bool{}
	for _, f := range findings {
		got[f.ResourceID+"/"+f.CheckID] = true
	}
	require.True(t, got["snap-pub/aws-rds-snapshot-public"])
	require.False(t, got["snap-priv/aws-rds-snapshot-public"])
	require.True(t, got["disk-open/azure-disk-internet-exportable"])
	require.False(t, got["disk-safe/azure-disk-internet-exportable"])
	require.True(t, got["gke-pub/gcp-gke-public-endpoint"])
	require.True(t, got["gke-pub/gcp-gke-legacy-abac"])
	require.False(t, got["gke-safe/gcp-gke-public-endpoint"])
}

func TestRun_NoAssets(t *testing.T) {
	require.Empty(t, Default().Run(nil, fixedTime))
}

// rootPod builds a k8s_pod asset that violates k8s-container-runs-as-root,
// with optional owner-workload metadata from the collector.
func rootPod(name string, owner map[string]string) asset.Asset {
	m := map[string]string{"namespace": "billing", "phase": "Running", "run_as_root": "true"}
	for k, v := range owner {
		m[k] = v
	}
	return asset.Asset{
		ID: "prod/pod/billing/" + name, Name: name, Type: "k8s_pod",
		Provider: asset.ProviderKubernetes, Region: "prod", Metadata: m,
	}
}

func TestRun_AggregatesPodFindingsByWorkload(t *testing.T) {
	deployment := map[string]string{"owner_kind": "Deployment", "owner_name": "api"}
	tests := []struct {
		name         string
		assets       []asset.Asset
		wantResource string // aggregated (or per-pod) resource ID
		wantType     string
		wantOccurs   string // "" = no occurrences annotation
		wantTitleHas string
	}{
		{
			name: "three deployment replicas collapse to one finding",
			assets: []asset.Asset{
				rootPod("api-7f9c4-aaaaa", deployment),
				rootPod("api-7f9c4-bbbbb", deployment),
				rootPod("api-7f9c4-ccccc", deployment),
			},
			wantResource: "prod/deployment/billing/api",
			wantType:     "k8s_deployment",
			wantOccurs:   "3",
			wantTitleHas: "(×3 pods)",
		},
		{
			// StatefulSet is collected as a k8s_statefulset asset (kubernetes.go),
			// so the aggregated finding's ResourceID resolves to a real asset.
			name: "statefulset pod aggregates to the statefulset asset",
			assets: []asset.Asset{
				rootPod("db-0", map[string]string{"owner_kind": "StatefulSet", "owner_name": "db"}),
			},
			wantResource: "prod/statefulset/billing/db",
			wantType:     "k8s_statefulset",
		},
		{
			name: "daemonset pod aggregates to the daemonset asset",
			assets: []asset.Asset{
				rootPod("node-agent-abcde", map[string]string{"owner_kind": "DaemonSet", "owner_name": "node-agent"}),
			},
			wantResource: "prod/daemonset/billing/node-agent",
			wantType:     "k8s_daemonset",
		},
		{
			name: "job pod aggregates to the job asset",
			assets: []asset.Asset{
				rootPod("backup-123-xyz", map[string]string{"owner_kind": "Job", "owner_name": "backup-123"}),
			},
			wantResource: "prod/job/billing/backup-123",
			wantType:     "k8s_job",
		},
		{
			// Bare-ReplicaSet owners are NOT aggregated: no k8s_replicaset asset is
			// collected, so an aggregated finding would be an unresolvable zombie
			// (the sync lifecycle reconcile only sees collected asset IDs).
			name:         "bare replicaset pod stays per-pod (no workload asset to resolve against)",
			assets:       []asset.Asset{rootPod("standalone-abc", map[string]string{"owner_kind": "ReplicaSet", "owner_name": "standalone"})},
			wantResource: "prod/pod/billing/standalone-abc",
			wantType:     "k8s_pod",
		},
		{
			name:         "bare pod without owner stays per-pod",
			assets:       []asset.Asset{rootPod("bare", nil)},
			wantResource: "prod/pod/billing/bare",
			wantType:     "k8s_pod",
		},
	}
	r := Default()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []finding.Finding
			for _, f := range r.Run(tt.assets, fixedTime) {
				if f.CheckID == "k8s-container-runs-as-root" {
					got = append(got, f)
				}
			}
			require.Len(t, got, 1)
			f := got[0]
			require.Equal(t, tt.wantResource, f.ResourceID)
			require.Equal(t, tt.wantType, f.ResourceType)
			require.Equal(t, tt.wantOccurs, f.Metadata["occurrences"])
			if tt.wantTitleHas != "" {
				require.Contains(t, f.Title, tt.wantTitleHas)
			} else {
				require.NotContains(t, f.Title, "×")
			}
		})
	}
}

// When replicas grade differently, the rolled-up finding carries the most
// severe replica's severity AND its evidence, so the host paths shown justify
// the grade — whichever replica the sweep happened to see first.
func TestRun_WorkloadAggregateTakesMostSevereReplicaEvidence(t *testing.T) {
	pod := func(name, paths string) asset.Asset {
		return asset.Asset{
			ID: "prod/pod/billing/" + name, Name: name, Type: "k8s_pod", Provider: asset.ProviderKubernetes, Region: "prod",
			Metadata: map[string]string{
				"namespace": "billing", "phase": "Running", "host_path_volumes": paths,
				"owner_kind": "Deployment", "owner_name": "api",
			},
		}
	}
	for _, order := range [][]asset.Asset{
		{pod("api-a", "/data/cache"), pod("api-b", "/var/lib/kubelet")},
		{pod("api-b", "/var/lib/kubelet"), pod("api-a", "/data/cache")},
	} {
		var got []finding.Finding
		for _, f := range Default().Run(order, fixedTime) {
			if f.CheckID == "k8s-pod-host-path-volume" {
				got = append(got, f)
			}
		}
		require.Len(t, got, 1)
		f := got[0]
		require.Equal(t, finding.SeverityHigh, f.Severity)
		require.Equal(t, "/var/lib/kubelet", f.Metadata["host_paths"], "evidence must justify the grade")
		require.Equal(t, "prod/deployment/billing/api", f.ResourceID)
		require.Equal(t, "k8s_deployment", f.ResourceType)
		require.Equal(t, "api", f.ResourceName)
		require.Equal(t, "2", f.Metadata["occurrences"])
	}
}

func TestRun_WorkloadAggregateIDStableAcrossSweeps(t *testing.T) {
	r := Default()
	owner := map[string]string{"owner_kind": "Deployment", "owner_name": "api"}
	// Different replica names across sweeps (pods churn) must upsert the same row.
	first := r.Run([]asset.Asset{rootPod("api-7f9c4-aaaaa", owner), rootPod("api-7f9c4-bbbbb", owner)}, fixedTime)
	second := r.Run([]asset.Asset{rootPod("api-5d2e8-zzzzz", owner)}, fixedTime.Add(time.Hour))
	find := func(fs []finding.Finding) finding.Finding {
		for _, f := range fs {
			if f.CheckID == "k8s-container-runs-as-root" {
				return f
			}
		}
		t.Fatal("finding not produced")
		return finding.Finding{}
	}
	require.Equal(t, find(first).ID, find(second).ID, "same workload+check must yield the same ID for idempotent upsert")
}

func TestRun_WorkloadsAggregateSeparately(t *testing.T) {
	r := Default()
	assets := []asset.Asset{
		rootPod("api-7f9c4-aaaaa", map[string]string{"owner_kind": "Deployment", "owner_name": "api"}),
		rootPod("web-6b1d2-aaaaa", map[string]string{"owner_kind": "Deployment", "owner_name": "web"}),
	}
	byResource := map[string]bool{}
	for _, f := range r.Run(assets, fixedTime) {
		if f.CheckID == "k8s-container-runs-as-root" {
			byResource[f.ResourceID] = true
		}
	}
	require.Len(t, byResource, 2, "different owners never collapse together")
	require.Contains(t, byResource, "prod/deployment/billing/api")
	require.Contains(t, byResource, "prod/deployment/billing/web")
}

func TestDefault_RegistersChecks(t *testing.T) {
	// Pinned count for the registry's built-in catalogue. Update deliberately
	// when adding, removing, or collapsing checks — this test exists so a
	// registration change is never silent.
	require.Equal(t, 853, Default().Len())
}

func TestRun_CheapAWSChecks(t *testing.T) {
	r := Default()
	assets := []asset.Asset{
		// Root without MFA fires; root WITH MFA does not.
		{ID: "arn:aws:iam::111:root", Type: "iam_user", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"root": "true", "console_access": "true", "mfa_enabled": "false", "active_key_count": "0"}},
		{ID: "arn:aws:iam::222:root", Type: "iam_user", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"root": "true", "console_access": "true", "mfa_enabled": "true", "active_key_count": "0"}},
		{ID: "cluster/prod", Type: "eks_cluster", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"endpoint_public_access": "true", "public_access_cidrs": "0.0.0.0/0"}},
		{ID: "arn:secret/db", Type: "secretsmanager_secret", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"rotation_enabled": "false"}},
		{ID: "arn:ecr/app", Type: "ecr_repository", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"tag_mutability": "MUTABLE"}},
	}
	byResource := map[string][]string{}
	for _, f := range r.Run(assets, fixedTime) {
		byResource[f.ResourceID] = append(byResource[f.ResourceID], f.CheckID)
	}
	require.Contains(t, byResource["arn:aws:iam::111:root"], "aws-iam-root-no-mfa")
	require.NotContains(t, byResource["arn:aws:iam::222:root"], "aws-iam-root-no-mfa", "root with MFA is compliant")
	require.Contains(t, byResource["cluster/prod"], "aws-eks-public-endpoint")
	require.Contains(t, byResource["arn:secret/db"], "aws-secretsmanager-no-rotation")
	require.Contains(t, byResource["arn:ecr/app"], "aws-ecr-mutable-image-tags")
}

func TestRun_BreadthChecks(t *testing.T) {
	r := Default()
	assets := []asset.Asset{
		{ID: "p/cloudsql/db", Type: "cloudsql_instance", Provider: asset.ProviderGCP,
			Metadata: map[string]string{"public": "true", "require_ssl": "false"}},
		{ID: "p/cloudrun/api", Type: "cloudrun_service", Provider: asset.ProviderGCP,
			Metadata: map[string]string{"public": "true"}},
		{ID: "p/secret/key", Type: "gcp_secret", Provider: asset.ProviderGCP,
			Metadata: map[string]string{"rotation": "false"}},
		{ID: "arn:svc", Type: "ecs_service", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"assign_public_ip": "ENABLED"}},
	}
	got := map[string]bool{}
	for _, f := range r.Run(assets, fixedTime) {
		got[f.CheckID] = true
	}
	require.True(t, got["gcp-cloudsql-public-ip"])
	require.True(t, got["gcp-cloudsql-no-ssl"])
	require.True(t, got["gcp-cloudrun-public"])
	require.True(t, got["gcp-secret-no-rotation"])
	require.True(t, got["ecs-service-assign-public-ip"])
}

func TestRun_SGWorldOpenAdminPort(t *testing.T) {
	r := Default()
	open := `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]}]`
	scoped := `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["10.0.0.0/8"]}]`
	httpsOnly := `[{"protocol":"tcp","from_port":443,"to_port":443,"cidrs":["0.0.0.0/0"]}]`
	assets := []asset.Asset{
		{ID: "sg-open", Type: "security_group", Provider: asset.ProviderAWS, Metadata: map[string]string{"ingress": open}},
		{ID: "sg-scoped", Type: "security_group", Provider: asset.ProviderAWS, Metadata: map[string]string{"ingress": scoped}},
		{ID: "sg-https", Type: "security_group", Provider: asset.ProviderAWS, Metadata: map[string]string{"ingress": httpsOnly}},
	}
	byResource := map[string]finding.Finding{}
	for _, f := range r.Run(assets, fixedTime) {
		byResource[f.ResourceID] = f
	}
	require.Contains(t, byResource, "sg-open")
	require.Equal(t, "aws-security-group-world-open-admin-port", byResource["sg-open"].CheckID)
	require.Equal(t, finding.SeverityHigh, byResource["sg-open"].Severity)
	require.NotContains(t, byResource, "sg-scoped", "admin port open only to private CIDR")
	require.NotContains(t, byResource, "sg-https", "443 world-open is not an admin port")
}

// ::/0 is the IPv6 world: an admin port or all-traffic egress open to it is as
// exposed as 0.0.0.0/0.
func TestSGChecks_IPv6WorldIsWorld(t *testing.T) {
	v6Admin := asset.Asset{Metadata: map[string]string{"ingress": `[{"protocol":"tcp","from_port":3389,"to_port":3389,"cidrs":["::/0"]}]`}}
	require.True(t, sgWorldOpenAdminPort(v6Admin))
	v6Egress := asset.Asset{Metadata: map[string]string{"egress": `[{"protocol":"-1","cidrs":["::/0"]}]`}}
	require.True(t, sgUnrestrictedEgress(v6Egress))
	prefixOnly := asset.Asset{Metadata: map[string]string{"ingress": `[{"protocol":"tcp","from_port":22,"to_port":22,"prefix_lists":["pl-123"]}]`}}
	require.False(t, sgWorldOpenAdminPort(prefixOnly), "a prefix list is a reference, not the world")
}

func TestRun_DNSTakeoverNoDoubleFireAndDemoted(t *testing.T) {
	r := Default()
	assets := []asset.Asset{
		{ID: "specific", Type: "dns_record", Provider: asset.ProviderAWS, Name: "app.example.com", Metadata: map[string]string{"type": "CNAME", "values": "d123.cloudfront.net"}},
		{ID: "wild", Type: "dns_record", Provider: asset.ProviderAWS, Name: "*.example.com", Metadata: map[string]string{"type": "CNAME", "values": "old-app.herokuapp.com"}},
		{ID: "owned", Type: "dns_record", Provider: asset.ProviderAWS, Name: "safe.example.com", Metadata: map[string]string{"type": "A", "values": "1.2.3.4"}},
	}
	byResource := map[string][]finding.Finding{}
	for _, f := range r.Run(assets, fixedTime) {
		byResource[f.ResourceID] = append(byResource[f.ResourceID], f)
	}
	// Specific CNAME → exactly one finding, demoted to medium (pattern-only candidate).
	require.Len(t, byResource["specific"], 1)
	require.Equal(t, "dns-cname-takeover-risk", byResource["specific"][0].CheckID)
	require.Equal(t, finding.SeverityMedium, byResource["specific"][0].Severity)
	// Wildcard → exactly one finding (the wildcard check), NOT also the base one.
	require.Len(t, byResource["wild"], 1, "wildcard must not double-fire base + wildcard checks")
	require.Equal(t, "dns-wildcard-cname-takeover-risk", byResource["wild"][0].CheckID)
	require.Equal(t, finding.SeverityHigh, byResource["wild"][0].Severity)
	// A-record to an IP is not a takeover candidate.
	require.NotContains(t, byResource, "owned")
}

func TestRun_DefaultSAExactMatch(t *testing.T) {
	r := Default()
	assets := []asset.Asset{
		// role_ref must name a PRIVILEGED role for the check to fire at all — see
		// TestK8sDefaultServiceAccountBoundRequiresPrivilege. "view" would be
		// silenced by the privilege gate before the subject match is reached.
		{ID: "crb-default", Type: "k8s_cluster_role_binding", Provider: asset.ProviderKubernetes, Metadata: map[string]string{"role_ref": "admin", "subjects": "ServiceAccount/default"}},
		// "default-backend" must NOT substring-match "default".
		{ID: "crb-backend", Type: "k8s_cluster_role_binding", Provider: asset.ProviderKubernetes, Metadata: map[string]string{"role_ref": "admin", "subjects": "ServiceAccount/default-backend"}},
	}
	hit := map[string]bool{}
	for _, f := range r.Run(assets, fixedTime) {
		if f.CheckID == "k8s-default-service-account-bound" {
			hit[f.ResourceID] = true
		}
	}
	require.True(t, hit["crb-default"], "the real default SA must fire")
	require.False(t, hit["crb-backend"], "default-backend must not substring-match")
}

// TestRun_NamespacedRBACChecks exercises the four Role/RoleBinding sibling
// checks end-to-end through the registry, pinning the false-positive guard
// that role_ref_kind exists to prevent: a namespaced Role legitimately named
// "admin" must NOT trip k8s-rolebinding-admin-binding, only a RoleBinding
// naming the built-in ClusterRole "admin"/"edit"/"cluster-admin" does.
func TestRun_NamespacedRBACChecks(t *testing.T) {
	r := Default()
	assets := []asset.Asset{
		// Wildcard Role.
		{ID: "role-wild", Type: "k8s_role", Provider: asset.ProviderKubernetes,
			Metadata: map[string]string{"namespace": "billing", "wildcard_verbs": "true"}},
		// Dangerous-permission Role (reuses dangerousPermissionCategories, same as ClusterRole).
		{ID: "role-danger", Type: "k8s_role", Provider: asset.ProviderKubernetes,
			Metadata: map[string]string{"namespace": "billing", "dangerous_perms": "true", "dangerous_perms_detail": "secrets-read"}},
		// RoleBinding -> built-in ClusterRole "admin": must fire.
		{ID: "rb-to-clusterrole-admin", Type: "k8s_role_binding", Provider: asset.ProviderKubernetes,
			Metadata: map[string]string{"namespace": "billing", "role_ref": "admin", "role_ref_kind": "ClusterRole"}},
		// RoleBinding -> namespaced Role legitimately named "admin": must NOT fire
		// (the false positive role_ref_kind exists to prevent).
		{ID: "rb-to-role-admin", Type: "k8s_role_binding", Provider: asset.ProviderKubernetes,
			Metadata: map[string]string{"namespace": "billing", "role_ref": "admin", "role_ref_kind": "Role"}},
		// RoleBinding -> ClusterRole "edit": must fire.
		{ID: "rb-to-clusterrole-edit", Type: "k8s_role_binding", Provider: asset.ProviderKubernetes,
			Metadata: map[string]string{"namespace": "billing", "role_ref": "edit", "role_ref_kind": "ClusterRole"}},
		// RoleBinding -> ClusterRole "view" (not admin/edit): must NOT fire.
		{ID: "rb-to-clusterrole-view", Type: "k8s_role_binding", Provider: asset.ProviderKubernetes,
			Metadata: map[string]string{"namespace": "billing", "role_ref": "view", "role_ref_kind": "ClusterRole"}},
		// Default SA bound to a READ-ONLY role: must NOT fire. Binding `view` to the
		// default SA is not a privilege-escalation path, and Helm charts do it
		// routinely — firing here is the
		// fire-on-everything pattern that gets a check muted.
		{ID: "rb-default-sa-view", Type: "k8s_role_binding", Provider: asset.ProviderKubernetes,
			Metadata: map[string]string{"namespace": "billing", "role_ref": "view", "role_ref_kind": "ClusterRole", "subjects": "ServiceAccount/default"}},
		// Default SA bound to a PRIVILEGED role: must fire.
		{ID: "rb-default-sa-admin", Type: "k8s_role_binding", Provider: asset.ProviderKubernetes,
			Metadata: map[string]string{"namespace": "billing", "role_ref": "admin", "role_ref_kind": "ClusterRole", "subjects": "ServiceAccount/default"}},
	}
	byResource := map[string][]string{}
	for _, f := range r.Run(assets, fixedTime) {
		byResource[f.ResourceID] = append(byResource[f.ResourceID], f.CheckID)
	}
	require.Contains(t, byResource["role-wild"], "k8s-role-wildcard-verbs")
	require.Contains(t, byResource["role-danger"], "k8s-rbac-secrets-access")
	require.Contains(t, byResource["rb-to-clusterrole-admin"], "k8s-rolebinding-admin-binding")
	require.NotContains(t, byResource["rb-to-role-admin"], "k8s-rolebinding-admin-binding",
		"a namespaced Role named admin must not be confused with the built-in ClusterRole admin")
	require.Contains(t, byResource["rb-to-clusterrole-edit"], "k8s-rolebinding-admin-binding")
	require.Empty(t, byResource["rb-to-clusterrole-view"])
	require.NotContains(t, byResource["rb-default-sa-view"], "k8s-rolebinding-default-service-account-bound",
		"the default SA bound to a read-only role is not an escalation path")
	require.Contains(t, byResource["rb-default-sa-admin"], "k8s-rolebinding-default-service-account-bound")
}

func TestRun_RootActiveKey(t *testing.T) {
	r := Default()
	assets := []asset.Asset{
		{ID: "arn:aws:iam::1:root", Name: "root", Type: "iam_user", Provider: asset.ProviderAWS, Metadata: map[string]string{"root": "true", "active_key_count": "1", "mfa_enabled": "false", "console_access": "true"}},
		{ID: "arn:aws:iam::1:root-nokey", Name: "root", Type: "iam_user", Provider: asset.ProviderAWS, Metadata: map[string]string{"root": "true", "active_key_count": "0"}},
		// A regular user named "root" (not the account root) must not trip it.
		{ID: "arn:aws:iam::1:user/root", Name: "root", Type: "iam_user", Provider: asset.ProviderAWS, Metadata: map[string]string{"active_key_count": "3"}},
	}
	hit := map[string]bool{}
	for _, f := range r.Run(assets, fixedTime) {
		if f.CheckID == "aws-iam-root-active-key" {
			hit[f.ResourceID] = true
		}
	}
	require.True(t, hit["arn:aws:iam::1:root"], "root with an active key must fire")
	require.False(t, hit["arn:aws:iam::1:root-nokey"], "root with zero keys must not fire")
	require.False(t, hit["arn:aws:iam::1:user/root"], "a non-root user named root must not fire")
}

func TestTieredExposureSeverity(t *testing.T) {
	sev := tieredExposureSeverity(finding.SeverityHigh, finding.SeverityLow)
	require.Equal(t, finding.SeverityHigh, sev(asset.Asset{Metadata: map[string]string{"public_access": asset.PublicAccessConfirmed}}))
	require.Equal(t, finding.SeverityLow, sev(asset.Asset{Metadata: map[string]string{"public_access": asset.PublicAccessPossible}}))
	// No tier key (legacy/unknown) grades to the lower band, not the higher.
	require.Equal(t, finding.SeverityLow, sev(asset.Asset{Metadata: map[string]string{}}))
}

func TestTieredExposureTitle(t *testing.T) {
	title := tieredExposureTitle("is public", "is not locked down")
	require.Equal(t, "is public", title(asset.Asset{Metadata: map[string]string{"public_access": asset.PublicAccessConfirmed}}))
	require.Equal(t, "is not locked down", title(asset.Asset{Metadata: map[string]string{"public_access": asset.PublicAccessPossible}}))
	// No tier key (legacy/unknown) must take the WEAKER claim, never assert "public".
	require.Equal(t, "is not locked down", title(asset.Asset{Metadata: map[string]string{}}))
}

// TestRun_S3PossibleTierIsNotTitledPublic pins a reporting bug.
//
// aws-s3-public-bucket fires on both exposure tiers. The detection was always right —
// only the CONFIRMED tier (a public policy or ACL) emits an exposed_to_internet edge —
// but the finding TITLE was the absolute "S3 bucket is public" for both, so a bucket
// with IsPublic=false and no public ACL, merely missing Block Public Access, surfaced as
// a Low finding literally asserting it was public — wording that invites escalating a
// bucket as a public exposure it is not.
func TestRun_S3PossibleTierIsNotTitledPublic(t *testing.T) {
	r := Default()
	assets := []asset.Asset{
		{ID: "b-confirmed", Type: "s3_bucket", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"public": "true", "public_access": asset.PublicAccessConfirmed}},
		{ID: "b-possible", Type: "s3_bucket", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"public": "true", "public_access": asset.PublicAccessPossible}},
	}

	byID := map[string]finding.Finding{}
	for _, f := range r.Run(assets, fixedTime) {
		if f.CheckID == "aws-s3-public-bucket" {
			byID[f.ResourceID] = f
		}
	}
	require.Len(t, byID, 2, "both tiers must still surface a finding")

	confirmed := byID["b-confirmed"]
	require.Equal(t, finding.SeverityHigh, confirmed.Severity)
	require.Equal(t, "S3 bucket is public", confirmed.Title,
		"a genuinely public bucket must keep the direct wording")

	possible := byID["b-possible"]
	require.Equal(t, finding.SeverityLow, possible.Severity)
	require.NotContains(t, possible.Title, "is public",
		"a bucket that is NOT public must never carry a title asserting it is")
	require.Equal(t, "S3 bucket has no Block Public Access", possible.Title)

	// The ids must be unchanged by the retitle: DeterministicID covers (check id,
	// asset id) only, so this rewrites existing rows instead of forking duplicates.
	require.NotEqual(t, confirmed.ID, possible.ID)
}

// A check with no TitleFor keeps its static Title — the retitle must be opt-in.
func TestCheckWithoutTitleForKeepsStaticTitle(t *testing.T) {
	c := Check{
		ID: "t-static", Title: "static title", Type: "exposure",
		Severity: finding.SeverityLow, Provider: asset.ProviderAWS,
		Violates: func(asset.Asset) bool { return true },
	}
	got, ok := c.eval(asset.Asset{ID: "a-1"}, fixedTime)
	require.True(t, ok)
	require.Equal(t, "static title", got.Title)
}

// Publicly-accessible RDS is reachability-only (auth still required) → low severity.
func TestRun_RDSPubliclyAccessibleIsLow(t *testing.T) {
	r := Default()
	assets := []asset.Asset{
		{ID: "db-pub", Type: "rds_instance", Provider: asset.ProviderAWS, Metadata: map[string]string{"publicly_accessible": "true", "public_access": asset.PublicAccessPossible, "storage_encrypted": "true", "backup_retention": "7", "deletion_protection": "true", "multi_az": "true"}},
	}
	var got *finding.Finding
	for _, f := range r.Run(assets, fixedTime) {
		if f.CheckID == "aws-rds-publicly-accessible" {
			f := f
			got = &f
		}
	}
	require.NotNil(t, got, "publicly-accessible RDS must still surface")
	require.Equal(t, finding.SeverityLow, got.Severity)
}

func TestRun_SGOpenPortsExtra(t *testing.T) {
	r := Default()
	dbPort := `[{"protocol":"tcp","from_port":3306,"to_port":3306,"cidrs":["0.0.0.0/0"]}]`
	allTraffic := `[{"protocol":"-1","from_port":0,"to_port":0,"cidrs":["0.0.0.0/0"]}]`
	dbScoped := `[{"protocol":"tcp","from_port":3306,"to_port":3306,"cidrs":["10.0.0.0/8"]}]`
	assets := []asset.Asset{
		{ID: "sg-db", Type: "security_group", Provider: asset.ProviderAWS, Metadata: map[string]string{"ingress": dbPort}},
		{ID: "sg-all", Type: "security_group", Provider: asset.ProviderAWS, Metadata: map[string]string{"ingress": allTraffic}},
		{ID: "sg-dbscoped", Type: "security_group", Provider: asset.ProviderAWS, Metadata: map[string]string{"ingress": dbScoped}},
	}
	byCheck := map[string]bool{}
	for _, f := range r.Run(assets, fixedTime) {
		byCheck[f.CheckID+"|"+f.ResourceID] = true
	}
	// Previously dead (parser read "cidr"; collector emits "cidrs"): now fire.
	require.True(t, byCheck["aws-sg-open-database-ports|sg-db"], "world-open 3306 must fire")
	require.True(t, byCheck["aws-sg-open-all-ports|sg-all"], "protocol -1 all-traffic must fire")
	require.False(t, byCheck["aws-sg-open-database-ports|sg-all"],
		"an all-ports-open group is already Critical under aws-sg-open-all-ports — reporting it again as a db-port exposure is the same finding twice")
	require.False(t, byCheck["aws-security-group-world-open-admin-port|sg-all"],
		"and again as an admin-port exposure")
	require.False(t, byCheck["aws-sg-open-database-ports|sg-dbscoped"], "db port scoped to private CIDR must not fire")
}

func TestRun_FirewallOpenIngress(t *testing.T) {
	r := Default()
	fw := func(id string, md map[string]string) asset.Asset {
		base := map[string]string{"open_to_internet": "true", "shadowed_by_deny": "false",
			"ssh_open_to_internet": "false", "rdp_open_to_internet": "false"}
		for k, v := range md {
			base[k] = v
		}
		return asset.Asset{ID: id, Type: "gcp_firewall", Provider: asset.ProviderGCP, Metadata: base}
	}
	assets := []asset.Asset{
		fw("p/firewall/open", map[string]string{"allowed": "tcp:8080"}),
		fw("p/firewall/closed", map[string]string{"open_to_internet": "false"}),
		// Every allowed port is denied first by a higher-priority world deny.
		fw("p/firewall/shadowed", map[string]string{"allowed": "tcp:8080", "shadowed_by_deny": "true"}),
		// SSH is the specific finding; the generic one steps aside.
		fw("p/firewall/ssh", map[string]string{"allowed": "tcp:22,8080", "ssh_open_to_internet": "true"}),
	}
	got := map[string]string{}
	for _, f := range r.Run(assets, fixedTime) {
		got[f.ResourceID] = f.CheckID
	}
	require.Equal(t, map[string]string{
		"p/firewall/open": "gcp-firewall-open-ingress",
		"p/firewall/ssh":  "gcp-firewall-ssh-open-internet",
	}, got)
}

// gcp-firewall-open-ingress used to be High on any port; the grade now follows
// what the rule opens.
func TestFirewallOpenSeverity(t *testing.T) {
	sev := func(allowed string) finding.Severity {
		return firewallOpenSeverity(asset.Asset{Metadata: map[string]string{"allowed": allowed}})
	}
	require.Equal(t, finding.SeverityHigh, sev("all"))
	require.Equal(t, finding.SeverityHigh, sev("tcp"), "a protocol with no ports opens every port")
	require.Equal(t, finding.SeverityHigh, sev("tcp:5000-6000"), "spans 5432")
	require.Equal(t, finding.SeverityHigh, sev("tcp:443;udp:6379"))
	require.Equal(t, finding.SeverityLow, sev("tcp:80,443"))
	require.Equal(t, finding.SeverityMedium, sev("tcp:443,8443"))
	require.Equal(t, finding.SeverityMedium, sev("tcp:80-443"), "a range is not just the web ports")
	require.Equal(t, finding.SeverityHigh, sev("tcp:x"), "unreadable is not graded down")
}

func TestRegistry_OnlyAppliesMatchingProvider(t *testing.T) {
	// An AWS check must never fire on a GCP asset even with a public IP.
	r := NewRegistry()
	r.Register(awsEC2PublicIP)
	findings := r.Run([]asset.Asset{
		{ID: "g-1", Type: "gce_instance", Provider: asset.ProviderGCP, PublicIP: "1.1.1.1"},
	}, fixedTime)
	require.Empty(t, findings)
}

// Fingerprint identifies the check SET: stable across registration order,
// different when the catalogue changes — the sync worker persists it per
// connector to detect check deployments needing a full-asset backfill.
func TestRegistry_Fingerprint(t *testing.T) {
	a := Check{ID: "aws-a", Provider: asset.ProviderAWS, Violates: func(asset.Asset) bool { return false }}
	b := Check{ID: "aws-b", Provider: asset.ProviderAWS, Violates: func(asset.Asset) bool { return false }}

	r1 := NewRegistry()
	r1.Register(a, b)
	r2 := NewRegistry()
	r2.Register(b, a)
	require.Equal(t, r1.Fingerprint(), r2.Fingerprint(), "order must not matter")

	r3 := NewRegistry()
	r3.Register(a)
	require.NotEqual(t, r1.Fingerprint(), r3.Fingerprint(), "a different check set must fingerprint differently")
	require.NotEmpty(t, r3.Fingerprint())

	// Same IDs, edited logic: the stored fingerprint must mismatch so the sync
	// worker re-checks every unchanged asset against the new predicate.
	edited := NewRegistry()
	edited.Register(a, b)
	edited.checks[0].logic = "edited"
	require.NotEqual(t, r1.Fingerprint(), edited.Fingerprint(), "editing a check's logic must change the fingerprint")
}

// Every catalogue check carries a logic digest, otherwise an edit to it would
// not move the fingerprint and would stay dark on unchanged assets.
func TestRegisteredChecksCarryLogicDigest(t *testing.T) {
	for _, c := range Default().All() {
		require.NotEmptyf(t, c.logic, "check %q has no logic digest — run: go run ./cmd/checkkeys-gen", c.ID)
	}
}

// The lifecycle checks (VM and runtime end of life, EKS support windows, long
// stops), the storage key age check and the root-use and secret-age checks
// compare a stored date to today, so they are the time-dependent ones, and
// TimeDependent() selects exactly the clock readers.
func TestRegistry_TimeDependent(t *testing.T) {
	var got []string
	for _, c := range Default().TimeDependent().All() {
		require.True(t, c.TimeDependent)
		got = append(got, c.ID)
	}
	want := []string{
		"aws-ec2-os-end-of-life", "gcp-gce-os-end-of-life", "aws-ec2-stopped-long", "aws-lambda-deprecated-runtime",
		"aws-eks-unsupported-version", "aws-eks-nodegroup-unsupported-version", "azure-storage-key-not-rotated",
		"aws-iam-root-recently-used", "aws-iam-server-certificate-expired", "aws-ec2-instance-too-old",
	}
	for _, check := range []string{"rotation-overdue", "not-rotated-90d", "unused"} {
		want = append(want, "aws-secretsmanager-"+check)
	}
	require.ElementsMatch(t, want, got)
	ec2, ok := Default().ByID("aws-ec2-public-ip")
	require.True(t, ok)
	require.False(t, ec2.TimeDependent)
}

// No two registered checks may read the same metadata key on the same asset type
// at the same severity — that is the signature of a duplicate pair such as
// aws-s3-versioning-disabled and aws-s3-no-versioning, which both graded
// `versioning` on s3_bucket at Medium and so produced findings restating a
// problem already counted. A dashboard that says the same thing twice
// teaches people to stop reading it.
//
// This asserts the four known pairs stay gone. It is deliberately a specific
// assertion rather than a generic scan: `Violates` is a closure, so there is no
// way to compare two checks' predicates programmatically — only their IDs.
//
// Four such pairs are a structural consequence of importing check
// sets from several sources (cis.go, cspm_extra.go, hygiene.go) that each
// independently cover the CIS baseline, not four coincidences. When adding a check,
// grep the registry for its metadata key on its asset type first.
func TestDefault_NoReintroducedDuplicateChecks(t *testing.T) {
	seen := Default().IDs()
	for _, removed := range []string{
		"aws-s3-versioning-disabled", "aws-s3-logging-disabled",
		// Identical predicate to aws-iam-user-no-mfa on the same asset type — every
		// MFA-less console user produced two findings at two severities.
		"aws-iam-no-mfa",
		// Identical predicate (storage_encrypted == "false") to
		// aws-rds-not-encrypted on the same rds_instance asset type at the same
		// High severity — every unencrypted database counted twice.
		"aws-rds-unencrypted",
	} {
		require.False(t, seen[removed],
			"%s was removed as an exact duplicate — re-registering it double-counts an already-reported problem", removed)
	}
	// The survivors must still be registered, or the gap goes undetected entirely.
	require.True(t, seen["aws-s3-no-versioning"], "the kept versioning check must remain")
	require.True(t, seen["aws-s3-access-logging-disabled"], "the kept logging check must remain")
	require.True(t, seen["aws-iam-user-no-mfa"],
		"the surviving MFA check must remain — console access without MFA is the account-takeover path")
	require.True(t, seen["aws-rds-not-encrypted"],
		"the surviving RDS encryption check must remain — it carries the snapshot-copy remediation")
}

// cluster-admin bound to system:authenticated makes every caller a cluster
// administrator. Nothing detected it before: graph edges fan out only to
// ServiceAccount subjects, so a Group subject produced no edge, and every other
// RBAC check reads either the role's rules or its SA subjects.
func TestRun_PrivilegedBindingToEveryone(t *testing.T) {
	r := Default()
	assets := []asset.Asset{
		// The catastrophic case.
		{ID: "crb-world-admin", Type: "k8s_cluster_role_binding", Provider: asset.ProviderKubernetes,
			Metadata: map[string]string{"role_ref": "cluster-admin", "role_ref_kind": "ClusterRole",
				"subjects": "Group/system:authenticated"}},
		// Anonymous is worse still, and namespaced counts too.
		{ID: "rb-anon-admin", Type: "k8s_role_binding", Provider: asset.ProviderKubernetes,
			Metadata: map[string]string{"namespace": "billing", "role_ref": "admin", "role_ref_kind": "ClusterRole",
				"subjects": "Group/system:unauthenticated"}},
		// The standard Kubernetes benign defaults. These must stay silent or the
		// check is pure noise.
		{ID: "crb-basic-user", Type: "k8s_cluster_role_binding", Provider: asset.ProviderKubernetes,
			Metadata: map[string]string{"role_ref": "system:basic-user", "role_ref_kind": "ClusterRole",
				"subjects": "Group/system:authenticated,Group/system:unauthenticated"}},
		{ID: "crb-discovery", Type: "k8s_cluster_role_binding", Provider: asset.ProviderKubernetes,
			Metadata: map[string]string{"role_ref": "system:discovery", "role_ref_kind": "ClusterRole",
				"subjects": "Group/system:authenticated"}},
		// A privileged role bound to a NAMED group is not everyone.
		{ID: "crb-named-group", Type: "k8s_cluster_role_binding", Provider: asset.ProviderKubernetes,
			Metadata: map[string]string{"role_ref": "cluster-admin", "role_ref_kind": "ClusterRole",
				"subjects": "Group/platform-oncall"}},
	}
	fired := map[string]bool{}
	for _, f := range r.Run(assets, fixedTime) {
		if f.CheckID == "k8s-privileged-binding-to-everyone" {
			fired[f.ResourceID] = true
			require.Equal(t, finding.SeverityCritical, f.Severity)
		}
	}
	require.True(t, fired["crb-world-admin"], "cluster-admin to system:authenticated must fire Critical")
	require.True(t, fired["rb-anon-admin"], "a namespaced binding to anonymous must fire too")
	require.False(t, fired["crb-basic-user"], "the Kubernetes default must stay silent")
	require.False(t, fired["crb-discovery"], "the Kubernetes default must stay silent")
	require.False(t, fired["crb-named-group"], "a named group is not everyone")
}
