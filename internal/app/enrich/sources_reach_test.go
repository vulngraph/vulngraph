package enrich

import (
	"context"
	"errors"
	"testing"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type fakeReach struct {
	hops int
	ok   bool
	err  error
}

func (f fakeReach) InternetHops(context.Context, string) (int, bool, error) {
	return f.hops, f.ok, f.err
}

func reachPrivescFinding() finding.Finding {
	return finding.Finding{ResourceID: "role:x", ResourceType: "iam_role", CheckID: "iam-privesc-01", Type: "ciem_privesc"}
}

// reachNetworkFinding is a plain infrastructure misconfiguration on a
// network-addressable resource — neither privesc nor an "exposure"/"public"
// check by string. Before the gate widened to resource type, this class was
// silently skipped by InternetReach (no ec2_instance finding was ever
// evaluated). It now qualifies via
// IsNetworkReachableResource.
func reachNetworkFinding() finding.Finding {
	return finding.Finding{ResourceID: "i-abc", ResourceType: "ec2_instance", CheckID: "ec2-imdsv1-enabled", Type: "misconfiguration"}
}

func TestInternetReach(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name           string
		f              finding.Finding
		reach          fakeReach
		wantApplied    bool
		wantSuppress   bool
		wantPointsSign int // -1, 0, +1
	}{
		{"1 hop promotes", reachPrivescFinding(), fakeReach{1, true, nil}, true, false, +1},
		{"3 hops promotes less", reachPrivescFinding(), fakeReach{3, true, nil}, true, false, +1},
		{"unreachable demotes (negative, not suppress)", reachPrivescFinding(), fakeReach{reachNone, true, nil}, true, false, -1},
		{"direct (hop 0) scores — not an exposure-type finding, so ExposureType never covered it", reachPrivescFinding(), fakeReach{0, true, nil}, true, false, +1},
		{"direct (hop 0) no-op when ExposureType already covers it", finding.Finding{ResourceID: "b", ResourceType: "s3_bucket", CheckID: "s3-public", Type: "exposure", Severity: finding.SeverityMedium}, fakeReach{0, true, nil}, false, false, 0},
		{"unknown reachability → no signal", reachPrivescFinding(), fakeReach{0, false, nil}, false, false, 0},
		{"error → not applied", reachPrivescFinding(), fakeReach{0, false, errors.New("busy")}, false, false, 0},
		{"KEV never demoted for unreachable", func() finding.Finding { f := reachPrivescFinding(); f.KnownExploited = true; return f }(), fakeReach{reachNone, true, nil}, false, false, 0},
		{"non-reachability-meaningful type ignored", finding.Finding{ResourceID: "r", ResourceType: "iam_role", CheckID: "supply-chain-cve", Type: "vulnerability"}, fakeReach{reachNone, true, nil}, false, false, 0},
		// Network-addressable resource with a plain misconfig check: gate opens on
		// resource type, so the BFS now runs and its signal applies.
		{"network resource 1 hop promotes", reachNetworkFinding(), fakeReach{1, true, nil}, true, false, +1},
		{"network resource unreachable demotes", reachNetworkFinding(), fakeReach{reachNone, true, nil}, true, false, -1},
		{"network resource direct (hop 0) scores — misconfiguration type, not exposure", reachNetworkFinding(), fakeReach{0, true, nil}, true, false, +1},
		{"network resource unknown → no signal", reachNetworkFinding(), fakeReach{0, false, nil}, false, false, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			factor, applied, err := InternetReach{Reach: tc.reach}.Evaluate(ctx, tc.f)
			if err != nil && tc.reach.err == nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if applied != tc.wantApplied {
				t.Fatalf("applied = %v, want %v", applied, tc.wantApplied)
			}
			if !applied {
				return
			}
			if factor.Suppress != tc.wantSuppress {
				t.Errorf("suppress = %v, want %v", factor.Suppress, tc.wantSuppress)
			}
			sign := 0
			if factor.Points > 0 {
				sign = 1
			} else if factor.Points < 0 {
				sign = -1
			}
			if sign != tc.wantPointsSign {
				t.Errorf("points %d sign = %d, want %d", factor.Points, sign, tc.wantPointsSign)
			}
		})
	}

	t.Run("nil provider no-op", func(t *testing.T) {
		_, applied, _ := InternetReach{}.Evaluate(ctx, reachPrivescFinding())
		if applied {
			t.Fatal("nil provider must not apply")
		}
	})
}

func TestIsNetworkReachableResource(t *testing.T) {
	reachable := []string{
		"ec2_instance", "gce_instance", "lambda_function", "security_group",
		"load_balancer", "rds_instance", "k8s_pod", "k8s_service", "k8s_ingress",
		"k8s_deployment", "k8s_statefulset", "k8s_daemonset", "k8s_job",
		// InternetReachability producers (correlate/reachability.go): missing
		// from this gate, their findings would sit at blank must_fix_class
		// regardless of graph evidence.
		"cloud_function", "cloudsql_instance", "api_gateway",
	}
	for _, rt := range reachable {
		if !IsNetworkReachableResource(rt) {
			t.Errorf("IsNetworkReachableResource(%q) = false, want true", rt)
		}
	}
	notReachable := []string{"iam_role", "iam_user", "gcp_service_account", "s3_bucket", "github_repo", ""}
	for _, rt := range notReachable {
		if IsNetworkReachableResource(rt) {
			t.Errorf("IsNetworkReachableResource(%q) = true, want false", rt)
		}
	}
}

// TestDirectExposurePoints_AtLeastAsUrgentAsOneHop pins the documented
// invariant: a directly internet-facing resource is at least as urgent as a
// 1-hop path, so InternetReach must never rank direct exposure below it.
func TestDirectExposurePoints_AtLeastAsUrgentAsOneHop(t *testing.T) {
	if directExposurePoints < reachPoints(1) {
		t.Fatalf("directExposurePoints (%d) must be >= reachPoints(1) (%d)", directExposurePoints, reachPoints(1))
	}
}

func TestExposureTypeCovers(t *testing.T) {
	cases := []struct {
		name string
		f    finding.Finding
		want bool
	}{
		{"exposure + medium is covered", finding.Finding{Type: "exposure", Severity: finding.SeverityMedium}, true},
		{"exposure + high is not covered (ExposureType only boosts medium)", finding.Finding{Type: "exposure", Severity: finding.SeverityHigh}, false},
		{"threat type is never covered", finding.Finding{Type: "threat", Severity: finding.SeverityMedium}, false},
		{"misconfiguration type is never covered", finding.Finding{Type: "misconfiguration", Severity: finding.SeverityMedium}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := exposureTypeCovers(c.f); got != c.want {
				t.Errorf("exposureTypeCovers = %v, want %v", got, c.want)
			}
		})
	}
}

func TestReachabilityMeaningful(t *testing.T) {
	cases := []struct {
		name string
		f    finding.Finding
		want bool
	}{
		{"privesc by check id", finding.Finding{CheckID: "aws-privesc-15"}, true},
		{"exposure type", finding.Finding{Type: "exposure"}, true},
		{"public check id", finding.Finding{CheckID: "aws-s3-public"}, true},
		{"network resource type", finding.Finding{ResourceType: "ec2_instance", CheckID: "ec2-imdsv1-enabled"}, true},
		{"k8s pod network resource", finding.Finding{ResourceType: "k8s_pod", CheckID: "k8s-allow-privilege-escalation"}, true},
		{"non-network config hygiene", finding.Finding{ResourceType: "s3_bucket", CheckID: "s3-versioning-disabled"}, false},
		{"supply-chain package", finding.Finding{ResourceType: "package", CheckID: "CVE-2023-44487"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := reachabilityMeaningful(c.f); got != c.want {
				t.Errorf("reachabilityMeaningful = %v, want %v", got, c.want)
			}
		})
	}
}
