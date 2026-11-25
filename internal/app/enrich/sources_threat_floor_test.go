package enrich

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestThreatFloor(t *testing.T) {
	gd := func(checkID string) finding.Finding {
		return finding.Finding{Source: "aws_guardduty", Type: "threat", Severity: finding.SeverityHigh, CheckID: checkID}
	}
	// wantCeiling is set for the DNS-observation families: declining to floor them
	// only removes a lift, so they are additionally capped below the actionable
	// band (see sources_threat_floor.go). A row with
	// neither a floor nor a ceiling is not applied at all.
	tests := []struct {
		name        string
		f           finding.Finding
		wantFloor   int
		wantCeiling int
	}{
		// Act-now, page-worthy.
		{"instance cred exfil → page", gd("UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS"), ThresholdPage, 0},
		{"malicious file → page", gd("Execution:EC2/MaliciousFile"), ThresholdPage, 0},
		// The !DNS gate now beats the page markers, reversing the old precedence.
		// "GuardDuty first saw it via DNS" is not evidence that BitcoinTool was
		// EXECUTED — a '!DNS' detection is only ever a lookup to a flagged domain.
		// On hosts that resolve externally-supplied domains, that would fire a
		// burst of pages off one DNS resolution each. A
		// host genuinely mining still reaches page via
		// corroboration with a non-DNS signal.
		{"crypto mining seen only via DNS → no floor", gd("CryptoCurrency:EC2/BitcoinTool.B!DNS"), 0, ThresholdHigh},
		// A page marker still wins when the detection is NOT a DNS observation.
		{"crypto mining (non-DNS) → page", gd("CryptoCurrency:EC2/BitcoinTool.B"), ThresholdPage, 0},
		// Actionable — non-DNS behavioral detections (real connection/traffic).
		{"C&C (non-DNS) → high", gd("Backdoor:EC2/C&CActivity.B"), ThresholdHigh, 0},
		{"DNS exfil → high", gd("Trojan:EC2/DNSDataExfiltration"), ThresholdHigh, 0},
		// Noisy single-signal DNS observations — NOT floored on their own (no
		// corroborating peer here); a lone !DNS lookup is corroboration-gated
		// regardless of threat family, so the C&C/Backdoor !DNS variant that used
		// to floor large numbers of EC2s on one lookup now defers like the phishing families.
		{"C&C via DNS only → no floor", gd("Backdoor:EC2/C&CActivity.B!DNS"), 0, ThresholdHigh},
		{"phishing domain request → no floor", gd("Trojan:EC2/PhishingDomainRequest!DNS"), 0, ThresholdHigh},
		{"drive-by traffic → no floor", gd("Trojan:EC2/DriveBySourceTraffic!DNS"), 0, ThresholdHigh},
		// The whole DNS-reputation family is one mechanism and must gate as one.
		// These three carry no '!DNS' suffix, so they used to match the high
		// markers ("DGADomainRequest" is one; the Reputation variants match
		// "Impact:") and floored to actionable while their PhishingDomainRequest
		// sibling was held back.
		{"DGA domain request → no floor", gd("Trojan:EC2/DGADomainRequest.B"), 0, ThresholdHigh},
		{"suspicious domain reputation → no floor", gd("Impact:EC2/SuspiciousDomainRequest.Reputation"), 0, ThresholdHigh},
		{"abused domain reputation → no floor", gd("Impact:EC2/AbusedDomainRequest.Reputation"), 0, ThresholdHigh},
		// Non-threat findings untouched.
		// Severity is Medium because that is what the check now declares — the
		// registry pins it (internal/checks TestAWSEBSUnencrypted_IsMediumNotHigh).
		// The assertion here is about SOURCE, not severity: a cspm misconfiguration
		// is not a threat finding and never gets a threat floor at any severity.
		{"cspm finding → no floor", finding.Finding{Source: "cspm", Type: "misconfiguration", CheckID: "aws-ebs-unencrypted", Severity: finding.SeverityMedium}, 0, 0},
		{"cspm finding at high → still no floor", finding.Finding{Source: "cspm", Type: "misconfiguration", CheckID: "aws-ebs-unencrypted", Severity: finding.SeverityHigh}, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, applied, err := ThreatFloor{}.Evaluate(context.Background(), tt.f)
			require.NoError(t, err)
			if tt.wantFloor == 0 && tt.wantCeiling == 0 {
				require.False(t, applied)
				return
			}
			require.True(t, applied)
			require.Equal(t, tt.wantFloor, f.Floor)
			require.Equal(t, tt.wantCeiling, f.Ceiling)
		})
	}
}

// SCC threat findings (small, GCP-curated) floor to actionable wholesale by severity.
func TestThreatFloor_SCC(t *testing.T) {
	high := finding.Finding{Source: "gcp_scc", Type: "threat", Severity: finding.SeverityHigh, CheckID: "Persistence: IAM Anomalous Grant"}
	f, applied, err := ThreatFloor{}.Evaluate(context.Background(), high)
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, ThresholdHigh, f.Floor)

	low := finding.Finding{Source: "gcp_scc", Type: "threat", Severity: finding.SeverityLow, CheckID: "Discovery: Service Account Self-Investigation"}
	_, applied, err = ThreatFloor{}.Evaluate(context.Background(), low)
	require.NoError(t, err)
	require.False(t, applied, "low-severity SCC threat is not floored")
}

// Even after GuardDuty-collapse dedup, open PhishingDomainRequest!DNS and
// DriveBySourceTraffic!DNS findings can outnumber every high-banded sibling
// and would swamp the high band if floored wholesale. Decision: keep them
// excluded from the blanket per-check floor; escalate only when the same host
// also shows another distinct, independently-floored threat detection.
func TestThreatFloor_DNSObservation_CorroboratedEscalatesToAuto(t *testing.T) {
	phish := finding.Finding{
		ID: "f1", Source: "aws_guardduty", Type: "threat", Severity: finding.SeverityHigh,
		CheckID: "Trojan:EC2/PhishingDomainRequest!DNS", ResourceID: "i-123",
	}
	// A genuine independent threat (non-DNS behavioral detection) on the same host.
	// It must NOT be another !DNS observation — two DNS signals don't corroborate
	// each other (see TestThreatFloor_DNSObservation_SameFamilyPeersDoNotCorroborate).
	cnc := finding.Finding{
		ID: "f2", Source: "aws_guardduty", Type: "threat", Severity: finding.SeverityHigh,
		CheckID: "Backdoor:EC2/C&CActivity.B", ResourceID: "i-123",
	}
	fp := fakeFindings{all: []finding.Finding{phish, cnc}}

	f, applied, err := (ThreatFloor{Findings: fp}).Evaluate(context.Background(), phish)
	require.NoError(t, err)
	require.True(t, applied, "corroborated by another distinct threat detection on the same host")
	require.Equal(t, ThresholdHigh, f.Floor)
}

// The same DNS-observation finding on a host with NO other threat detection is
// not floored — an isolated hit is not corroborating evidence — AND is capped
// below the actionable band, so the additive graph sources cannot carry it there
// on resource context alone.
func TestThreatFloor_DNSObservation_UncorroboratedIsCappedBelowAuto(t *testing.T) {
	phish := finding.Finding{
		ID: "f1", Source: "aws_guardduty", Type: "threat", Severity: finding.SeverityHigh,
		CheckID: "Trojan:EC2/PhishingDomainRequest!DNS", ResourceID: "i-456",
	}
	fp := fakeFindings{all: []finding.Finding{phish}}

	f, applied, err := (ThreatFloor{Findings: fp}).Evaluate(context.Background(), phish)
	require.NoError(t, err)
	require.True(t, applied, "an uncorroborated DNS observation must emit a ceiling")
	require.Zero(t, f.Floor, "capping must never also lift")
	require.Equal(t, ThresholdHigh, f.Ceiling)

	// End-to-end through the scorer: high base severity plus enough resource
	// context to clear the high band lands in pipeline, not high.
	got := Aggregate([]Factor{
		{Source: sourceBaseSeverity, Points: 30},
		{Source: sourceBlastRadius, Points: 25},
		{Source: sourceInternetReach, Points: 20},
		f,
	})
	require.Equal(t, BandPipeline, got.Band)
	require.Equal(t, uint8(ThresholdHigh-1), got.Value)
}

// A KEV page floor outranks the ceiling — capping must never hide a
// known-exploited finding (Aggregate's page-floor exception).
func TestThreatFloor_DNSObservation_CeilingNeverBeatsKEVPageFloor(t *testing.T) {
	phish := finding.Finding{
		ID: "f1", Source: "aws_guardduty", Type: "threat", Severity: finding.SeverityHigh,
		CheckID: "Trojan:EC2/PhishingDomainRequest!DNS", ResourceID: "i-456",
	}
	f, applied, err := (ThreatFloor{Findings: fakeFindings{all: []finding.Finding{phish}}}).
		Evaluate(context.Background(), phish)
	require.NoError(t, err)
	require.True(t, applied)

	got := Aggregate([]Factor{
		{Source: sourceBaseSeverity, Points: 30},
		{Source: sourceKEV, Points: 30, Floor: ThresholdPage},
		f,
	})
	require.Equal(t, BandPage, got.Band)
}

// The ceiling is scoped to the DNS-observation families only. A threat finding
// that simply matches no marker (no '!DNS' suffix, no named noisy family) is
// left entirely alone and keeps its graph-derived score.
func TestThreatFloor_UnmarkedThreatIsNotCapped(t *testing.T) {
	recon := finding.Finding{
		ID: "f1", Source: "aws_guardduty", Type: "threat", Severity: finding.SeverityLow,
		CheckID: "Recon:EC2/PortProbeUnprotectedPort", ResourceID: "i-999",
	}
	fp := fakeFindings{all: []finding.Finding{recon}}

	_, applied, err := (ThreatFloor{Findings: fp}).Evaluate(context.Background(), recon)
	require.NoError(t, err)
	require.False(t, applied, "an unmarked threat family is neither floored nor capped")
}

// Two DNS-observation findings on the same host (both excluded families) do
// NOT corroborate each other — corroboration requires an independently-floored
// distinct threat, not another instance of the same noisy family.
func TestThreatFloor_DNSObservation_SameFamilyPeersDoNotCorroborate(t *testing.T) {
	phish := finding.Finding{
		ID: "f1", Source: "aws_guardduty", Type: "threat", Severity: finding.SeverityHigh,
		CheckID: "Trojan:EC2/PhishingDomainRequest!DNS", ResourceID: "i-789",
	}
	driveby := finding.Finding{
		ID: "f2", Source: "aws_guardduty", Type: "threat", Severity: finding.SeverityHigh,
		CheckID: "Trojan:EC2/DriveBySourceTraffic!DNS", ResourceID: "i-789",
	}
	fp := fakeFindings{all: []finding.Finding{phish, driveby}}

	f, applied, err := (ThreatFloor{Findings: fp}).Evaluate(context.Background(), phish)
	require.NoError(t, err)
	require.True(t, applied)
	require.Zero(t, f.Floor, "two excluded-family findings do not corroborate each other")
	require.Equal(t, ThresholdHigh, f.Ceiling, "and neither escapes the cap")
}

type failingFindings struct{}

func (failingFindings) List(context.Context, finding.Filter) ([]finding.Finding, error) {
	return nil, errors.New("clickhouse: timeout")
}

// A failed corroboration query must not drop the source wholesale: that also
// dropped the uncorroborated-DNS ceiling, letting graph points carry a lone DNS
// lookup into the high band. The ceiling is kept (fail safe) and the source is
// reported unmeasured.
func TestThreatFloor_CorroborationErrorKeepsTheCeiling(t *testing.T) {
	phish := finding.Finding{
		ID: "f1", Source: "aws_guardduty", Type: "threat", Severity: finding.SeverityHigh,
		CheckID: "Trojan:EC2/PhishingDomainRequest!DNS", ResourceID: "i-456",
	}
	f, applied, err := (ThreatFloor{Findings: failingFindings{}}).Evaluate(context.Background(), phish)
	require.Error(t, err)
	require.True(t, applied)
	require.Equal(t, ThresholdHigh, f.Ceiling)
	require.Zero(t, f.Floor)

	svc := NewService(&fakeFindingWriter{}, &fakeSignalRepo{}, []Source{
		fakeSource{name: "graph", factor: Factor{Source: "graph", Points: 90}, applied: true},
		ThreatFloor{Findings: failingFindings{}},
	})
	score, err := svc.Enrich(context.Background(), phish)
	require.NoError(t, err)
	require.Equal(t, BandPipeline, score.Band, "the kept ceiling still caps graph points below high")
	require.Equal(t, []string{sourceThreatFloor}, score.Unmeasured)
}

// GuardDuty families that no marker names fall back to GuardDuty severity:
// critical (AttackSequence:* is its highest-confidence compromise verdict)
// pages, high is actionable. A marker and the severity never add up.
func TestThreatFloor_GuardDutySeverityFallback(t *testing.T) {
	gd := func(id string, sev finding.Severity) finding.Finding {
		return finding.Finding{Source: "aws_guardduty", Type: "threat", CheckID: id, Severity: sev}
	}
	for _, id := range []string{
		"AttackSequence:IAM/CompromisedCredentials", "AttackSequence:S3/CompromisedData",
		"Trojan:EC2/BlackholeTraffic", "UnauthorizedAccess:IAMUser/AnomalousBehavior",
		"Execution:Runtime/ReverseShell", "CredentialAccess:Kubernetes/MaliciousIPCaller",
	} {
		assert.Equal(t, ThresholdPage, threatFloor(gd(id, finding.SeverityCritical)), "critical %s", id)
		assert.Equal(t, ThresholdHigh, threatFloor(gd(id, finding.SeverityHigh)), "high %s", id)
		assert.Zero(t, threatFloor(gd(id, finding.SeverityMedium)), "medium %s", id)

		s := Aggregate([]Factor{{Source: sourceBaseSeverity, Points: 30}, {Source: sourceThreatFloor, Floor: threatFloor(gd(id, finding.SeverityHigh))}})
		assert.True(t, UrgentRegardlessOfReach(s.Factors), "a high GuardDuty threat is reach-independent urgency")
	}
	assert.Equal(t, ThresholdHigh, threatFloor(gd("Backdoor:EC2/C&CActivity.B", finding.SeverityMedium)), "a marker still floors a medium")
	assert.Equal(t, ThresholdPage, threatFloor(gd("Backdoor:EC2/C&CActivity.B", finding.SeverityCritical)), "the higher floor wins, once")
	assert.Zero(t, threatFloor(gd("Trojan:EC2/DNSDataExfiltration!DNS", finding.SeverityCritical)), "the DNS-observation gate still runs first")
	for _, id := range []string{"Policy:IAMUser/RootCredentialUsage", "Policy:S3/BucketBlockPublicAccessDisabled"} {
		assert.Zero(t, threatFloor(gd(id, finding.SeverityHigh)), "Policy: is standing configuration, not compromise: %s", id)
	}
	for _, id := range []string{"Recon:EC2/PortProbeUnprotectedPort", "UnauthorizedAccess:EC2/TorClient"} {
		assert.Equal(t, ThresholdHigh, threatFloor(gd(id, finding.SeverityHigh)), "someone is acting on the resource now: %s", id)
	}
	assert.Zero(t, threatFloor(finding.Finding{Source: "gcp_scc", Type: "threat", CheckID: "x", Severity: finding.SeverityLow}))
}

// Intended side effect of the GuardDuty severity fallback: a marker-less HIGH
// GuardDuty detection on the same host is an independently-floored threat, so
// it corroborates a lone !DNS observation (two distinct GuardDuty verdicts on
// one host are converging evidence). A medium one, or a Policy: finding, has no
// floor and corroborates nothing.
func TestThreatFloor_DNSObservation_CorroboratedBySeverityFloor(t *testing.T) {
	phish := finding.Finding{ID: "f1", Source: "aws_guardduty", Type: "threat", Severity: finding.SeverityHigh,
		CheckID: "Trojan:EC2/PhishingDomainRequest!DNS", ResourceID: "i-789"}
	peer := func(id string, sev finding.Severity) finding.Finding {
		return finding.Finding{ID: "f2", Source: "aws_guardduty", Type: "threat", Severity: sev, CheckID: id, ResourceID: "i-789"}
	}
	floorWith := func(p finding.Finding) int {
		f, _, err := (ThreatFloor{Findings: fakeFindings{all: []finding.Finding{phish, p}}}).Evaluate(context.Background(), phish)
		require.NoError(t, err)
		return f.Floor
	}
	assert.Equal(t, ThresholdHigh, floorWith(peer("Execution:Runtime/ReverseShell", finding.SeverityHigh)))
	assert.Zero(t, floorWith(peer("Execution:Runtime/ReverseShell", finding.SeverityMedium)))
	assert.Zero(t, floorWith(peer("Policy:IAMUser/RootCredentialUsage", finding.SeverityHigh)))
}
