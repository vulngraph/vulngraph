// golden_cases_test.go — the fixtures of the two opt-in LLM golden sets
// (eval_test.go, adjudicate_eval_test.go). They build without the eval tag so
// TestGoldenSetSizesMatchDocs can hold the case counts the README and ADR 038
// state to the real ones.
package reason_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/belief"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/respond"
)

// goldenCase is one fixture: a context pack and what a correct reasoner must do
// with it. Expectation is coarse on purpose — mustObserve / mustAct — so the
// gate flags real regressions without pinning debatable class choices.
type goldenCase struct {
	name        string
	pack        respond.ContextPack
	mustObserve bool // true: the only correct answer is "observe"; false: must NOT be "observe"
	// unmeasured keeps the pack's known-ness flags at their zero value (every
	// lookup failed). Every other case is marked fully measured, so its zero
	// counts read as real zeros.
	unmeasured bool
}

func goldenCases() []goldenCase {
	cases := rawGoldenCases()
	for i := range cases {
		if !cases[i].unmeasured {
			p := &cases[i].pack
			p.Blast.Known, p.Exposure.PeersKnown, p.FactorsKnown, p.Impact.DependentsKnown = true, true, true, true
		}
	}
	return cases
}

func rawGoldenCases() []goldenCase {
	return []goldenCase{
		{
			// Isolated, unprivileged, not internet-facing, nothing reachable, low
			// score — the low-risk, no-exposure case the system prompt says to "observe".
			name: "isolated-unprivileged-lowscore",
			pack: respond.ContextPack{
				Finding: finding.Finding{
					Title: "S3 bucket missing access logging", Source: "cspm",
					Severity: finding.SeverityLow, Type: "misconfiguration",
					ResourceID: "int-only-bucket", ResourceType: "s3_bucket",
					CheckID: "aws-s3-access-logging-disabled", Score: 12, ScoreBand: "monitor",
					Description: "Server access logging is not enabled.",
				},
				Blast:    respond.BlastSummary{Count: 0},
				Exposure: respond.ExposureFlags{InternetFacing: false, Privileged: false},
			},
			mustObserve: true,
		},
		{
			// Internet-facing, privileged, high score, actively-exploited CVE with a
			// wide blast radius — unambiguously a real risk; must act, not observe.
			name: "internet-facing-kev-critical",
			pack: respond.ContextPack{
				Finding: finding.Finding{
					Title: "RCE in exposed API", Source: "supply_chain",
					Severity: finding.SeverityCritical, Type: "vulnerability",
					ResourceID: "prod-web-1", ResourceType: "ec2_instance",
					CheckID: "CVE-2024-9999", Score: 94, ScoreBand: "page",
					KnownExploited: true,
					Description:    "Remote code execution in an internet-facing service.",
				},
				Blast:      respond.BlastSummary{Count: 18, ByType: map[string]int{"ec2_instance": 12, "rds_instance": 6}},
				Exposure:   respond.ExposureFlags{InternetFacing: true, Privileged: true},
				CVE:        &respond.CVEContext{CVEID: "CVE-2024-9999", EPSS: 0.92, EPSSBand: "critical", KEV: true, FixedVersion: "2.1.0"},
				Provenance: respond.Provenance{Environment: "production", Owner: "platform"},
			},
			mustObserve: false,
		},

		{
			// The same KEV CVE shape as kev-cve-not-deployed-not-reachable below,
			// but every graph lookup failed: blast radius, peer findings (so
			// exposure) and dependents are unknown, not empty. Unknown is not
			// clean, so observe is wrong — a human has to look.
			name: "kev-cve-graph-unknown",
			pack: respond.ContextPack{
				Finding: finding.Finding{
					Title: "KEV CVE in a dependency", Source: "supply_chain",
					Severity: finding.SeverityCritical, Type: "vulnerability",
					ResourceID: "pkg:golang/example/[email protected]", ResourceType: "package",
					CheckID: "CVE-2023-1111", Score: 22, ScoreBand: "monitor", KnownExploited: true,
					Description: "Known-exploited CVE in a package dependency.",
				},
				CVE:        &respond.CVEContext{CVEID: "CVE-2023-1111", EPSS: 0.4, EPSSBand: "medium", KEV: true},
				Provenance: respond.Provenance{Environment: "production", Owner: "platform"},
			},
			mustObserve: false,
			unmeasured:  true,
		},

		// ── low-risk, no meaningful exposure: the only correct answer is observe ──
		{
			// The flagship deployed-vs-installed case: a KEV CVE on a package that is
			// present but NOT reachable — no internet path, empty blast radius, not
			// privileged. Severity is scary but context says it can't be exploited here.
			name: "kev-cve-not-deployed-not-reachable",
			pack: respond.ContextPack{
				Finding: finding.Finding{
					Title: "KEV CVE in unused transitive dependency", Source: "supply_chain",
					Severity: finding.SeverityCritical, Type: "vulnerability",
					ResourceID: "pkg:golang/example/[email protected]", ResourceType: "package",
					CheckID: "CVE-2023-1111", Score: 22, ScoreBand: "monitor", KnownExploited: true,
					Description: "Known-exploited CVE, but the package is in the SBOM only — no running workload loads it.",
				},
				Blast:      respond.BlastSummary{Count: 0},
				Exposure:   respond.ExposureFlags{InternetFacing: false, Privileged: false},
				CVE:        &respond.CVEContext{CVEID: "CVE-2023-1111", EPSS: 0.4, EPSSBand: "medium", KEV: true},
				Provenance: respond.Provenance{Environment: "production", Owner: "platform"},
			},
			mustObserve: true,
		},
		{
			// Medium EPSS but the asset is not internet-facing, not privileged, and
			// reaches nothing — not exploitable in place. Observe.
			name: "medium-epss-isolated-not-reachable",
			pack: respond.ContextPack{
				Finding: finding.Finding{
					Title: "Vulnerable library on internal batch host", Source: "supply_chain",
					Severity: finding.SeverityMedium, Type: "vulnerability",
					ResourceID: "internal-batch-3", ResourceType: "ec2_instance",
					CheckID: "CVE-2022-2222", Score: 34, ScoreBand: "monitor",
					Description: "Medium-severity CVE on an isolated internal host with no reachable neighbours.",
				},
				Blast:      respond.BlastSummary{Count: 0},
				Exposure:   respond.ExposureFlags{InternetFacing: false, Privileged: false},
				CVE:        &respond.CVEContext{CVEID: "CVE-2022-2222", EPSS: 0.35, EPSSBand: "medium", KEV: false},
				Provenance: respond.Provenance{Environment: "production", Owner: "data"},
			},
			mustObserve: true,
		},
		{
			// Dev-environment hygiene finding, low score, no exposure, no blast — noise.
			name: "dev-hygiene-lowscore-isolated",
			pack: respond.ContextPack{
				Finding: finding.Finding{
					Title: "Security group description missing", Source: "cspm",
					Severity: finding.SeverityLow, Type: "misconfiguration",
					ResourceID: "dev-sg-42", ResourceType: "security_group",
					CheckID: "aws-sg-no-description", Score: 9, ScoreBand: "monitor",
					Description: "Cosmetic hygiene finding in a development account.",
				},
				Blast:      respond.BlastSummary{Count: 0},
				Exposure:   respond.ExposureFlags{InternetFacing: false, Privileged: false},
				Provenance: respond.Provenance{Environment: "development", Owner: "sandbox"},
			},
			mustObserve: true,
		},
		{
			// Info-severity misconfig, isolated, unprivileged — observe.
			name: "info-misconfig-isolated",
			pack: respond.ContextPack{
				Finding: finding.Finding{
					Title: "S3 bucket versioning disabled", Source: "cspm",
					Severity: finding.SeverityLow, Type: "misconfiguration",
					ResourceID: "logs-archive-bucket", ResourceType: "s3_bucket",
					CheckID: "aws-s3-versioning-disabled", Score: 8, ScoreBand: "monitor",
					Description: "Versioning is disabled on an internal, non-sensitive log-archive bucket.",
				},
				Blast:      respond.BlastSummary{Count: 0},
				Exposure:   respond.ExposureFlags{InternetFacing: false, Privileged: false},
				Provenance: respond.Provenance{Environment: "production", Owner: "platform"},
			},
			mustObserve: true,
		},

		// ── unambiguous real risks: must act, not observe ────────────────────────
		{
			// Publicly-accessible production database with a KEV CVE — clear act.
			name: "public-rds-kev-prod",
			pack: respond.ContextPack{
				Finding: finding.Finding{
					Title: "Publicly accessible RDS with exploited CVE", Source: "supply_chain",
					Severity: finding.SeverityCritical, Type: "vulnerability",
					ResourceID: "prod-db-main", ResourceType: "rds_instance",
					CheckID: "CVE-2024-8888", Score: 91, ScoreBand: "page", KnownExploited: true,
					Description: "Internet-reachable production database affected by an actively-exploited CVE.",
				},
				Blast:      respond.BlastSummary{Count: 7, ByType: map[string]int{"rds_instance": 1, "ec2_instance": 6}},
				Exposure:   respond.ExposureFlags{InternetFacing: true, Privileged: false},
				CVE:        &respond.CVEContext{CVEID: "CVE-2024-8888", EPSS: 0.88, EPSSBand: "critical", KEV: true, FixedVersion: "14.11"},
				Provenance: respond.Provenance{Environment: "production", Owner: "data"},
			},
			mustObserve: false,
		},
		{
			// Exposed secret on a production, internet-facing host — must act (rotate/isolate).
			name: "exposed-secret-prod-internet",
			pack: respond.ContextPack{
				Finding: finding.Finding{
					Title: "AWS access key exposed in an HTTP response", Source: "nuclei",
					Severity: finding.SeverityHigh, Type: "vulnerability",
					ResourceID: "prod-web-7", ResourceType: "ec2_instance",
					CheckID: "aws-access-key-value", Score: 82, ScoreBand: "page",
					Description: "A live AWS access key is served in an HTTP response from an internet-facing production host.",
				},
				Blast:      respond.BlastSummary{Count: 11, ByType: map[string]int{"ec2_instance": 5, "s3_bucket": 6}},
				Exposure:   respond.ExposureFlags{InternetFacing: true, Privileged: true},
				Provenance: respond.Provenance{Environment: "production", Owner: "platform"},
			},
			mustObserve: false,
		},
		{
			// Internet-facing workload with a privilege-escalation path to admin and a
			// wide blast radius, high score — a real attack path; must act.
			name: "internet-privesc-to-admin",
			pack: respond.ContextPack{
				Finding: finding.Finding{
					Title: "Exposed workload can escalate to admin", Source: "ciem_privesc",
					Severity: finding.SeverityHigh, Type: "ciem_privesc",
					ResourceID: "prod-api-role", ResourceType: "iam_role",
					CheckID: "aws-privesc-01", Score: 88, ScoreBand: "page",
					Description: "An internet-exposed workload's role can escalate to administrator across the account.",
				},
				Blast:      respond.BlastSummary{Count: 25, ByType: map[string]int{"iam_role": 9, "ec2_instance": 10, "s3_bucket": 6}},
				Exposure:   respond.ExposureFlags{InternetFacing: true, Privileged: true},
				Provenance: respond.Provenance{Environment: "production", Owner: "platform"},
			},
			mustObserve: false,
		},
	}
}

type adjCase struct {
	name     string
	in       belief.AdjudicationInput
	mustHold bool // true: verdict MUST be high/critical; false: verdict MUST be medium/low
}

func adjGoldenCases() []adjCase {
	return []adjCase{
		// ── mustHold: genuine criticals must survive scrutiny AT critical ────────
		{
			name: "public-rds-kev-genuinely-exposed",
			in: belief.AdjudicationInput{
				FindingID: "g1", ResourceID: "prod-db-main", Title: "Publicly accessible RDS with actively-exploited CVE",
				RawScore: 94, RawBand: "page",
				Context: "Enriched score: 94 (page)\n" +
					"Exposure: internet_facing=true, privileged=false\n" +
					"Blast radius: 7 reachable asset(s)\n" +
					"Impact: 6 dependents\n" +
					"Exploitability: EPSS=88.0% KEV=true fix=14.11\n",
			},
			mustHold: true,
		},
		{
			name: "internet-facing-privesc-to-admin-wide-blast",
			in: belief.AdjudicationInput{
				FindingID: "g2", ResourceID: "prod-web-1", Title: "Internet-facing host role can escalate to admin",
				RawScore: 90, RawBand: "page",
				Context: "Enriched score: 90 (page)\n" +
					"Must-fix class: must_fix — internet-exposed · active privilege-escalation path · blast radius 25\n" +
					"Exposure: internet_facing=true, privileged=true\n" +
					"Blast radius: 25 reachable asset(s)\n" +
					"Privilege paths: iam:PassRole, sts:AssumeRole to admin\n",
			},
			mustHold: true,
		},

		{
			// An identity's own internet_facing=false does not refute a must-fix
			// claim "assumable from an internet-exposed asset" — that claim is
			// about the SOURCE asset in the trust path. With real blast and no
			// compensating control, this must hold; a demotion citing the
			// identity's own exposure flag is exactly the mistake the
			// identity-scoping rule forbids.
			name: "identity-assumable-from-exposed-source-must-hold",
			in: belief.AdjudicationInput{
				FindingID: "g6", ResourceID: "arn:aws:iam::1:role/deploy", Title: "IAM role allows privilege escalation to admin",
				RawScore: 91, RawBand: "page",
				Context: "Enriched score: 91 (page)\n" +
					"Must-fix class: must_fix — reachability claim (scope: the internet-exposed SOURCE asset in the trust path, NOT this identity): assumable from an internet-exposed asset · active privilege-escalation path · blast radius 18\n" +
					"Exposure: identity_itself_internet_facing=false (identities are never network endpoints — this does NOT contradict reachability via a trust path), privileged=true\n" +
					"Blast radius: 18 reachable asset(s)\n" +
					"Privilege paths: iam:PassRole, sts:AssumeRole to admin\n" +
					"Trust: assumable by the role of internet-exposed EC2 instance prod-web-1 (no MFA, no federation)\n",
			},
			mustHold: true,
		},

		{
			// The absence of a named source asset in the context is a rendering
			// limitation (InternetHops returns only a hop count, never a
			// source-asset identity), not missing evidence — "Must-fix class:
			// elevated" is itself the deterministic BFS's reachability
			// determination. With real, uncontrolled blast (18, over the
			// must-fix threshold), this must hold regardless of the missing name.
			name: "elevated-privesc-no-named-source-asset-large-blast-must-hold",
			in: belief.AdjudicationInput{
				FindingID: "g7", ResourceID: "arn:aws:iam::1:role/lambda-exec", Title: "IAM role allows privilege escalation via lambda:UpdateFunctionCode",
				RawScore: 100, RawBand: "page",
				Context: "Enriched score: 100 (page)\n" +
					"Must-fix class: elevated — reachability claim (scope: the internet-exposed SOURCE asset in the trust path, NOT this identity): assumable from an internet-exposed asset · active privilege-escalation path\n" +
					"Exposure: identity_itself_internet_facing=false (identities are never network endpoints — this does NOT contradict reachability via a trust path), privileged=true\n" +
					"Blast radius: 18 reachable asset(s)\n" +
					"Impact: 6 dependents\n",
			},
			mustHold: true,
		},

		// ── mustDemote: contained / unreachable / mislabeled highs must come down ─
		{
			name: "identity-dead-end-privesc-contained",
			in: belief.AdjudicationInput{
				FindingID: "g3", ResourceID: "arn:aws:iam::1:user/example-user", Title: "IAM user allows privilege escalation",
				RawScore: 100, RawBand: "page",
				Context: "Enriched score: 100 (page)\n" +
					"Must-fix class: elevated — reachability claim (scope: the internet-exposed SOURCE asset in the trust path, NOT this identity): assumable from an internet-exposed asset · active privilege-escalation path\n" +
					"Exposure: identity_itself_internet_facing=false (identities are never network endpoints — this does NOT contradict reachability via a trust path), privileged=true\n" +
					"Blast radius: 1 reachable asset(s)\n" +
					"Impact: dependents=0; nothing routes to or runs as this resource\n",
			},
			mustHold: false,
		},
		{
			name: "privesc-contained-behind-sso-mfa",
			in: belief.AdjudicationInput{
				FindingID: "g4", ResourceID: "arn:aws:iam::1:role/admin", Title: "Role can escalate to administrator",
				RawScore: 92, RawBand: "page",
				Context: "Enriched score: 92 (page)\n" +
					"Must-fix class: controlled — assumption gated by a compensating control (MFA / IdP federation)\n" +
					"Exposure: internet_facing=false, privileged=true\n" +
					"Blast radius: 3 reachable asset(s)\n" +
					"Trust: federated via Okta SSO, MFA required to assume\n",
			},
			mustHold: false,
		},
		{
			name: "high-score-internal-unreachable-small-blast",
			in: belief.AdjudicationInput{
				FindingID: "g5", ResourceID: "internal-batch-3", Title: "Vulnerable library on internal host",
				RawScore: 82, RawBand: "page",
				Context: "Enriched score: 82 (page)\n" +
					"Must-fix class: contained — no internet-reachable attack path — internal/lateral risk only\n" +
					"Exposure: internet_facing=false, privileged=false\n" +
					"Blast radius: 0 reachable asset(s)\n" +
					"Exploitability: EPSS=35.0% KEV=false\n",
			},
			mustHold: false,
		},
		{
			// A network resource labeled directly internet-exposed, but the
			// independent fresh exposed-edge re-query says there is no live edge
			// and internet_facing=false. The direct-exposure claim is
			// corroborated by no independent signal — the model must use the
			// structural contradiction exception and demote.
			name: "direct-exposure-claim-contradicted-by-fresh-edge",
			in: belief.AdjudicationInput{
				FindingID: "g6", ResourceID: "sg-internal-only", Title: "Security group flagged internet-exposed",
				RawScore: 88, RawBand: "page",
				Context: "Enriched score: 88 (page)\n" +
					"Must-fix class: must_fix — internet-exposed · blast radius 9\n" +
					"Exposure: internet_facing=false, privileged=false\n" +
					"Exposed_to_internet edge (fresh graph re-query): present=false\n" +
					"Blast radius: 9 reachable asset(s)\n",
			},
			mustHold: false,
		},
	}
}

// adjMaxMisses is how many adjudicator cases may miss before
// TestAdjudicatorGolden fails: one debatable model call does not flake the
// gate, a regression across several cases does.
const adjMaxMisses = 1

// The README, docs/capabilities.md and ADR 038 state each golden set's size and the adjudicator's
// pass bar; adding or removing a case without updating them fails here.
func TestGoldenSetSizesMatchDocs(t *testing.T) {
	respondN, adjN := len(goldenCases()), len(adjGoldenCases())
	docs := map[string][]string{
		"../../README.md": {
			fmt.Sprintf("two small golden sets (%d and %d cases)", respondN, adjN),
		},
		"../../docs/capabilities.md": {
			fmt.Sprintf("respond set (%d cases)", respondN),
			fmt.Sprintf("adjudicator set (%d cases)", adjN),
			fmt.Sprintf("passes at %d of %d", adjN-adjMaxMisses, adjN),
		},
		"../../docs/adr/038-reasoning-eval-harness.md": {
			fmt.Sprintf("`TestReasoningGolden`** (`eval_test.go`, %d cases)", respondN),
			fmt.Sprintf("`TestAdjudicatorGolden`** (`adjudicate_eval_test.go`, %d cases)", adjN),
			fmt.Sprintf("fails on more than %d miss (`adjMaxMisses`), so it passes at %d of %d", adjMaxMisses, adjN-adjMaxMisses, adjN),
		},
	}
	for path, want := range docs {
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		text := strings.Join(strings.Fields(string(raw)), " ")
		for _, w := range want {
			require.Contains(t, text, w, "%s must state the golden set as it is in the code", path)
		}
	}
}
