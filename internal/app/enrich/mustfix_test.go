package enrich

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestClassifyMustFix(t *testing.T) {
	// A fully-qualifying must-fix input; individual cases tweak one axis.
	full := mustFixInputs{present: true, reachKnown: true, hops: 1, reachable: true, exploitable: true, blast: 10, blastKnown: true}

	tests := []struct {
		name string
		in   mustFixInputs
		want string
	}{
		{"reachable+exploitable+blast+present → must_fix", full, MustFix},
		{"controlled demotes (not KEV)", mut(full, func(i *mustFixInputs) { i.controlled = true }), MustFixControlled},
		{"KEV overrides compensating control", mut(full, func(i *mustFixInputs) { i.controlled = true; i.kev = true }), MustFix},
		{"definitively unreachable → contained", mut(full, func(i *mustFixInputs) { i.reachable = false; i.hops = reachNone }), MustFixContained},
		{"contained wins even with big blast", mustFixInputs{reachKnown: true, reachable: false, exploitable: true, blast: 100, present: true}, MustFixContained},
		// An exploited finding is never demoted for lacking an internet path or
		// for a compensating control: KEV on an internal host is reachable from
		// any foothold, and an active-compromise detection already happened.
		{"KEV + definitively unreachable → elevated, never contained", mustFixInputs{reachKnown: true, reachable: false, exploitable: true, kev: true, present: true}, MustFixElevated},
		{"active threat + unreachable → elevated, never contained", mustFixInputs{reachKnown: true, reachable: false, exploitable: true, activeThreat: true, present: true}, MustFixElevated},
		{"active threat ignores a compensating control", mustFixInputs{controlled: true, exploitable: true, activeThreat: true}, MustFixElevated},
		{"KEV with unknown reach and small blast → elevated, never routine", mustFixInputs{exploitable: true, kev: true, blast: 1, blastKnown: true}, MustFixElevated},
		{"low blast → elevated (reachable+exploitable)", mut(full, func(i *mustFixInputs) { i.blast = 1 }), MustFixElevated},
		{"not present → not must_fix, elevated", mut(full, func(i *mustFixInputs) { i.present = false }), MustFixElevated},
		// Scope boundary — still a scope boundary, now stated explicitly.
		// Reachable but with no positive exploitability evidence (no KEV, no active
		// privesc path) — a plain "S3 bucket is public" or "EC2 has an open security
		// group" — must never earn must_fix/elevated, and it does not: MustFixRoutine
		// ranks below contained and carries no urgency.
		//
		// What changed is the VALUE, not the boundary. "" was doing double
		// duty: enriched-and-unclassifiable findings and never-enriched findings
		// both read as "". A reader (human, UI, or the drift sweep) could not tell
		// "asked, no urgency" from "never asked". A distinct terminal value separates them; the earlier note that
		// ec2_instance findings are "100% '' and that's correct" stays true in
		// substance, they are now 100% routine.
		{"reachable, not exploitable → routine (scope boundary, stated explicitly)", mut(full, func(i *mustFixInputs) { i.exploitable = false }), MustFixRoutine},
		// Unknown reach can never demote (fail-open, so a missing signal cannot
		// manufacture a false "contained"), and without exploitability there is nothing
		// to promote either — so this is the routine terminal, not silence.
		{"reachability unknown, not exploitable → routine", mustFixInputs{present: true}, MustFixRoutine},
		// blastKnown gates the blast axis exactly as reachKnown gates the reach
		// axis: a failed blast walk (blastKnown=false) must never let a leftover
		// or simulated blast count satisfy the threshold, even when every other
		// axis (exploitable) is positive — an unmeasured blast is not evidence.
		{"unmeasured blast never promotes on the blast axis alone", mustFixInputs{exploitable: true, blast: 100, blastKnown: false}, MustFixRoutine},
		// The same inputs with blastKnown=true DO promote on the blast axis alone
		// (no reach evidence needed) — proving the case above is gated on
		// blastKnown, not on some other field accidentally suppressing it.
		{"measured blast alone promotes to elevated", mustFixInputs{exploitable: true, blast: 100, blastKnown: true}, MustFixElevated},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := classifyMustFix(tc.in)
			if got != tc.want {
				t.Fatalf("class = %q, want %q", got, tc.want)
			}
			if got == MustFix && reason == "" {
				t.Error("must_fix should carry an evidence reason")
			}
		})
	}
}

func mut(base mustFixInputs, f func(*mustFixInputs)) mustFixInputs {
	f(&base)
	return base
}

// TestAssessMustFix_K8sPodMisconfigNotExploitable locks in the Phase 3a fix at
// the must-fix layer: k8s-allow-privilege-escalation is no longer treated as an
// IAM privesc finding, so exploitable is false and — even when the graph proves
// the pod reachable with a large blast radius — it can't reach must_fix/elevated
// through the old title-match accident. It lands on the scope-boundary "" like
// any plain reachable misconfiguration with no positive exploitability evidence.
func TestAssessMustFix_K8sPodMisconfigNotExploitable(t *testing.T) {
	f := finding.Finding{
		CheckID: "k8s-allow-privilege-escalation", Title: "Kubernetes Pod allows privilege escalation",
		ResourceType: "k8s_pod", ResourceID: "k8s:pod:default/web",
	}
	seed := asset.Asset{ID: "k8s:pod:default/web", LastSeen: time.Now()}
	class, _ := assessMustFix(context.Background(), f, seed,
		fakeReach{hops: 1, ok: true}, fakeCounter{count: 20}, nil, nil, nil, time.Now())
	if class == MustFix || class == MustFixElevated {
		t.Fatalf("k8s pod misconfig must not reach %q via the privesc accident", class)
	}
}

// TestAssessMustFix_ExploitedOnUnreachableHostIsNeverContained pins the
// "confirmed Low KEV" hole: a KEV CVE (or a page-floored active-compromise
// detection) on a host the graph proves is NOT internet-reachable used to land
// contained, which belief.Reconcile grounds as a confirmed Low and the
// adjudicator treats as decided.
func TestAssessMustFix_ExploitedOnUnreachableHostIsNeverContained(t *testing.T) {
	seed := asset.Asset{ID: "i-internal", Type: "ec2_instance", LastSeen: time.Now()}
	unreachable := fakeReach{hops: reachNone, ok: true}
	for name, f := range map[string]finding.Finding{
		"KEV": {
			Source: "vm_vuln", CheckID: "CVE-2021-44228", KnownExploited: true,
			ResourceType: "ec2_instance", ResourceID: "i-internal",
		},
		"crypto mining": {
			Source: "aws_guardduty", Type: "threat", CheckID: "CryptoCurrency:EC2/BitcoinTool.B",
			ResourceType: "ec2_instance", ResourceID: "i-internal",
		},
		"credential exfiltration": {
			Source: "aws_guardduty", Type: "threat", CheckID: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
			ResourceType: "ec2_instance", ResourceID: "i-internal",
		},
	} {
		t.Run(name, func(t *testing.T) {
			class, reason := assessMustFix(context.Background(), f, seed, unreachable, fakeCounter{count: 1}, nil, nil, nil, time.Now())
			require.Equal(t, MustFixElevated, class)
			require.Contains(t, reason, "not reachable from the internet")
			require.False(t, ReachabilityEvidenced(class, reason),
				"the unreachable disclosure must not read as positive reachability evidence")
		})
	}

	t.Run("an unexploited finding on the same host is still contained", func(t *testing.T) {
		f := finding.Finding{Source: "vm_vuln", CheckID: "CVE-2099-0001", ResourceType: "ec2_instance", ResourceID: "i-internal"}
		class, _ := assessMustFix(context.Background(), f, seed, unreachable, fakeCounter{count: 1}, nil, nil, nil, time.Now())
		require.Equal(t, MustFixContained, class)
	})
}

// TestAssessMustFix_BlastRadiusErrorNeverReadsAsSafe is the degraded-input
// regression guard for the blast axis (CLAUDE.md's "a zero value is not a
// measurement" rule): a BlastRadiusCounter error must leave the blast axis
// unmeasured, not silently 0-and-therefore-below-threshold. Constructed so
// every OTHER must_fix condition is satisfied (reachable, exploitable,
// present) — if the blast error were misread as "blast=0, known", this would
// still correctly land below must_fix on the threshold; asserting elevated
// (not must_fix) and the "unmeasured" reason string is what actually proves
// blastKnown, not blast's zero value, is doing the gating.
func TestAssessMustFix_BlastRadiusErrorNeverReadsAsSafe(t *testing.T) {
	f := finding.Finding{
		CheckID: "aws-privesc-01", Title: "Privilege escalation via iam:PassRole",
		ResourceType: "iam_role", ResourceID: "arn:aws:iam::1:role/deployer",
	}
	seed := asset.Asset{ID: f.ResourceID, Type: "iam_role", LastSeen: time.Now()}
	reach := fakeReach{hops: 1, ok: true}
	blast := fakeCounter{err: errors.New("ladybug: query timeout")}
	class, reason := assessMustFix(context.Background(), f, seed, reach, blast, nil, nil, nil, time.Now())
	if class == MustFix {
		t.Fatalf("must_fix requires a KNOWN blast measurement; got %q from an errored walk", class)
	}
	if !strings.Contains(reason, "unmeasured") {
		t.Errorf("reason should disclose the blast walk failed, got %q", reason)
	}
}

// fakeSupplyChainReach is a scriptable SupplyChainReachProvider for
// assessSupplyChainMustFix's table tests.
type fakeSupplyChainReach struct {
	anyDeployed, anyExposed, truncated bool
	err                                error
	// repo* script RepoDeployExposure independently of the package lookup, so a
	// code-scanning case can't accidentally be satisfied by package scripting.
	repoDeployed, repoExposed, repoTruncated bool
	repoErr                                  error
	fleetCanonical                           bool
	fleetInstances                           int
	fleetErr                                 error
}

func (f fakeSupplyChainReach) PackageDeployExposure(context.Context, string) (bool, bool, bool, error) {
	return f.anyDeployed, f.anyExposed, f.truncated, f.err
}

func (f fakeSupplyChainReach) RepoDeployExposure(context.Context, string) (bool, bool, bool, error) {
	return f.repoDeployed, f.repoExposed, f.repoTruncated, f.repoErr
}

func (f fakeSupplyChainReach) FleetCanonical(context.Context, finding.Finding) (bool, int, error) {
	return f.fleetCanonical, f.fleetInstances, f.fleetErr
}

func pkgFindingForMustFix() finding.Finding {
	return finding.Finding{
		Source: "supply_chain", ResourceType: "package",
		ResourceID: "pkg:golang/golang.org/x/net@0.0.0-20210813160813-60bc85c4be6d",
	}
}

// TestAssessSupplyChainMustFix covers the gap directly: a package finding
// (CVE-2023-44487-shaped) resolves must-fix urgency from the dependent-repo
// deployment traversal instead of the asset-seed lookup, which never resolves
// for a bare package purl.
//
// It also covers the IMAGE path, which is the only one that can resolve for an OS
// package: an apk/deb inside a base image has no dependent repo, so the repo
// traversal alone left every image finding blank, including critical ones.
func TestAssessSupplyChainMustFix(t *testing.T) {
	tests := []struct {
		name       string
		reach      SupplyChainReachProvider
		imgReach   ReachProvider
		wantClass  string
		wantReason bool // reason must be non-empty
	}{
		{
			name:       "deployed to an internet-exposed workload → elevated",
			reach:      fakeSupplyChainReach{anyDeployed: true, anyExposed: true},
			wantClass:  MustFixElevated,
			wantReason: true,
		},
		{
			name:       "deployed but not exposed → contained",
			reach:      fakeSupplyChainReach{anyDeployed: true, anyExposed: false},
			wantClass:  MustFixContained,
			wantReason: true,
		},
		{
			name:      "dependent repos exist but zero deploy edges (template-repo case) → blank",
			reach:     fakeSupplyChainReach{anyDeployed: false, anyExposed: false},
			wantClass: "",
		},
		{
			name:      "no dependent repos at all → blank",
			reach:     fakeSupplyChainReach{anyDeployed: false, anyExposed: false},
			wantClass: "",
		},
		{
			name:      "nil provider → blank, fail-open",
			reach:     nil,
			wantClass: "",
		},
		{
			name:      "lookup error → blank, fail-open, never blocks Enrich",
			reach:     fakeSupplyChainReach{anyDeployed: true, anyExposed: true, err: errors.New("ladybug pool busy")},
			wantClass: "",
		},
		// ── image path: no dependent repo at all, reach comes from the package node ──
		{
			name:       "OS package in an image on an internet-reachable pod → elevated",
			reach:      fakeSupplyChainReach{anyDeployed: false},
			imgReach:   fakeReach{hops: 2, ok: true},
			wantClass:  MustFixElevated,
			wantReason: true,
		},
		{
			name:       "image reach known but beyond the must-fix hop budget → contained",
			reach:      fakeSupplyChainReach{anyDeployed: false},
			imgReach:   fakeReach{hops: maxMustFixHops + 1, ok: true},
			wantClass:  MustFixContained,
			wantReason: true,
		},
		{
			name:       "directly exposed workload (0 hops) → elevated",
			reach:      nil,
			imgReach:   fakeReach{hops: 0, ok: true},
			wantClass:  MustFixElevated,
			wantReason: true,
		},
		{
			name:      "image reach unknown and no dependent repo → blank, fail-open",
			reach:     fakeSupplyChainReach{anyDeployed: false},
			imgReach:  fakeReach{ok: false},
			wantClass: "",
		},
		{
			name:      "image reach lookup error → blank, never guesses",
			reach:     nil,
			imgReach:  fakeReach{hops: 0, ok: true, err: errors.New("graph not ready")},
			wantClass: "",
		},
		// ── VM fleet dedupe: the per-fleet vm_vuln findings own VM-only packages ──
		{
			name:       "VM-only package carried by fleet findings → routine, even on an exposed host",
			reach:      fakeSupplyChainReach{fleetCanonical: true, fleetInstances: 3},
			imgReach:   fakeReach{hops: 0, ok: true},
			wantClass:  MustFixRoutine,
			wantReason: true,
		},
		{
			name:       "fleet check fails → the package keeps its own evidence",
			reach:      fakeSupplyChainReach{fleetCanonical: true, fleetErr: errors.New("ch down")},
			imgReach:   fakeReach{hops: 0, ok: true},
			wantClass:  MustFixElevated,
			wantReason: true,
		},
		{
			name:       "not fleet-canonical (an image also runs it) → normal evaluation",
			reach:      fakeSupplyChainReach{},
			imgReach:   fakeReach{hops: 1, ok: true},
			wantClass:  MustFixElevated,
			wantReason: true,
		},
		{
			name:       "image path exposed wins over a contained repo verdict",
			reach:      fakeSupplyChainReach{anyDeployed: true, anyExposed: false},
			imgReach:   fakeReach{hops: 1, ok: true},
			wantClass:  MustFixElevated,
			wantReason: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			class, reason := assessSupplyChainMustFix(context.Background(), pkgFindingForMustFix(), tc.reach, tc.imgReach)
			if class != tc.wantClass {
				t.Fatalf("class = %q, want %q", class, tc.wantClass)
			}
			if tc.wantReason && reason == "" {
				t.Error("expected a non-empty evidence reason")
			}
			if !tc.wantReason && reason != "" {
				t.Errorf("expected empty reason, got %q", reason)
			}
		})
	}
}

func malFindingForMustFix() finding.Finding {
	f := pkgFindingForMustFix()
	f.CheckID = "MAL-2026-11524"
	return f
}

// TestAssessSupplyChainMustFix_MaliciousPackage covers the category-error fix
// directly: a MAL-* (OpenSSF malicious-packages) advisory must always resolve
// to MustFixElevated, regardless of deployment/exposure state — its payload
// already ran at install/build time, so the deploy-exposure switch that
// correctly gates an ordinary CVE must never apply to it. In particular the
// "deployed but not exposed" case must NOT become MustFixContained, which is
// exactly the behavior TestAssessSupplyChainMustFix pins for an ordinary CVE
// with the identical reach inputs — this test is the regression guard that
// the two classes stay divergent.
func TestAssessSupplyChainMustFix_MaliciousPackage(t *testing.T) {
	tests := []struct {
		name  string
		reach SupplyChainReachProvider
	}{
		{"not deployed at all", fakeSupplyChainReach{anyDeployed: false, anyExposed: false}},
		{"deployed but not exposed", fakeSupplyChainReach{anyDeployed: true, anyExposed: false}},
		{"deployed and exposed", fakeSupplyChainReach{anyDeployed: true, anyExposed: true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			class, reason := assessSupplyChainMustFix(context.Background(), malFindingForMustFix(), tc.reach, nil)
			if class != MustFixElevated {
				t.Fatalf("class = %q, want %q (malicious packages must never be demoted by reachability)", class, MustFixElevated)
			}
			if reason == "" {
				t.Error("expected a non-empty evidence reason")
			}
		})
	}
}

// TestIsMaliciousPackage pins the exact gating: both the CheckID prefix AND
// isSupplyChainPackage must hold, so an unrelated finding whose CheckID
// happens to start with "MAL-" from some other source can never match.
func TestIsMaliciousPackage(t *testing.T) {
	tests := []struct {
		name string
		f    finding.Finding
		want bool
	}{
		{"supply-chain package with MAL- checkID", malFindingForMustFix(), true},
		{"supply-chain package with ordinary CVE checkID", pkgFindingForMustFix(), false},
		{"non-supply-chain finding with MAL- checkID", finding.Finding{Source: "nuclei", ResourceType: "http_service", CheckID: "MAL-2026-11524"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isMaliciousPackage(tc.f); got != tc.want {
				t.Errorf("isMaliciousPackage() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAssessMustFix_SupplyChainRoutesAroundSeedPath confirms assessMustFix
// dispatches supply_chain/package findings to the traversal-based path instead
// of the normal seed-based one, even when seed is the zero value (as it always
// is for a package purl — never a graph.assets row).
func TestAssessMustFix_SupplyChainRoutesAroundSeedPath(t *testing.T) {
	f := pkgFindingForMustFix()
	class, reason := assessMustFix(context.Background(), f, asset.Asset{},
		nil, nil, fakeSupplyChainReach{anyDeployed: true, anyExposed: true}, nil, nil, time.Now())
	if class != MustFixElevated {
		t.Fatalf("class = %q, want %q", class, MustFixElevated)
	}
	if reason == "" {
		t.Error("expected a non-empty evidence reason")
	}
}

func ghasSecretFinding(checkID string) finding.Finding {
	return finding.Finding{
		Source: "ghas_secrets", ResourceType: "github_repo",
		ResourceID: "example/widgets", CheckID: checkID,
	}
}

// ghasSecretFindingWithValidity is ghasSecretFinding carrying GitHub's
// validity verdict ("" = none reported).
func ghasSecretFindingWithValidity(checkID, validity string) finding.Finding {
	f := ghasSecretFinding(checkID)
	if validity != "" {
		f.Metadata = map[string]string{finding.SecretValidityKey: validity}
	}
	return f
}

// TestAssessGHASSecretsMustFix covers the gap directly: a ghas_secrets
// finding resolves a real github_repo asset
// but must_fix_class was blank because
// assessMustFix ran the network-reachability BFS path for it. The repo's
// visibility metadata — collected already, unused until now — is the fix.
func TestAssessGHASSecretsMustFix(t *testing.T) {
	tests := []struct {
		name       string
		checkID    string
		validity   string
		visibility string
		wantClass  string
	}{
		{"public repo, validity active → must_fix (no reach or blast needed)", "stripe_secret_key", "active", "public", MustFix},
		{"public repo, validity unknown → must_fix, unknown is never safe", "stripe_secret_key", "unknown", "public", MustFix},
		{"public repo, no validity reported → must_fix, unknown is never safe", "aws_secret_access_key", "", "public", MustFix},
		{"public repo, validity inactive → contained", "stripe_secret_key", "inactive", "public", MustFixContained},
		{"public repo, test-mode credential → contained (demoted)", "stripe_test_secret_key", "", "public", MustFixContained},
		{"public repo, test-mode credential even when active → contained", "stripe_test_secret_key", "active", "public", MustFixContained},
		{"private repo, validity active → elevated, never contained", "stripe_secret_key", "active", "private", MustFixElevated},
		{"private repo, no validity → elevated", "stripe_secret_key", "", "private", MustFixElevated},
		{"private repo, validity inactive → contained", "stripe_secret_key", "inactive", "private", MustFixContained},
		{"private repo, test-mode credential → contained", "stripe_test_secret_key", "", "private", MustFixContained},
		{"unknown visibility (missing metadata) → blank, fail-open", "stripe_secret_key", "active", "", ""},
		{"internal (enterprise-wide) repo, validity active → elevated, at least as strict as private", "stripe_secret_key", "active", "internal", MustFixElevated},
		{"internal repo, no validity → elevated", "stripe_secret_key", "", "internal", MustFixElevated},
		{"internal repo, test-mode credential → contained", "stripe_test_secret_key", "", "internal", MustFixContained},
		{"garbage visibility value → blank, fail-open", "stripe_secret_key", "", "not-a-visibility", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			seed := asset.Asset{Metadata: map[string]string{}}
			if tc.visibility != "" {
				seed.Metadata["visibility"] = tc.visibility
			}
			class, reason := assessGHASSecretsMustFix(ghasSecretFindingWithValidity(tc.checkID, tc.validity), seed)
			if class != tc.wantClass {
				t.Fatalf("class = %q, want %q", class, tc.wantClass)
			}
			if tc.wantClass != "" && reason == "" {
				t.Error("expected a non-empty evidence reason")
			}
			if tc.wantClass == "" && reason != "" {
				t.Errorf("expected empty reason, got %q", reason)
			}
			if ReachabilityEvidenced(class, reason) {
				t.Errorf("a leaked secret carries no network-reachability evidence, but reason %q reads as one", reason)
			}
			// "live" and "working key" are claims only GitHub's validity check
			// can back: a key with no active verdict must never be described so.
			if tc.validity != "active" {
				for _, claim := range []string{"live credential exposed", "working key", "works from anywhere"} {
					if strings.Contains(reason, claim) {
						t.Errorf("validity %q, but reason %q claims %q", tc.validity, reason, claim)
					}
				}
			}
		})
	}
}

// TestAssessMustFix_GHASSecretsRoutesAroundReachPath confirms assessMustFix
// dispatches ghas_secrets findings to the visibility-based path instead of
// calling the network-reachability BFS — a nil ReachProvider must not block
// classification, since the general reach/blast path is never consulted here.
func TestAssessMustFix_GHASSecretsRoutesAroundReachPath(t *testing.T) {
	f := ghasSecretFinding("stripe_secret_key")
	seed := asset.Asset{Metadata: map[string]string{"visibility": "public"}}
	class, reason := assessMustFix(context.Background(), f, seed, nil, nil, nil, nil, nil, time.Now())
	if class != MustFix {
		t.Fatalf("class = %q, want %q", class, MustFix)
	}
	if reason == "" {
		t.Error("expected a non-empty evidence reason")
	}
}

func ghasCodeScanningFinding() finding.Finding {
	return finding.Finding{
		Source: "ghas_code_scanning", ResourceType: "github_repo",
		ResourceID: "example-org/notify-server", Severity: finding.SeverityHigh,
	}
}

// TestAssessGHASCodeScanningMustFix pins the tier mapping: a SAST alert is judged
// on where its code RUNS (deploys_to lineage), never on the repo's own network
// reachability.
func TestAssessGHASCodeScanningMustFix(t *testing.T) {
	tests := []struct {
		name      string
		reach     SupplyChainReachProvider
		wantClass string
	}{
		{
			"code deployed to an internet-exposed workload → elevated",
			fakeSupplyChainReach{repoDeployed: true, repoExposed: true}, MustFixElevated,
		},
		{
			"code deployed but no exposed workload → contained",
			fakeSupplyChainReach{repoDeployed: true, repoExposed: false}, MustFixContained,
		},
		{
			"no deploys_to lineage (most prod repos) → blank, fail-open",
			fakeSupplyChainReach{repoDeployed: false}, "",
		},
		{
			"lineage lookup error → blank, never guesses",
			fakeSupplyChainReach{repoDeployed: true, repoExposed: true, repoErr: errors.New("ladybug pool busy")}, "",
		},
		{"nil provider → blank, fail-open", nil, ""},
		{
			"package scripting must not leak into the repo path",
			fakeSupplyChainReach{anyDeployed: true, anyExposed: true}, "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			class, reason := assessGHASCodeScanningMustFix(context.Background(), ghasCodeScanningFinding(), tc.reach)
			if class != tc.wantClass {
				t.Fatalf("class = %q, want %q", class, tc.wantClass)
			}
			if tc.wantClass != "" && reason == "" {
				t.Error("expected a non-empty evidence reason")
			}
			if tc.wantClass == "" && reason != "" {
				t.Errorf("expected empty reason, got %q", reason)
			}
		})
	}
}

// TestAssessMustFix_CodeScanningNeverNetworkContained is the regression guard for
// a defect where code-scanning findings, including critical and high
// severity, were stamped MustFixContained with "no
// internet-reachable attack path" purely because the internet-hops BFS resolved
// the github_repo as not-reachable.
// A repo is not a network node; that verdict must never be reachable from this
// source again, whatever the BFS says.
func TestAssessMustFix_CodeScanningNeverNetworkContained(t *testing.T) {
	f := ghasCodeScanningFinding()
	seed := asset.Asset{ID: f.ResourceID, Type: "github_repo", LastSeen: time.Now()}
	// A reach provider that positively reports "known, and far beyond the hop
	// budget" — precisely what produced the false contained.
	reach := fakeReach{hops: maxMustFixHops + 10, ok: true}
	class, reason := assessMustFix(context.Background(), f, seed, reach, nil, nil, nil, nil, time.Now())
	if class == MustFixContained {
		t.Fatalf("code-scanning finding classified %q via the network-reach path: %q", class, reason)
	}
	if class != "" {
		t.Fatalf("class = %q, want blank (no deployment lineage available)", class)
	}
	if strings.Contains(reason, "internet-reachable attack path") {
		t.Errorf("network-reachability reason leaked onto a repo finding: %q", reason)
	}
}

// TestAssessMustFix_CodeScanningRoutesToDeploymentLineage confirms the dispatch
// reaches the new path and that a positive lineage still classifies.
func TestAssessMustFix_CodeScanningRoutesToDeploymentLineage(t *testing.T) {
	f := ghasCodeScanningFinding()
	seed := asset.Asset{ID: f.ResourceID, Type: "github_repo", LastSeen: time.Now()}
	reach := fakeReach{hops: maxMustFixHops + 10, ok: true}
	scReach := fakeSupplyChainReach{repoDeployed: true, repoExposed: true}
	class, reason := assessMustFix(context.Background(), f, seed, reach, nil, scReach, nil, nil, time.Now())
	if class != MustFixElevated {
		t.Fatalf("class = %q (%q), want %q", class, reason, MustFixElevated)
	}
}

// TestAssessMustFix_NonNetworkResourceNeverReachDemoted is the regression guard
// for a Ladybug-loading-set defect: ecr_repository was synced into Ladybug
// purely to seed repository-policy-public exposure edges, has no
// assessXMustFix dedicated path (unlike supply-chain/ghas_secrets/
// ghas_code_scanning/k8s-rbac), and so fell into the general reach path once it
// became "known" to InternetHops — reading its edgeless-node absence of data as
// positive unreachability evidence, the same category error already fixed once
// for ghas_code_scanning. aws-ecr-mutable-image-tags and
// aws-ecr-scanning-disabled findings wrongly landed on MustFixContained. ecr_repository is deliberately NOT in
// IsNetworkReachableResource (it isn't a network-addressable node) and is not
// an identity either, so assessMustFix must never call reach.InternetHops for
// it at all — any future type added to Ladybug's sync set for an unrelated edge
// gets the same protection for free, not just ECR.
func TestAssessMustFix_NonNetworkResourceNeverReachDemoted(t *testing.T) {
	f := finding.Finding{
		CheckID: "aws-ecr-mutable-image-tags", Title: "ECR repository allows mutable image tags",
		ResourceType: "ecr_repository", ResourceID: "arn:aws:ecr:us-east-1:1:repository/app",
	}
	seed := asset.Asset{ID: f.ResourceID, Type: "ecr_repository", LastSeen: time.Now()}
	// A reach provider that positively reports "known, and beyond the hop
	// budget" — exactly what an edgeless node resolves to, and exactly what
	// produced the false contained verdict.
	reach := fakeReach{hops: maxMustFixHops + 10, ok: true}
	class, reason := assessMustFix(context.Background(), f, seed, reach, nil, nil, nil, nil, time.Now())
	if class == MustFixContained {
		t.Fatalf("ecr_repository finding classified %q via the network-reach path: %q", class, reason)
	}
	if strings.Contains(reason, "internet-reachable attack path") {
		t.Errorf("network-reachability reason leaked onto a non-network resource: %q", reason)
	}
}

// The grounding fix: an identity (IAM user/role, GCP SA) is a principal, not a
// network endpoint, so the reason must never claim "internet-exposed" — the false
// label that inflated identity findings before the grounding fix.
func TestMustFixReason_IdentityNeverInternetExposed(t *testing.T) {
	tests := []struct {
		name         string
		in           mustFixInputs
		wantContains string
		wantAbsent   string
	}{
		{
			"identity at 0 hops is not 'internet-exposed'",
			mustFixInputs{reachKnown: true, reachable: true, hops: 0, exploitable: true, identity: true},
			"assumable from an internet-exposed asset", "internet-exposed ",
		},
		{
			"identity with a path frames it as reachable-from, not exposed",
			mustFixInputs{reachKnown: true, reachable: true, hops: 2, exploitable: true, identity: true},
			"reachable from an internet-exposed asset (2 hops)", "internet-exposed·",
		},
		{
			"network resource at 0 hops keeps 'internet-exposed'",
			mustFixInputs{reachKnown: true, reachable: true, hops: 0, exploitable: true, identity: false},
			"internet-exposed", "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := mustFixReason(tc.in)
			if !strings.Contains(r, tc.wantContains) {
				t.Fatalf("reason %q does not contain %q", r, tc.wantContains)
			}
			// The identity cases must never assert the resource itself is internet-exposed.
			if tc.in.identity && strings.Contains(r, "internet-exposed ·") {
				t.Fatalf("identity reason falsely claims internet-exposed: %q", r)
			}
		})
	}
}

// ReachabilityEvidenced fires only on must_fix/elevated whose reason carries a
// positive reachability phrase — never on contained/controlled, never on
// exploitability/blast-only reasons. It is the conservative trigger for the
// adjudicator's corroboration gate.
func TestReachabilityEvidenced(t *testing.T) {
	tests := []struct {
		name   string
		class  string
		reason string
		want   bool
	}{
		{"must_fix internet-exposed", MustFix, "internet-exposed · known-exploited (KEV) · blast radius 12", true},
		{"must_fix identity assumable", MustFix, "assumable from an internet-exposed asset · blast radius 18", true},
		{"elevated reachable hops", MustFixElevated, "internet-reachable (2 hops) · active privilege-escalation path", true},
		{"elevated identity hops", MustFixElevated, "reachable from an internet-exposed asset (1 hops)", true},
		{"elevated exploit+blast only — no reach evidence", MustFixElevated, "active privilege-escalation path · blast radius 9", false},
		{"contained never fires", MustFixContained, "no internet-reachable attack path — internal/lateral risk only", false},
		{"controlled never fires", MustFixControlled, "privilege-escalation path gated by an observed compensating control (MFA-required or non-admin SSO role assumption, or an inactive or MFA-gated keyless user)", false},
		{"empty class", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ReachabilityEvidenced(tt.class, tt.reason); got != tt.want {
				t.Fatalf("ReachabilityEvidenced(%q, %q) = %t, want %t", tt.class, tt.reason, got, tt.want)
			}
		})
	}
}

func TestIsControlled(t *testing.T) {
	ctx := context.Background()
	privesc := finding.Finding{CheckID: "aws-privesc-15"}
	nonPrivesc := finding.Finding{CheckID: "aws-s3-public-bucket"}

	role := func(md map[string]string) asset.Asset {
		return asset.Asset{Type: "iam_role", Metadata: md}
	}
	user := func(md map[string]string) asset.Asset {
		return asset.Asset{Type: "iam_user", Metadata: md}
	}

	nonAdminSSO := fakeSSO{info: SSOInfo{GrantsAdmin: false}, ok: true}

	// Non-privesc is never controlled.
	require.False(t, isControlled(ctx, role(map[string]string{"federated_trust": "saml"}), nonPrivesc, nonAdminSSO))

	// The ONE surviving metadata-only control: MFA required by the trust policy.
	require.True(t, isControlled(ctx, role(map[string]string{"mfa_required_to_assume": "true"}), privesc, nil))
	require.False(t, isControlled(ctx, role(map[string]string{}), privesc, nil))

	// trust_entry "service" is NOT a compensating control. It says only an AWS
	// service can assume the role — the definition of a workload role, and exactly
	// the credential an attacker gets for free after SSRF/RCE on that workload.
	// This single disjunct would mark as "controlled" privesc findings on, e.g.,
	// an admin role attached to internet-exposed EC2 instances running IMDSv1.
	require.False(t, isControlled(ctx, role(map[string]string{"trust_entry": "service"}), privesc, nil),
		"a service-only trust policy is a workload role, not a gate on it")

	// Machine OIDC (GitHub Actions, EKS IRSA) involves no human and no MFA.
	require.False(t, isControlled(ctx, role(map[string]string{"federated_trust": "oidc"}), privesc, nil),
		"machine OIDC federation is not a compensating control")
	require.False(t, isControlled(ctx, role(map[string]string{"federated_trust": "oidc"}), privesc, nonAdminSSO),
		"the SSO corroboration applies to SAML only, never to machine OIDC")

	// SAML demotes ONLY when corroborated by a collected, non-admin SSO permission
	// set. Unresolved (no connector, stale collector) must never demote: with no
	// collected human_identity assets, an unobserved IdP is absence of evidence.
	require.False(t, isControlled(ctx, role(map[string]string{"federated_trust": "saml"}), privesc, nil),
		"absence of evidence never demotes — an uncorroborated SAML claim is not an observed control")
	require.True(t, isControlled(ctx, role(map[string]string{"federated_trust": "saml"}), privesc, nonAdminSSO))

	// SSO admin permission set is an anti-control — NOT controlled.
	adminSSO := fakeSSO{info: SSOInfo{GrantsAdmin: true}, ok: true}
	require.False(t, isControlled(ctx, role(map[string]string{"federated_trust": "saml"}), privesc, adminSSO))
	require.False(t, isControlled(ctx, role(map[string]string{"mfa_required_to_assume": "true"}), privesc, adminSSO),
		"an admin SSO grant outranks even an MFA-required trust policy")

	// iam_user: demote only on positively-present controls.
	require.True(t, isControlled(ctx, user(map[string]string{"inactive": "true"}), privesc, nil))
	require.True(t, isControlled(ctx, user(map[string]string{"mfa_enabled": "true", "active_key_count": "0"}), privesc, nil))
	require.False(t, isControlled(ctx, user(map[string]string{"mfa_enabled": "true", "active_key_count": "2"}), privesc, nil),
		"an MFA console user WITH a standalone access key can bypass MFA — not controlled")
	require.False(t, isControlled(ctx, user(map[string]string{}), privesc, nil), "absence of evidence never demotes")
	// The collector omits active_key_count when ListAccessKeys fails: an
	// unread key count is not "no keys".
	require.False(t, isControlled(ctx, user(map[string]string{"mfa_enabled": "true"}), privesc, nil),
		"a missing active_key_count must never read as zero keys")
	require.False(t, isControlled(ctx, user(map[string]string{"mfa_enabled": "true", "active_key_count": "garbage"}), privesc, nil))
}

// Network unreachability must NOT demote an identity finding to contained.
//
// A principal is never itself on the internet — IsIdentityResource's own doc
// comment says so — and privilege escalation through it is a cloud control-plane
// API call that needs no internet path: creating a service-account key, calling
// actAs, setting project metadata. An insider or one leaked credential anywhere in
// the org is enough. gcp-privesc findings on gcp_service_account were being
// suppressed to MustFixContained with the reason
// "no internet-reachable attack path". The
// `identity` input was computed and read only for the display string, never by the
// gate — a dead field, not a policy decision.
func TestClassifyMustFix_IdentityNotDemotedByNetworkUnreachability(t *testing.T) {
	identityUnreachable := mustFixInputs{
		identity:    true,
		reachKnown:  true,
		reachable:   false,
		exploitable: true,
		blast:       mustFixBlastThreshold,
		present:     true,
	}
	class, reason := classifyMustFix(identityUnreachable)
	require.NotEqual(t, MustFixContained, class,
		"a service account's privesc path does not require an internet route; got reason %q", reason)

	// A genuine network resource with no internet path IS correctly contained —
	// the fix must not disable the gate wholesale.
	networkUnreachable := identityUnreachable
	networkUnreachable.identity = false
	class, reason = classifyMustFix(networkUnreachable)
	require.Equal(t, MustFixContained, class,
		"an unreachable network resource is still contained")
	require.Contains(t, reason, "no internet-reachable attack path")

	// A compensating control still demotes an identity — that gate is about how
	// hard the principal is to assume, which does apply.
	controlledIdentity := identityUnreachable
	controlledIdentity.controlled = true
	class, _ = classifyMustFix(controlledIdentity)
	require.Equal(t, MustFixControlled, class,
		"MFA/IdP gating is a real compensating control for an identity")
}

// classifyMustFixPin is a checksum over classifyMustFix's ENTIRE decision table.
// It exists because the classifier's behaviour and the enrich fingerprint version
// (internal/app/enrichcache.Fingerprint) must change together: the change gate
// skips re-enriching a finding whose INPUTS are unchanged, so a pure
// classifier change reaches the standing corpus only if the fingerprint version
// is bumped to invalidate the cache.
//
// Without the pin the coupling is only documented: a classifier change shipped
// without a bump leaves open findings serving their old class while the
// classifier is right, so the product shows the old answer.
//
// Same idiom as graphstore's SchemaDDLChecksum: a deliberate pin, not a
// behavioural assertion. When this fails, decide which happened:
//   - intended semantics change → bump enrichcache.LogicVersion AND update this
//     constant;
//   - unintended → you just changed the classifier by accident; fix the code.
const classifyMustFixPin = "386525eac46e9e0aeb1f4fda341a7c8a90ea75d5bc2ca962dea122d718f8c74a"

func TestClassifyMustFixDecisionTableIsPinned(t *testing.T) {
	bools := []bool{false, true}
	// hops covers each branch of the reach switch plus the reachNone sentinel and
	// an out-of-domain value; blast straddles mustFixBlastThreshold.
	hopsSet := []int{-1, 0, 1, 2, 3, 4}
	blastSet := []int{0, 4, 5, 50}

	var b strings.Builder
	cases := 0
	for _, present := range bools {
		for _, reachKnown := range bools {
			for _, reachable := range bools {
				for _, exploitable := range bools {
					for _, controlled := range bools {
						for _, kev := range bools {
							for _, activeThreat := range bools {
								for _, identity := range bools {
									for _, blastKnown := range bools {
										for _, hops := range hopsSet {
											for _, blast := range blastSet {
												in := mustFixInputs{
													present: present, reachKnown: reachKnown, hops: hops,
													reachable: reachable, exploitable: exploitable, blast: blast,
													blastKnown: blastKnown,
													controlled: controlled, kev: kev, identity: identity,
													activeThreat: activeThreat,
												}
												class, reason := classifyMustFix(in)
												fmt.Fprintf(&b, "%v|%s|%s\n", in, class, reason)
												cases++
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	sum := sha256.Sum256([]byte(b.String()))
	got := hex.EncodeToString(sum[:])

	require.Equal(t, 12288, cases, "decision-table coverage changed — did mustFixInputs gain a field?")
	require.Equal(t, classifyMustFixPin, got,
		"classifyMustFix's decision table changed.\n"+
			"If that was INTENDED: bump the version prefix in enrichcache.Fingerprint (with a changelog\n"+
			"entry) so the change-gate re-enriches the standing corpus, then set classifyMustFixPin = %q.\n"+
			"If it was NOT intended: you have changed classification behaviour by accident.", got)
}

// ghasLeakDecisionPin pins assessGHASSecretsMustFix the way classifyMustFixPin
// pins classifyMustFix: leaked secrets never reach classifyMustFix, so its pin
// cannot see a change here. Set for v1 (public + validity active or unknown is
// must_fix, private or internal is elevated, test-mode or inactive is
// contained).
const ghasLeakDecisionPin = "61de72b0b389877b6773c9775fb4111c9d3223a6b29d0c5b224c95f488d49a51"

func TestAssessGHASSecretsMustFixIsPinned(t *testing.T) {
	var b strings.Builder
	for _, visibility := range []string{"", "public", "private", "internal"} {
		for _, checkID := range []string{"stripe_secret_key", "stripe_test_secret_key", "testing_key"} {
			for _, validity := range []string{"", "active", "inactive", "unknown"} {
				seed := asset.Asset{Metadata: map[string]string{"visibility": visibility}}
				class, reason := assessGHASSecretsMustFix(ghasSecretFindingWithValidity(checkID, validity), seed)
				fmt.Fprintf(&b, "%s|%s|%s|%s|%s\n", visibility, checkID, validity, class, reason)
			}
		}
	}
	sum := sha256.Sum256([]byte(b.String()))
	got := hex.EncodeToString(sum[:])
	require.Equal(t, ghasLeakDecisionPin, got,
		"assessGHASSecretsMustFix's decision table changed.\n"+
			"If that was INTENDED: bump enrichcache.LogicVersion (with a changelog entry on\n"+
			"enrichcache.Fingerprint) so the standing corpus is re-enriched, then set ghasLeakDecisionPin = %q.\n"+
			"If it was NOT intended: you have changed classification behaviour by accident.", got)
}

// sso_permission_set is a grant object, not a principal in the sense the five
// cloud identity types are — nothing "acts as" a permission set — but the same
// category error applies: it is not network-located, so "no internet-reachable
// path" is not evidence it is safe.
//
// This is a DEFENSIVE addition, not a fix for the symptom that motivated
// looking at it. Verified against the real call path (assessMustFix in
// mustfix.go): reachKnown is set only when reach.InternetHops resolves a hop
// count, and sso_permission_set is structurally never a DESTINATION of any
// Reach/Inherit edge (only ever a source, via grants_admin), so reachKnown is
// always false for it and this identity flag can never actually reach the
// classifyMustFix branch it guards — today. It closes the INV-1 category-error
// guard for the one asset-type gap in it, the same defect class that has
// already caused a real bug once (the cache-poisoning bug
// INV-1 exists to prevent), against the day some future edge accidentally
// seeds this type. Open aws-sso-permission-set-admin findings sitting at
// blank must_fix_class are the CORRECT scope-boundary answer — a real
// misconfiguration with no positive exploitability evidence — not something
// this change touches; fixing that would mean isPrivesc recognizing this
// check or a dedicated classifier, a separate and larger change.
func TestIsIdentityResource_IncludesSSOPermissionSet(t *testing.T) {
	require.True(t, IsIdentityResource("sso_permission_set"))
}

// Pure-function-level pin of the carve-out classifyMustFix relies on: IF reach
// data were ever available for an identity/grant-type resource (reachKnown is
// currently always false for sso_permission_set — see the test above), it must
// not demote to contained for lacking a hop count.
func TestClassifyMustFix_IdentityCarveOutAppliesRegardlessOfType(t *testing.T) {
	class, _ := classifyMustFix(mustFixInputs{
		reachKnown: true, reachable: false, identity: true,
	})
	require.NotEqual(t, MustFixContained, class,
		"a principal or grant object must not be demoted for lacking a network-reachable path")
}
