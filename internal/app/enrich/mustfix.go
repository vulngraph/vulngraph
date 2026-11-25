package enrich

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/graphschema"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Must-fix urgency tiers, persisted on the finding as must_fix_class. Orthogonal to
// the score and to safety_class: this answers "must I fix it NOW?" with evidence,
// not "how bad is the number". Empty until enriched.
const (
	MustFix           = "must_fix"   // reachable AND exploitable AND real blast, present, uncontrolled; or a non-test-mode credential (validity active or unknown) leaked in a public repo
	MustFixElevated   = "elevated"   // high-signal but not all must-fix conditions met
	MustFixContained  = "contained"  // definitively NOT internet-reachable (internal/lateral only)
	MustFixControlled = "controlled" // an observed compensating control (isControlled) gates a non-exploited privesc path
	// MustFixRoutine is the terminal verdict for a finding with no urgency evidence:
	// not exploitable (no KEV, no privesc), and not provably unreachable either, so
	// neither a promote nor the "contained" demote applies. A package that runs only
	// on inventoried VMs is routine too: its per-fleet vm_vuln finding carries the
	// urgency (fleetCanonicalDetail). This combination is the
	// MAJORITY of findings, so it needs its own answer rather than falling through
	// to "" — the field that answers "must I fix this now?" must not go silent for
	// most findings.
	//
	// This is deliberately NOT a promotion. Routine ranks below contained and carries no
	// urgency; it says "asked and answered: no evidence of urgency", which is a
	// different and useful statement from "" ("never asked, or asked and fell through").
	// Anything that should rank higher — e.g. internet-reachable but not exploitable —
	// is a separate prioritisation decision, deliberately not bundled here so its
	// effect stays measurable on its own.
	MustFixRoutine = "routine"
)

// mustFixBlastThreshold: "real blast" means more than a handful of reachable
// assets — a reachable, exploitable, but dead-end resource isn't top priority.
const mustFixBlastThreshold = 5

// maxMustFixHops: reachable-for-must-fix means within the attacker-movement depth
// the graph computes (0 = direct .. maxReachDepth transitive).
const maxMustFixHops = 3

// SupplyChainReachProvider answers the must-fix reachability question for a
// supply-chain finding whose resource is a bare package purl (e.g.
// pkg:golang/golang.org/x/net@...) — never itself a row in graph.assets, so the
// normal seed-based reachability path (asset.Service.Get keyed on ResourceID)
// can never resolve for it. Implemented by SupplyChainExposure
// (sources_supply_chain.go): package ← depends_on ← repo → deploys_to →
// workload → exposed_to_internet — the exact traversal the score source
// already runs, reused here so scoring and must-fix classification can never
// disagree about what "reachable" means for a package.
type SupplyChainReachProvider interface {
	// truncated reports that a fan-out cap cut the walk short, so a negative
	// anyExposed is a sample — never grounds for a containment claim.
	PackageDeployExposure(ctx context.Context, packageID string) (anyDeployed, anyExposed, truncated bool, err error)
	// RepoDeployExposure answers the same question for a finding whose resource
	// IS a github_repo — a code-scanning (SAST) alert on first-party source,
	// where the deployment lineage starts at the repo instead of at a package.
	RepoDeployExposure(ctx context.Context, repoID string) (anyDeployed, anyExposed, truncated bool, err error)
	// FleetCanonical reports whether a package finding's VM runners are its
	// only runners and are all carried by per-fleet vm_vuln findings, which
	// then own its urgency (sources_supply_chain_vm.go).
	FleetCanonical(ctx context.Context, f finding.Finding) (canonical bool, instances int, err error)
}

// mustFixInputs are the evidence facts the pure classifier weighs.
type mustFixInputs struct {
	present     bool
	reachKnown  bool
	hops        int
	reachable   bool
	exploitable bool
	blast       int
	// blastKnown pairs with blast the same way reachKnown pairs with reachable:
	// a failed blast-radius walk must never read as "0 reachable assets" (a
	// safe-looking measurement) when it is really "not measured at all". See
	// CLAUDE.md's "Degraded input" rule — this is that class, on the blast axis.
	blastKnown bool
	controlled bool
	kev        bool
	// activeThreat: a behavioral detection floored to the page band (crypto
	// mining, malware executed, instance credentials used off-host — see
	// threatPageMarkers). Like kev it is evidence the resource is already being
	// exploited, so no reachability or compensating-control demotion applies.
	activeThreat bool
	identity     bool // the resource is a principal (IAM user/role, GCP SA), not a network endpoint
}

// IsIdentityResource reports whether a resource is a principal rather than a
// network-addressable resource. "internet-exposed" (direct network reachability)
// is a category error for these — an identity is never itself on the internet;
// its exposure risk is being reachable/assumable FROM an internet-exposed asset,
// which the reason string renders accurately instead of the false "internet-exposed".
// Exported because the adjudication context must scope exposure facts the same way.
// Derived from graphschema.IsIdentityType so the reach seed filter (graphstore)
// and this scorer share one identity-type list ("declare once, derive
// everywhere"); the two must never drift.
func IsIdentityResource(rt string) bool {
	return graphschema.IsIdentityType(rt)
}

// IsNetworkReachableResource reports whether a resource type is a
// network-addressable node where internet reachability is a real, dominant risk
// axis — i.e. exactly the asset types the internet-hops BFS (graphstore) exists
// to reason about. It is the gate that lets the reachability score source and
// its grounded promote/demote signal apply to plain infrastructure
// misconfigurations (an EC2 in a public subnet, a wide-open security group),
// which are neither privesc nor an "exposure"/"public" check by check-id/type
// string and so would otherwise be silently skipped. Additive and fail-open: a
// type listed here still contributes nothing unless the graph actually has a
// path (unknown → no-op) — see InternetReach.Evaluate.
func IsNetworkReachableResource(rt string) bool {
	switch rt {
	case "ec2_instance", "gce_instance", "lambda_function", "security_group",
		"load_balancer", "rds_instance", "k8s_pod", "k8s_service", "k8s_ingress",
		"k8s_deployment", "k8s_statefulset", "k8s_daemonset", "k8s_job",
		// cloud_function/cloudsql_instance/api_gateway are managed-service
		// producers InternetReachability (correlate/reachability.go) already
		// seeds exposed_to_internet edges for; this gate is what lets that
		// exposure evidence reach must-fix classification for them too.
		"cloud_function", "cloudsql_instance", "api_gateway":
		return true
	}
	return false
}

// ReachabilityEvidenced reports whether a finding's must-fix classification
// carries POSITIVE internet-reachability evidence from the deterministic layer
// (Ladybug internet-hops BFS): must_fix/elevated with a reachability-based reason.
// Kept next to mustFixReason so the phrase matching and the phrasing can never
// drift apart. The adjudicator's corroboration gate uses it: a severity demotion
// that contradicts deterministic reachability evidence is flagged for review,
// not silently accepted.
func ReachabilityEvidenced(class, reason string) bool {
	if class != MustFix && class != MustFixElevated {
		return false
	}
	return strings.Contains(reason, "internet-exposed") || strings.Contains(reason, "internet-reachable")
}

// assessMustFix gathers the evidence (cheap, cached graph reads) and classifies a
// finding's urgency. seed is the finding's asset, fetched once by the caller and
// shared with assessSafety — a zero asset reads as not-present/not-controlled.
// Fail-open: nil providers or unknown facts can never PROMOTE to must_fix (that
// requires positive reachable+present evidence) and never falsely demote
// (contained needs a definitive unreachable).
//
// source=iac findings (Terraform static-analysis findings collected against a
// github_repo — internal/collect/github/iac.go) do NOT get a special-cased path
// the way supply-chain does, and that's deliberate, not an oversight: unlike a
// supply-chain package purl, an iac finding's ResourceID (the repo full name)
// resolves to a real github_repo asset, so seed is never the zero value here —
// the general path below runs. It correctly lands on "" for these findings today,
// for the ordinary reason documented at the bottom of classifyMustFix:
// isPrivesc/KnownExploited never key on an IaC misconfig, so exploitable is
// always false, and reach.InternetHops has no meaningful signal for a
// github_repo (it isn't a network node in the reachability graph), so
// reachKnown is always false too — the fail-open "no positive exploitability
// evidence" branch, same as a plain open-S3-bucket CSPM finding. Promoting these
// would require linking the specific Terraform *resource* (tags["iac_resource"],
// e.g. "aws_security_group.alb") to the AWS asset it actually deploys to, so
// deployment/exposure could be checked the way PackageDeployExposure does for
// packages; graph.graph_edges currently has no edge types connecting an iac
// finding's repo to the resource it declares, and no tagging convention join
// key exists at meaningful coverage. Revisit if/when tfstate ingestion or a
// consistent managed-by tagging convention lands.
//
// A supply-chain package finding takes a separate path (assessSupplyChainMustFix):
// its ResourceID is a bare package purl, never itself an asset, so seed is always
// the zero value and the normal reach/blast lookups (keyed on ResourceID) never
// resolve for it.
//
// A ghas_secrets (leaked-secret) finding also takes a separate path
// (assessGHASSecretsMustFix): its ResourceID IS a real github_repo asset (seed
// resolves normally), but the general reach/blast path is a category
// mismatch — reach.InternetHops runs a network-reachability BFS built for
// network-addressable infrastructure (EC2, security groups, load balancers), and
// a github_repo is never itself "network reachable" in that sense, so the BFS
// never resolves and the finding falls through to blank. The repo's own
// `visibility` metadata (already collected by internal/collect/github) answers
// the audience question directly, and whether the key is known to work answers
// the rest: a working credential is usable from anywhere once read.
func assessMustFix(ctx context.Context, f finding.Finding, seed asset.Asset, reach ReachProvider, blast BlastRadiusCounter, scReach SupplyChainReachProvider, sso SSOResolver, rbac RBACBindingResolver, now time.Time) (class, reason string) {
	if f.ResourceID == "" {
		return "", ""
	}
	if isSupplyChainPackage(f) {
		return assessSupplyChainMustFix(ctx, f, scReach, reach)
	}
	if isGHASSecret(f) {
		return assessGHASSecretsMustFix(f, seed)
	}
	if isGHASCodeScanning(f) {
		return assessGHASCodeScanningMustFix(ctx, f, scReach)
	}
	if isK8sRBACGrant(f) {
		return assessK8sRBACMustFix(ctx, f, seed, rbac)
	}
	activeThreat := isThreatFinding(f) && threatFloor(f) >= ThresholdPage
	in := mustFixInputs{
		kev:          f.KnownExploited,
		activeThreat: activeThreat,
		exploitable:  f.KnownExploited || isPrivesc(f) || activeThreat,
		present:      isPresent(seed, now),
		controlled:   isControlled(ctx, seed, f, sso),
		identity:     IsIdentityResource(f.ResourceType),
	}
	// Only ask the network-reachability BFS about a resource type where that
	// question is meaningful (IsNetworkReachableResource) or an identity (its
	// own reachable-FROM framing, handled inside classifyMustFix). Every other
	// type — anything Ladybug syncs for a reason OTHER than reachability scoring,
	// e.g. ecr_repository (added purely to seed repository-policy-public
	// exposure edges) — must never reach reach.InternetHops at all: it comes
	// back reachKnown=true, reachable=false (an edgeless node, not a proven
	// unreachable one), and classifyMustFix's unreachable-demote rule then
	// reads that absence of data as positive "no attack path" evidence. Gating
	// here (not just for the types known to trip it today) means the next
	// resource type added to Ladybug's sync set for an unrelated edge can't
	// silently trip this same category error again.
	if reach != nil && (IsNetworkReachableResource(f.ResourceType) || in.identity) {
		if hops, ok, err := reach.InternetHops(ctx, f.ResourceID); err == nil && ok {
			in.reachKnown = true
			in.hops = hops
			in.reachable = hops >= 0 && hops <= maxMustFixHops
		}
	}
	if blast != nil {
		// blast == nil (unset seam) is a deliberate, permanent no-op and logs
		// nothing — only an ACTUAL failed walk (blast wired, this call
		// errored) warns. At enrich sweep volume this can still mean one
		// WARN per finding per sweep in a deployment where the walk is
		// genuinely, persistently failing (not just transiently) — if that
		// shape shows up in practice, downgrade to a rate-limited/aggregate
		// log rather than removing the signal.
		if n, err := blast.BlastRadiusCount(ctx, f.ResourceID, blastDepth); err == nil {
			in.blast, in.blastKnown = n, true
		} else {
			log.FromContext(ctx).Warn().Err(err).Str("resource_id", f.ResourceID).
				Msg("must_fix: blast radius walk failed, blast axis unmeasured")
		}
	}
	return classifyMustFix(in)
}

// assessSupplyChainMustFix classifies must-fix urgency for a package finding.
// A package purl carries no reachKnown/blast/controlled facts of its own, so this
// weighs deployment exposure instead of the asset-seed evidence classifyMustFix
// uses. Deliberately narrower than the general classifier: any internet-exposed
// deployment target is enough to earn "elevated" (a package finding has no
// KEV/privesc exploitability axis of its own to also require — the CVE/dependency
// scanner's own severity already carries that signal).
//
// TWO INDEPENDENT PATHS reach a package, and a package needs only one of them:
//
//   - the IMAGE path (reach): imagevuln emits a real package asset per purl plus a
//     runs_package edge, and containment inheritance (graphschema.InheritEdgeTypes)
//     gives that node the hop count of whatever workload runs its image. This is
//     the ONLY path that can ever work for an OS package — an apk/deb inside a base
//     image has no dependent repo and no SBOM entry to walk. A VM's SSM/OS Config
//     inventory emits the same runs_package edge from the VM, so this path also
//     carries a VM's own hop count onto the packages installed on it.
//   - the REPO path (scReach): package ← depends_on ← repo → deploys_to → workload,
//     the original SBOM traversal. It is the only path for a language dependency
//     declared in a manifest but not yet present in a scanned image.
//
// Consulting only the repo path would leave every OS-package (image-only)
// finding blank: `!anyDeployed` would return before any image evidence was
// considered.
//
// Fail-open: a nil provider, a lookup error, or "can't
// determine deployment at all" leaves the class blank rather than guessing at
// urgency. Positive exposure from EITHER path wins; "contained" requires that at
// least one path positively resolved and neither found exposure.
//
// EXCEPTION: a confirmed malicious package (isMaliciousPackage) never reaches
// this deploy-exposure logic at all — see the early return below. Deployment
// and reachability are the wrong axis for install-time compromise; do not
// "fix" this a second time by adding another reachability gate here.
func assessSupplyChainMustFix(ctx context.Context, f finding.Finding, scReach SupplyChainReachProvider, reach ReachProvider) (class, reason string) {
	// A MAL-* (OpenSSF malicious-packages) advisory is a confirmed compromise,
	// not a "vulnerable if reached" CVE: the credential-stealing/backdoor
	// payload runs at npm-install/CI-build time merely by the dependency
	// resolving — before any deploy/reachability question is even meaningful.
	// Deployment and internet exposure answer "how far can an attacker move
	// next", not "did the compromise happen"; falling through to the
	// deploy-exposure switch below would silently demote an already-exploited
	// finding to MustFixContained's "internal/lateral risk only" framing,
	// which is simply false for this class. Checked first, the same way
	// isPrivesc/KEV precedes the general reach path in assessMustFix.
	if isMaliciousPackage(f) {
		return MustFixElevated, "confirmed malicious package (OpenSSF malicious-packages advisory) — install-time compromise already occurred when the dependency resolved; deployment state and internet exposure are irrelevant to whether the payload ran"
	}
	// A package run only by inventoried VMs is classified once, per fleet, on
	// the host: grading the package node too would put the same hosts in the
	// worklist twice, the package copy capped below must-fix. A failed check
	// falls through to the package's own evidence rather than demote on a guess.
	if scReach != nil {
		if canonical, instances, err := scReach.FleetCanonical(ctx, f); err == nil && canonical {
			return MustFixRoutine, fleetCanonicalDetail(instances)
		}
	}

	imageKnown, imageExposed := false, false
	if reach != nil {
		if hops, ok, err := reach.InternetHops(ctx, f.ResourceID); err == nil && ok {
			imageKnown = true
			imageExposed = hops >= 0 && hops <= maxMustFixHops
		}
	}

	repoKnown, repoExposed, repoTruncated := false, false, false
	if scReach != nil {
		if anyDeployed, anyExposed, truncated, err := scReach.PackageDeployExposure(ctx, f.ResourceID); err == nil && anyDeployed {
			repoKnown = true
			repoExposed = anyExposed
			repoTruncated = truncated
		}
	}

	switch {
	case imageExposed:
		// The package node inherits the hop count of whatever runs it — an image's
		// pod or, since VMs have an inventory, the VM itself — so the reason
		// must not claim which.
		return MustFixElevated, "vulnerable package runs on an internet-reachable workload — container image or VM (runtime reachability)"
	case repoExposed:
		return MustFixElevated, "vulnerable package deployed to an internet-exposed workload (supply-chain reachability)"
	case f.KnownExploited && (imageKnown || repoKnown):
		// Same rule classifyMustFix applies: no internet path says how an
		// attacker would get in, and for a KEV one already can from any foothold.
		return MustFixElevated, "known-exploited (KEV) vulnerable package — exploitable from any internal foothold whatever its internet exposure"
	case repoTruncated:
		// The lineage walk hit a fan-out cap: "no exposure among the first N" is
		// a sample, not the "not internet-reachable" containment claims.
		return "", ""
	case imageKnown || repoKnown:
		return MustFixContained, "package is deployed but not internet-reachable — internal/lateral risk only"
	}
	return "", ""
}

// isGHASSecret reports whether a finding is a GitHub secret-scanning alert
// (internal/collect/github/ghas.go secretFinding) — a leaked-credential
// detection whose resource is a real github_repo asset, not a network
// endpoint.
func isGHASSecret(f finding.Finding) bool {
	return f.Source == "ghas_secrets"
}

// isTestModeCredential reports whether a leaked secret is a provider's
// test-mode key rather than a production one. GHAS's secret_type taxonomy encodes
// this directly in the slug for providers that distinguish the two (e.g.
// Stripe's "stripe_test_api_key" / "stripe_test_secret_key" vs
// "stripe_api_key" / "stripe_secret_key") — secretFinding copies that slug
// verbatim into f.CheckID, so this is a real signal already present in the
// finding, not a new one being invented. A test-mode credential can still
// leak internal logic/config, but it can't move money or data the way a
// production key can, so it never classifies as urgently as one at the same
// repo visibility. Not test-mode is not the same as live: whether the key still
// works is GitHub's validity check (credentialNotLive).
//
// Matched on a whole "test" token of the slug, not a substring: a substring
// match also caught any provider whose NAME contains "test" (a testing-SaaS
// API key is a production key).
func isTestModeCredential(f finding.Finding) bool {
	if !isSecretFinding(f) {
		return false
	}
	tokens := strings.FieldsFunc(strings.ToLower(f.CheckID), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
	return slices.Contains(tokens, "test")
}

// secretValidityInactive reports whether GitHub's validity check found a
// leaked secret no longer works (finding.SecretValidityKey). Only "inactive"
// counts: "unknown" and an absent verdict say nothing either way.
func secretValidityInactive(f finding.Finding) bool {
	return isSecretFinding(f) && f.Metadata[finding.SecretValidityKey] == finding.SecretValidityInactive
}

// secretValidityActive reports whether GitHub's validity check found a leaked
// secret still works.
func secretValidityActive(f finding.Finding) bool {
	return isSecretFinding(f) && f.Metadata[finding.SecretValidityKey] == finding.SecretValidityActive
}

// credentialNotLive reports whether a leaked secret is known not to be a
// working key: a provider's test-mode key, or one GitHub's validity check
// found inactive. Unknown validity is not evidence either way, so it never
// counts. SignalFloor uses the same predicate, so the score and the class
// cannot disagree about which keys are not live.
func credentialNotLive(f finding.Finding) bool {
	return isTestModeCredential(f) || secretValidityInactive(f)
}

// secretAudience is the reason-string wording for who can read a repository of
// each visibility GitHub reports.
var secretAudience = map[string]struct{ repo, testMode, readers string }{
	"public":   {"a public repository", "publicly visible", "anyone can read it"},
	"private":  {"a private repository", "visible to repository members only", "every org member, collaborator and clone has it"},
	"internal": {"an internal repository", "enterprise-wide visibility", "every member of the enterprise, collaborator and clone has it"},
}

// assessGHASSecretsMustFix classifies a leaked-secret finding's urgency from
// whether the credential is known to work and who can read the repo
// (asset.Metadata["visibility"], collected by internal/collect/github/github.go
// from the GitHub API's repo.visibility field), instead of the general
// reach/blast evidence, which is a category mismatch for a github_repo (see
// assessMustFix's doc comment).
//
// Network reachability does not apply to a credential: once read, a working
// key works from anywhere, through forks, mirrored clones or a compromised
// collaborator account. So visibility only says how many people have already
// been able to read it, and the blast-radius count classifyMustFix requires
// has no analogue: the key's blast is whatever the key can do.
//
// Whether the key works comes from two signals: the secret_type slug names
// some providers' test-mode keys (isTestModeCredential), and GitHub's validity
// check (finding.SecretValidityKey) reports active or inactive for providers
// it can check. Neither is a check of ours. "Live" is claimed only when GitHub
// reported active; a key that is not test-mode with no verdict is graded as
// if live — unknown is never treated as safe — but its reason says the
// validity is unknown rather than that it works.
//
// Tier mapping:
//   - public + active, or public + not test-mode with validity unknown →
//     must_fix: anyone on the internet can read it.
//   - private or internal + active or unknown → elevated: the audience is
//     bounded. GitHub's "internal" visibility (Enterprise Cloud/Server) lets
//     every member of the enterprise read the repo, a wider audience than
//     private, so it is never graded below private.
//   - test-mode credential, or validity inactive (any known visibility) →
//     contained: it can leak internal logic/config but is not a working
//     production key. contained is the "real but capped" bucket, reserved here
//     for keys known not to be live.
//   - unknown/missing visibility → blank, fail-open: the GitHub API always
//     returns this field today, but a nil/empty value must never be read as
//     either "public" (would wrongly promote) or "private" (would wrongly
//     demote), so it is left unclassified like any other fail-open case in
//     this file.
func assessGHASSecretsMustFix(f finding.Finding, seed asset.Asset) (class, reason string) {
	visibility := seed.Metadata["visibility"]
	aud, ok := secretAudience[visibility]
	if !ok {
		return "", ""
	}
	urgent := MustFixElevated
	if visibility == "public" {
		urgent = MustFix
	}
	switch {
	case isTestModeCredential(f):
		return MustFixContained, "test-mode credential exposed in " + aud.repo + " — " + aud.testMode + ", but not a live-credential risk"
	case secretValidityInactive(f):
		return MustFixContained, "credential exposed in " + aud.repo + " — GitHub's validity check reports it inactive (revoked or expired), so it no longer works; " + aud.readers
	case secretValidityActive(f):
		return urgent, "live credential exposed in " + aud.repo + " — GitHub's validity check reports it active; " + aud.readers + ", and it works from anywhere"
	default:
		return urgent, "credential exposed in " + aud.repo + " — not a test-mode key, validity unknown (GitHub has not reported whether it still works), so graded as urgent; " + aud.readers
	}
}

// isGHASCodeScanning reports whether a finding is a GitHub code-scanning (SAST)
// alert — a static-analysis result on first-party source whose resource is the
// github_repo the code lives in.
func isGHASCodeScanning(f finding.Finding) bool {
	return f.Source == "ghas_code_scanning"
}

// assessGHASCodeScanningMustFix classifies a code-scanning alert from whether the
// repo's code is actually DEPLOYED and internet-exposed, instead of running the
// general reach/blast path.
//
// The general path is a category mismatch here, in exactly the way documented for
// ghas_secrets — reach.InternetHops runs a network-reachability BFS built for
// network-addressable infrastructure, and a github_repo is never itself a network
// node. Code scanning fails WORSE than ghas_secrets does, though: a code-scanning
// alert's github_repo resolves in the BFS as "known, and not within
// maxMustFixHops", so classifyMustFix's unreachable gate fires and stamps it
// MustFixContained / "no internet-reachable attack path — internal/lateral risk
// only", a claim the BFS never actually had an opinion to back — and contained is
// not inert: inv3ContainedHighBand (consistency.go) caps a contained finding
// below the high band.
//
// The honest signal is the deploys_to lineage the supply-chain classifier already
// walks: vulnerable first-party code matters where it RUNS, and "runs on an
// internet-exposed workload" is the same evidence a vulnerable dependency in the
// same repo would be judged on.
//
// Tier mapping, deliberately narrow and fail-open:
//   - deployed AND exposed → elevated. Capped at elevated, not must_fix, for the
//     same reason ghas_secrets is: must_fix additionally requires a blast-radius
//     count, and a SAST alert has no blast fact of its own to supply.
//   - deployed, positively not exposed → contained. This is a real containment
//     claim about the workload the code runs on, not about the repo.
//   - lineage unresolved → blank. Most repos have no deploys_to edge yet, so most
//     alerts land here — and blank is the correct answer (see classifyMustFix's
//     closing comment), not a downgrade of a verdict we were entitled to make.
//     Never fall back to the network-reach path that produces the false contained.
func assessGHASCodeScanningMustFix(ctx context.Context, f finding.Finding, scReach SupplyChainReachProvider) (class, reason string) {
	if scReach == nil {
		return "", ""
	}
	deployed, exposed, truncated, err := scReach.RepoDeployExposure(ctx, f.ResourceID)
	if err != nil || !deployed {
		return "", ""
	}
	if exposed {
		return MustFixElevated, "vulnerable code deployed to an internet-exposed workload (repository deployment lineage)"
	}
	if truncated {
		return "", "" // a capped sample found no exposure; the rest is unmeasured
	}
	return MustFixContained, "code is deployed but not to any internet-reachable workload — internal/lateral risk only"
}

// classifyMustFix is the pure, table-tested urgency decision. Order matters:
// compensating controls and unreachability are demotions that take precedence over
// the must-fix promotion, so a controlled/unreachable finding is never must_fix.
//
// Neither demotion applies to a finding already being exploited (KEV, or a
// page-floored active-compromise detection): "no internet path" says how an
// attacker would get in, and for these one already has — a KEV on an internal
// host is reachable from any foothold, and a host mining crypto is compromised
// whatever its exposure. Demoting them to contained also told belief.Reconcile
// to ground them as a confirmed Low and the adjudicator to skip them.
func classifyMustFix(in mustFixInputs) (class, reason string) {
	exploited := in.kev || in.activeThreat
	// Compensating control neutralizes the path (never demotes an exploited finding).
	if in.controlled && !exploited {
		return MustFixControlled, "privilege-escalation path gated by an observed compensating control (MFA-required or non-admin SSO role assumption, or an inactive or MFA-gated keyless user)"
	}
	// Definitively not reachable from the internet — strong demote to contained.
	//
	// NOT for identities. Network unreachability is a category error for a
	// principal, exactly as IsIdentityResource's doc comment says: an identity is
	// never itself on the internet, and privilege escalation through it needs no
	// internet path at all. Creating a service-account key, calling actAs, or
	// setting project metadata is a cloud control-plane API call — an insider, a
	// compromised low-privilege credential, or a leaked key anywhere in the org can
	// make it. Demoting on "no internet-reachable attack path" therefore suppressed
	// the very findings the privesc engine exists to produce.
	//
	// mustFixInputs.identity exists precisely to gate this branch — see its field
	// comment — never merely to render mustFixReason's display string. Identities
	// fall through to the exploitability/blast gates below instead, which is
	// where a principal's risk actually lives.
	if in.reachKnown && !in.reachable && !in.identity && !exploited {
		return MustFixContained, "no internet-reachable attack path — internal/lateral risk only"
	}
	// The bar: reachable AND exploitable AND real blast AND a live target.
	// blastKnown gates the blast half exactly as reachKnown gates the reach
	// half. Honest framing: since
	// mustFixBlastThreshold > 0, `in.blast >= mustFixBlastThreshold` on an
	// unmeasured (zero-value) blast already evaluates false on its own —
	// this `blastKnown &&` is a NO-OP for gating today, not a load-bearing
	// fix. The observable change from adding blastKnown is entirely in
	// mustFixReason's "blast radius unmeasured" disclosure below. It stays
	// in the condition anyway as genuine defense-in-depth: it keeps this
	// promotion correct if mustFixBlastThreshold is ever lowered to 0 (where
	// it would otherwise stop being a no-op and silently promote on an
	// unmeasured walk), and it documents the intent explicitly rather than
	// relying on an implicit "threshold happens to be positive" invariant
	// a future edit could break without noticing.
	if in.reachKnown && in.reachable && in.exploitable && in.blastKnown && in.blast >= mustFixBlastThreshold && in.present {
		return MustFix, mustFixReason(in)
	}
	// High-signal but not the full must-fix picture.
	if in.exploitable && (in.reachable || (in.blastKnown && in.blast >= mustFixBlastThreshold)) {
		return MustFixElevated, mustFixReason(in)
	}
	// Already exploited but short of the must-fix picture (unreachable, or
	// unmeasured reach and small blast): still urgent, never routine — routine's
	// "not exploitable" reason would be false here.
	if exploited {
		return MustFixElevated, mustFixReason(in)
	}
	// Scope boundary, by design, not a gap: routine here is a legitimate
	// urgency-lens answer, not "unclassified". must_fix/elevated require POSITIVE
	// exploitability evidence (KEV or an active privesc path) -- a reachable-but-
	// plain misconfiguration (an open S3 bucket, an EC2 with a public IP, an
	// unencrypted EBS volume, a k8s pod with no internet_hops node signal at all)
	// has no exploitability evidence to promote on, and isn't demonstrably
	// unreachable/controlled either, so it correctly lands here. The score/band
	// still carries that finding's danger -- must_fix_class is a narrow, additional
	// "which of these do I fix RIGHT NOW" lens, not a second classification of
	// every finding. Don't "fix" this by loosening the exploitable bar to cover
	// more resource types.
	//
	// No urgency evidence: not exploitable, and not provably unreachable either (an
	// unknown reach can never demote — that fail-open rule is what keeps a missing
	// signal from manufacturing a false "contained"). Terminal, and explicit — this
	// is the honest majority answer, not a fallthrough. The reason must not mention
	// internet reachability: Routine covers non-network resources and identities
	// too, where that framing is a category error.
	// TestAssessMustFix_NonNetworkResourceNeverReachDemoted checks for exactly this
	// phrase leaking.
	if in.exploitable {
		// A privilege-escalation path with neither reach nor a measured blast of
		// mustFixBlastThreshold assets: weighed and not promoted, but "not
		// exploitable" would be false.
		return MustFixRoutine, "privilege escalation path without the reach or blast radius to promote it"
	}
	return MustFixRoutine, "no urgency evidence: not exploitable (no KEV, no privilege escalation path)"
}

// mustFixReason renders the compact evidence string shown on the finding.
func mustFixReason(in mustFixInputs) string {
	var parts []string
	if in.reachKnown && !in.reachable && !in.identity {
		parts = append(parts, "not reachable from the internet (exploitable from any internal foothold)")
	}
	if in.reachKnown && in.reachable {
		switch {
		case in.identity:
			// A principal is not itself internet-facing — frame the path accurately
			// as reachability FROM an exposed asset, never the false "internet-exposed".
			if in.hops <= 0 {
				parts = append(parts, "assumable from an internet-exposed asset")
			} else {
				parts = append(parts, fmt.Sprintf("reachable from an internet-exposed asset (%d hops)", in.hops))
			}
		case in.hops == 0:
			parts = append(parts, "internet-exposed")
		default:
			parts = append(parts, fmt.Sprintf("internet-reachable (%d hops)", in.hops))
		}
	}
	if in.kev {
		parts = append(parts, "known-exploited (KEV)")
	} else if in.activeThreat {
		parts = append(parts, "active compromise detected")
	} else if in.exploitable {
		parts = append(parts, "active privilege-escalation path")
	}
	if in.blastKnown && in.blast >= mustFixBlastThreshold {
		parts = append(parts, fmt.Sprintf("blast radius %d", in.blast))
	} else if !in.blastKnown {
		parts = append(parts, "blast radius unmeasured")
	}
	return strings.Join(parts, " · ")
}

// isControlled reports whether a privilege-escalation finding's principal is gated
// by a real, POSITIVELY OBSERVED compensating control. Metadata from
// collect/aws/iam.go. Only meaningful for privesc findings; this is the
// "years-old privesc behind SSO isn't urgent" signal.
//
// Both branches obey one rule — absence of evidence never demotes. For an
// iam_role that means "only an AWS service can assume this role" is not a
// compensating control: it is the definition of a workload role rather than a
// gate on it. classifyRoleTrust (sources_identity.go) owns that judgement and is shared with
// the IdentityHygiene score source, so the class and the band cannot disagree.
func isControlled(ctx context.Context, a asset.Asset, f finding.Finding, sso SSOResolver) bool {
	if !isPrivesc(f) {
		return false
	}
	if a.Type == "iam_role" {
		ctrl, _ := classifyRoleTrust(ctx, a, sso)
		return ctrl.demotes()
	}
	// iam_user: no trust policy exists, so demote only on a positively-present
	// control — an inactive user, or an MFA-gated console-only user with no
	// standalone access key to bypass it. Absence of evidence never demotes.
	// active_key_count must be PRESENT and "0": the collector omits it when
	// ListAccessKeys fails, and an unread key count is not a keyless user.
	if a.Type == "iam_user" {
		if a.Metadata["inactive"] == "true" {
			return true
		}
		if a.Metadata["mfa_enabled"] == "true" && a.Metadata["active_key_count"] == "0" {
			return true
		}
	}
	return false
}
