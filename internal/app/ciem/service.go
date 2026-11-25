package ciem

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// AnalysisResult is the output of AnalyzeIAMAssets.
// ScoredAssets are the input IAM assets with RiskScore bumped based on worst
// detected privesc severity. The caller should re-ingest them so ClickHouse
// holds the elevated scores before the Ladybug graph is rebuilt — BFS then
// propagates the elevated risk outward to adjacent EC2/Lambda/etc. nodes.
type AnalysisResult struct {
	ScoredAssets               []asset.Asset
	OrganizationPolicyCoverage map[string]bool
	Paths                      []PrivescResult
	// Findings is one privesc finding per detected path, ready for the sync job
	// to persist as ciem_privesc findings. This is the single source of privesc
	// findings, with severity scaled by inbound assumability at the source.
	Findings []PrivescFinding
	// Tiers is the privilege tier of every IAM asset in the input, keyed by
	// asset id; StampTiers writes them onto the assets.
	Tiers map[string]TierVerdict
}

// PrivescFinding is the engine's finding-shaped output for one detected path.
// The sync job maps it onto finding.Finding (kept here so the ciem package stays
// free of the finding domain import).
type PrivescFinding struct {
	PrincipalID   string // resource id (ARN / SA / principal)
	PrincipalType string // iam_role | iam_user | gcp_service_account | azure_*
	PrincipalName string
	RuleID        string // e.g. "aws-privesc-15" — becomes CheckID
	Technique     string
	Description   string
	Severity      string // rule severity, capped by inbound assumability
	Steps         []string
	Resources     []string
}

// AnalyzeIAMAssets runs CIEM privilege escalation detection across all IAM
// assets in the provided slice. Non-IAM assets are silently skipped.
// Returns a copy of each affected IAM asset with RiskScore bumped, plus the
// raw detected paths. The caller re-ingests ScoredAssets so ClickHouse holds
// the elevated scores before the Ladybug graph is rebuilt; BFS then propagates
// the risk outward to adjacent nodes.
func AnalyzeIAMAssets(ctx context.Context, assets []asset.Asset) AnalysisResult {
	logger := log.FromContext(ctx)
	var result AnalysisResult

	// Applicability is principal-specific: SCPs do not constrain management
	// accounts or service-linked roles, and missing inventory is unknown.
	contexts := scpPoliciesByAccount(assets)
	organizationPolicies := map[string][]Policy{}
	result.OrganizationPolicyCoverage = map[string]bool{}
	for _, a := range assets {
		if a.Provider == asset.ProviderAWS && isIAMAsset(a.Type) {
			policies, complete := AWSOrganizationPolicies(a, contexts[a.AccountID])
			organizationPolicies[a.ID] = policies
			result.OrganizationPolicyCoverage[a.ID] = complete
		}
	}
	assets = append([]asset.Asset(nil), assets...)
	StampAWSOrganizationCoverage(assets, result.OrganizationPolicyCoverage)

	// First pass: how privileged is each principal already, and what is the most
	// privileged thing in its scope? A technique that reaches nothing above what
	// the principal holds is not an escalation (see privilege_delta.go). Computed
	// up front because it needs every principal in the account/project, not just
	// the one being evaluated.
	tierByAsset := make(map[string]privilegeTier, len(assets))
	adminEscalationProven := map[string]bool{}
	scopeMax := map[string]privilegeTier{}
	// aws-privesc-19/-28's scope names an EC2 instance, not a principal, so
	// resolveTargetPrincipals can never resolve it; see resolveSSMInstanceTargets.
	ec2Roles := ec2InstanceRoleByID(assets)
	for _, a := range assets {
		if !isIAMAsset(a.Type) {
			continue
		}
		p, err := principalFromAsset(a)
		if err != nil {
			continue // unread permissions: no tier entry, so classifyTiers stamps unknown
		}
		if a.Provider == asset.ProviderAWS {
			p.Policies = append(p.Policies, organizationPolicies[a.ID]...)
		}
		perms, err := effectivePermissions(p)
		if err != nil {
			continue // the main pass logs and skips this asset too
		}
		if a.Provider == asset.ProviderAWS {
			adminEscalationProven[a.ID] = awsGuardrailsPermitAdmin(p.Policies)
			for _, permission := range perms {
				if permission.Approximate {
					adminEscalationProven[a.ID] = false
				}
			}
		}
		tier := principalTier(string(a.Provider), a.Metadata["roles"], perms, a.AccountID)
		tierByAsset[a.ID] = tier
		if tier > scopeMax[a.AccountID] {
			scopeMax[a.AccountID] = tier
		}
	}

	pathsByAsset := map[string][]PrivescResult{}
	for _, a := range assets {
		if !isIAMAsset(a.Type) {
			continue
		}

		principal, err := principalFromAsset(a)
		if err != nil {
			logger.Warn().Err(err).Str("asset_id", a.ID).Msg("ciem: read principal policies failed")
			continue
		}
		if a.Provider == asset.ProviderAWS {
			principal.Policies = append(principal.Policies, organizationPolicies[a.ID]...)
		}
		perms, err := effectivePermissions(principal)
		if err != nil {
			logger.Warn().Err(err).Str("asset_id", a.ID).Msg("ciem: evaluate permissions failed")
			continue
		}
		if principal.Provider == "aws" {
			if names := NotActionAllowPolicies(principal.Policies); len(names) > 0 {
				logger.Debug().Str("asset_id", a.ID).Strs("policies", names).
					Msg("ciem: NotAction Allow treated as Allow * (conservative over-approximation)")
			}
		}
		if len(perms) == 0 {
			continue
		}

		paths := DetectPrivescPaths(principal, perms)
		if len(paths) == 0 {
			continue
		}
		resolveSSMInstanceTargets(paths, ec2Roles)

		result.Paths = append(result.Paths, paths...)
		pathsByAsset[a.ID] = paths

		// One finding per detected path, severity capped twice, taking whichever
		// ceiling is lower: by who can actually assume the principal
		// (federated/service/MFA → medium; specific-principal → high), and by the
		// privilege delta — a technique that reaches nothing above what the principal
		// already holds is not an escalation.
		tier, sMax := tierByAsset[a.ID], scopeMax[a.AccountID]
		for _, p := range paths {
			pathTier, pathMax := tier, sMax
			if a.Provider == asset.ProviderAzure && !azureTierCoversScopes(tier, perms, p.Resources) {
				pathTier, pathMax = tierNormal, tierNormal
			}
			sev := capToPrivilegeDelta(capSeverity(p.Rule.Severity, a), pathTier, pathMax)
			result.Findings = append(result.Findings, PrivescFinding{
				PrincipalID:   a.ID,
				PrincipalType: a.Type,
				PrincipalName: a.Name,
				RuleID:        p.Rule.ID,
				Technique:     p.Rule.Technique,
				Description:   p.Rule.Description,
				Severity:      sev,
				Steps:         p.Steps,
				Resources:     p.Resources,
			})
		}

		// Bump the asset's risk score based on worst detected privesc severity.
		// BFS picks up the elevated score on the next graph rebuild and propagates
		// it outward to adjacent assets (EC2s executing as this role, etc.).
		bumped := a
		bumped.RiskScore = privescScore(paths, a)
		result.ScoredAssets = append(result.ScoredAssets, bumped)

		logger.Debug().Str("asset_id", a.ID).Int("paths", len(paths)).
			Str("trust_entry", a.Metadata["trust_entry"]).
			Uint8("score", bumped.RiskScore).Msg("ciem: privilege escalation paths detected")
	}

	result.Tiers = classifyTiers(assets, tierByAsset, pathsByAsset, adminEscalationProven)
	// ScoredAssets are re-ingested over the rows the caller writes, so they
	// must carry the tier too or the re-ingest would erase it.
	StampTiers(result.ScoredAssets, result.Tiers)
	return result
}

// effectivePermissions dispatches to the right evaluator for each provider.
// AWS uses the full policy evaluator (boundaries, SCPs, explicit denies).
// GCP uses a shortcut: permissions are stored as comma-separated strings in
// Metadata["permissions"]. GCP IAM deny policies are not collected, so this
// allow-only view can over-report escalation.
func effectivePermissions(p Principal) ([]EffectivePermission, error) {
	if p.Provider == "gcp" {
		return buildGCPPermissions(p), nil
	}
	if p.Provider == "azure" {
		return buildAzurePermissions(p), nil
	}
	return EvaluateEffectivePermissions(p)
}

// buildGCPPermissions converts GCP's flat comma-separated permission list
// (stored by the GCP collector in Metadata["permissions"]) into EffectivePermissions
// without going through policy parsing. GCP IAM deny policies are not
// collected, so this allow-only view can retain unproven escalation candidates.
func buildGCPPermissions(p Principal) []EffectivePermission {
	raw := ""
	for _, pol := range p.Policies {
		if pol.Document != "" {
			raw = pol.Document
			break
		}
	}
	if raw == "" {
		return nil
	}
	var perms []EffectivePermission
	for _, perm := range strings.Split(raw, ",") {
		if perm = strings.TrimSpace(perm); perm != "" {
			perms = append(perms, EffectivePermission{
				Action:       perm,
				Resource:     "*",
				Effect:       "Allow",
				SourcePolicy: "gcp-metadata",
				Approximate:  true, // conditions, deny policies and target scopes are not evaluated
			})
		}
	}
	return perms
}

// worstSeverityScore returns the highest risk score implied by the detected
// privesc paths, clamped to never decrease below current.
func worstSeverityScore(paths []PrivescResult, current uint8) uint8 {
	score := current
	for _, p := range paths {
		var s uint8
		switch p.Rule.Severity {
		case SeverityCritical:
			s = 85
		case SeverityHigh:
			s = 65
		case SeverityMedium:
			s = 45
		}
		if s > score {
			score = s
		}
	}
	return score
}

// privescScore is the risk score a principal gets from its detected privesc
// paths: the worst path severity, ceiling-limited by the principal's inbound
// assumability. The actions are real, but a role no attacker can get INTO
// without an IdP session (or a specific upstream principal) must not score
// like a wildcard-assumable one. Never decreases an existing score.
func privescScore(paths []PrivescResult, a asset.Asset) uint8 {
	score := worstSeverityScore(paths, a.RiskScore)
	if ceil := entryCap(a); ceil != 0 && score > ceil {
		if ceil < a.RiskScore {
			ceil = a.RiskScore // cap the bump, never decrease an existing score
		}
		score = ceil
	}
	return score
}

// entryCap returns a ceiling for the privesc score bump based on who can
// actually assume the role — the collector's trust-policy metadata
// (trust_entry, mfa_required_to_assume; see collect/aws trustEntryClass).
// IdP-only (Okta/Identity Center), MFA-gated, or service-only entry caps the
// bump at the medium band; entry limited to specific AWS principals caps just
// under high. Public/mixed/unknown entry gets the full score. 0 = no cap.
// Applies to iam_role only — other principal types carry no trust policy.
func entryCap(a asset.Asset) uint8 {
	if a.Type != "iam_role" {
		return 0
	}
	switch {
	case a.Metadata["trust_entry"] == "federated",
		a.Metadata["trust_entry"] == "service",
		a.Metadata["mfa_required_to_assume"] == "true":
		return 45
	case a.Metadata["trust_entry"] == "cross_account",
		a.Metadata["trust_entry"] == "same_account":
		return 60
	}
	return 0
}

// severityRank orders the bands so a cap can be applied by comparison.
func severityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityHigh:
		return 2
	case SeverityMedium:
		return 1
	default:
		return 0
	}
}

// capSeverity lowers a rule's finding severity by the principal's inbound
// assumability, mirroring entryCap in severity space: federated/service/MFA-gated
// entry caps at medium (hard to reach at all), specific-principal entry caps at
// high. Public/mixed/unknown entry keeps the rule's severity. iam_role only.
func capSeverity(sev string, a asset.Asset) string {
	ceil := ""
	switch entryCap(a) {
	case 45:
		ceil = SeverityMedium
	case 60:
		ceil = SeverityHigh
	}
	if ceil != "" && severityRank(sev) > severityRank(ceil) {
		return ceil
	}
	return sev
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// scpPoliciesByAccount keeps applicability evidence intact until the shared
// principal-aware selector evaluates it. Legacy flat lists remain unknown.
func scpPoliciesByAccount(assets []asset.Asset) map[string][]Policy {
	out := map[string][]Policy{}
	for _, a := range assets {
		if a.Type == "aws_scp_set" && a.AccountID != "" {
			out[a.AccountID] = append(out[a.AccountID], Policy{Type: PolicyAWSOrganization, Document: a.Metadata[MetaAWSOrganization]})
		}
	}
	return out
}

func isIAMAsset(t string) bool {
	switch t {
	case "iam_role", "iam_user", "iam_group", "gcp_service_account",
		"azure_service_principal", "azure_managed_identity":
		return true
	}
	return false
}

// principalFromAsset builds a ciem.Principal from an asset, reading policies
// from the asset's metadata["policies"] field (JSON array of {type,document}).
// An unparseable policies field is an error, not an empty grant set: a
// principal with no readable permissions has no tier to state.
func principalFromAsset(a asset.Asset) (Principal, error) {
	p := Principal{
		ID:        a.ID,
		ARN:       a.ID,
		Name:      a.Name,
		Provider:  string(a.Provider),
		AccountID: a.AccountID,
		Type:      principalTypeFor(a.Type),
	}

	switch a.Provider {
	case "gcp":
		// GCP collector stores permissions as a comma-separated string in
		// Metadata["permissions"]. Store it as a synthetic policy document so
		// buildGCPPermissions can read it via the Policies slice.
		if perms, ok := a.Metadata["permissions"]; ok && perms != "" {
			p.Policies = []Policy{{Type: PolicyIdentity, Document: perms}}
		}
	case "azure":
		// Azure collector stores each role assignment whole in
		// Metadata["role_grants"], plus the flattened union of all of them in
		// Metadata["permissions"]/["not_permissions"] (comma-separated) for display
		// and as the fallback when role_grants is absent. All three are
		// carried as synthetic policies; buildAzurePermissions prefers the per-role
		// form, which is the only one that evaluates each assignment independently
		// the way Azure does.
		if grants, ok := a.Metadata["role_grants"]; ok && grants != "" {
			p.Policies = append(p.Policies, Policy{Type: PolicyAzureRoleGrants, Document: grants})
		}
		if perms, ok := a.Metadata["permissions"]; ok && perms != "" {
			p.Policies = append(p.Policies, Policy{Type: PolicyIdentity, Document: perms})
		}
		if not, ok := a.Metadata["not_permissions"]; ok && not != "" {
			p.Policies = append(p.Policies, Policy{Type: PolicyAzureNotActions, Document: not})
		}
	default:
		if raw, ok := a.Metadata["policies"]; ok && raw != "" {
			policies, err := parsePolicies(raw)
			if err != nil {
				return Principal{}, fmt.Errorf("principalFromAsset %s: %w", a.ID, err)
			}
			p.Policies = policies
			if (a.Type == "iam_role" || a.Type == "iam_user") && boundaryReadUnknown(a.Metadata["permission_boundary_complete"], policies) {
				p.Policies = append(p.Policies, Policy{Type: PolicyBoundary, Incomplete: true})
			}
		}
	}
	return p, nil
}

func principalTypeFor(assetType string) string {
	switch assetType {
	case "iam_role", "gcp_service_account", "azure_service_principal", "azure_managed_identity":
		return PrincipalRole
	case "iam_user":
		return PrincipalUser
	case "iam_group":
		return PrincipalGroup
	}
	return PrincipalRole
}

// parsePolicies decodes the policies JSON stored in asset metadata.
// The format matches what the AWS/GCP/Azure collectors write:
// [{type: "identity"|"boundary"|"scp", document: "<json>"}].
func parsePolicies(raw string) ([]Policy, error) {
	var stored []struct {
		Name       string `json:"name"`
		Type       string `json:"type"`
		Document   string `json:"document"`
		Incomplete bool   `json:"incomplete"`
	}
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		return nil, fmt.Errorf("parsePolicies: %w", err)
	}
	out := make([]Policy, 0, len(stored))
	for _, s := range stored {
		t := s.Type
		if t == "" {
			t = PolicyIdentity
		}
		name := s.Name
		if name == "" {
			name = strings.ToLower(t) + "-policy"
		}
		out = append(out, Policy{Name: name, Type: t, Document: s.Document, Incomplete: s.Incomplete})
	}
	return out, nil
}

// A legacy asset may already contain its one attached boundary even without
// the newer completeness field. Honor that cap; the evaluator handles unread
// or malformed documents separately.
func boundaryReadUnknown(complete string, policies []Policy) bool {
	if complete != "" {
		return complete != "true"
	}
	for _, p := range policies {
		if p.Type == PolicyBoundary {
			return false
		}
	}
	return true
}
