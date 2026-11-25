package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	// v2 is imported solely for folder IAM policies: the v1 FoldersService has no
	// GetIamPolicy (folders postdate v1). Everything else stays on v1 so the
	// existing project/organization calls are untouched.
	crmv2 "google.golang.org/api/cloudresourcemanager/v2"
	iam "google.golang.org/api/iam/v1"
	policyanalyzer "google.golang.org/api/policyanalyzer/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// iamAPI is the slice of GCP IAM the collector needs — small enough to fake.
// It is provider-neutral so the asset-mapping logic is independent of the
// google.golang.org/api shapes.
type iamAPI interface {
	// ServiceAccounts lists the project's service accounts (email, displayName).
	ServiceAccounts(ctx context.Context, projectID string) ([]gcpServiceAccount, error)
	// Policy returns the IAM policy on one resource — its bindings and audit
	// configs — named the way the Resource Manager API names it:
	// "projects/<id>", "folders/<n>" or "organizations/<n>". Implementations
	// MUST request policy version 3 so conditional bindings come back at all.
	Policy(ctx context.Context, resource string) (iamPolicy, error)
	// Ancestry returns the project's ancestors, nearest first — the folders it
	// sits in and finally the organization ("folders/123", "organizations/456").
	// GCP IAM is INHERITED: a role granted at the org or a folder applies to
	// every project beneath it, and reading only the project policy makes those
	// grants invisible. Best-effort — an error means "ancestry unknown", which
	// requires incomplete-evidence metadata on the returned assets.
	Ancestry(ctx context.Context, projectID string) ([]string, error)
	// OrganizationDomain returns an organization's primary domain: a Cloud
	// Identity / Workspace organization's displayName is that domain.
	OrganizationDomain(ctx context.Context, org string) (string, error)
	// RolePermissions resolves a role to its included permissions (cached by impl).
	RolePermissions(ctx context.Context, role string) ([]string, error)
	// UserManagedKeys lists a service account's USER_MANAGED keys — the
	// long-lived downloadable credentials (GCP's equivalent of AWS access keys).
	UserManagedKeys(ctx context.Context, email string) ([]gcpSAKey, error)
	// LastAuthentications queries Policy Analyzer activity for the given
	// activity type ("serviceAccountLastAuthentication" or
	// "serviceAccountKeyLastAuthentication") and returns lastAuthenticatedTime
	// keyed by the LAST path segment of the activity's fullResourceName (live
	// API: the SA email / key ID). Policy Analyzer's observation window is
	// up to ~1 year (startTime one year back, endTime lagging a few days),
	// so an identity absent from the map has not
	// authenticated in at least that long.
	LastAuthentications(ctx context.Context, projectID, activityType string) (map[string]time.Time, error)
}

// iamBinding is a provider-neutral IAM policy binding, carrying the scope it was
// granted at (Resource) and the IAM Condition (if any) that gates it. Both
// fields matter: GCP IAM is inherited, so a role bound at the org or a folder
// applies to every project beneath it, and an unevaluated Condition can mean
// the grant is no longer live at all (see conditionExpired).
type iamBinding struct {
	Role    string
	Members []string
	// Condition is the raw CEL expression from the binding, "" when
	// unconditional. Not evaluated in general — see conditionExpired for the one
	// case that can be decided deterministically.
	Condition string
	// Resource is the policy this binding came from ("projects/x", "folders/1",
	// "organizations/2"), kept so a finding can say WHERE the grant lives.
	Resource string
}

// scopeOf renders a binding's resource as a short scope label for metadata.
func scopeOf(resource string) string {
	switch {
	case strings.HasPrefix(resource, "organizations/"):
		return "organization"
	case strings.HasPrefix(resource, "folders/"):
		return "folder"
	default:
		return "project"
	}
}

type gcpServiceAccount struct {
	Email       string
	UniqueID    string // numeric ID — Policy Analyzer keys SA activity by it
	DisplayName string
	Disabled    bool
}

// gcpSAKey is a provider-neutral view of a USER_MANAGED service-account key.
type gcpSAKey struct {
	ID         string // last segment of projects/…/serviceAccounts/…/keys/<id>
	ValidAfter time.Time
	Disabled   bool
	// Exposed is set when Google itself flagged the key (DisableReason
	// EXPOSED — private key found in a public repo — or COMPROMISE_DETECTED).
	Exposed bool
}

// Policy Analyzer activity types for last-authentication lookups.
const (
	activitySALastAuth    = "serviceAccountLastAuthentication"
	activitySAKeyLastAuth = "serviceAccountKeyLastAuthentication"
)

// staleKeyDays mirrors the AWS collector's unused-credential threshold (CIS:
// disable credentials unused for 90 days).
const staleKeyDays = 90

// iamCollector implements collect for GCP IAM. newIAM is the seam: the default
// builds real IAM + ResourceManager clients via ADC; tests inject a fake.
type iamCollector struct {
	newIAM func(ctx context.Context, cfg map[string]string) (iamAPI, string, error)
	// auth carries Policy Analyzer answers across sweeps and across connectors.
	// It MUST be the long-lived one from *Collector — a per-call cache would
	// neither space requests against the shared quota nor carry anything
	// forward. See authcache.go.
	auth *authCache
}

// collectIAM gathers service accounts and the project IAM policy, computes each
// service account's effective permissions (the union of its bound roles'
// included permissions), and emits gcp_service_account assets carrying those
// permissions for the CIEM privilege-escalation checks to evaluate.
func collectIAM(ctx context.Context, cfg map[string]string, auth *authCache, now time.Time) ([]asset.Asset, error) {
	c := iamCollector{newIAM: defaultIAMClient, auth: auth}
	return c.collect(ctx, cfg, now)
}

func (c iamCollector) collect(ctx context.Context, cfg map[string]string, now time.Time) ([]asset.Asset, error) {
	client, projectID, err := c.newIAM(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectIAM: %w", err)
	}

	accounts, err := client.ServiceAccounts(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("collectIAM: service accounts: %w", err)
	}
	eff, err := effectivePolicy(ctx, client, projectID)
	if err != nil {
		return nil, fmt.Errorf("collectIAM: project bindings: %w", err)
	}
	grants := grantsByMember(eff.bindings, now)

	// Last-authentication activity, one Policy Analyzer query per type for the
	// whole project, served from a cache that survives sweeps and falls back to
	// the last good read when a refresh fails (see authcache.go — the API is
	// quota-limited to 10 requests/minute across the whole estate).
	//
	// Still fail-unknown at the end of it: when nothing fresh and nothing young
	// enough is available, ok is false and the usage metadata below is simply
	// OMITTED — never defaulted — so the hygiene checks stay silent instead of
	// firing false "unused" findings (same contract as the AWS collector's
	// GetAccessKeyLastUsed handling).
	saAuth := c.auth.lastAuth(ctx, client, projectID, activitySALastAuth)
	keyAuth := c.auth.lastAuth(ctx, client, projectID, activitySAKeyLastAuth)

	var assets []asset.Asset
	for _, sa := range accounts {
		member := "serviceAccount:" + sa.Email
		g := grants[member]
		perms, err := effectivePermissions(ctx, client, g.effectiveRoles)
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("service_account", sa.Email).
				Msg("gcp role permissions incomplete; retaining observed candidates without a clean verdict")
		}
		meta := map[string]string{
			"roles":                strings.Join(g.effectiveRoles, ","),
			"roles_complete":       strconv.FormatBool(eff.ancestorsComplete),
			"permissions":          strings.Join(perms, ","),
			"permissions_complete": strconv.FormatBool(eff.ancestorsComplete && err == nil),
			"disabled":             fmt.Sprintf("%t", sa.Disabled),
		}
		// Provenance for the roles that are NOT project-scoped, so a finding can
		// say "this came from the org policy" rather than pointing at a project
		// that merely inherits it.
		if len(g.inheritedRoles) > 0 {
			meta["inherited_roles"] = strings.Join(g.inheritedRoles, ",")
		}
		// Conditional and expired grants are recorded but scored differently —
		// see grantsByMember.
		if len(g.conditionalRoles) > 0 {
			meta["conditional_roles"] = strings.Join(g.conditionalRoles, ",")
		}
		if len(g.expiredRoles) > 0 {
			meta["expired_roles"] = strings.Join(g.expiredRoles, ",")
		}

		// USER_MANAGED keys — best-effort per SA: a keys.list error leaves the
		// key metadata absent (checks stay silent), never fails IAM collection.
		if keys, keysErr := client.UserManagedKeys(ctx, sa.Email); keysErr == nil {
			maps.Copy(meta, keyMetadata(keys, keyAuth, now))
		} else {
			log.FromContext(ctx).Warn().Err(keysErr).Str("service_account", sa.Email).
				Msg("gcp sa key listing skipped")
		}

		// SA-level last authentication (any credential: key, token, impersonation).
		if saAuth.ok {
			meta["sa_last_auth_days"] = "-1" // no activity in the observation window
			for _, id := range []string{sa.UniqueID, sa.Email} {
				if t, ok := saAuth.values[id]; ok {
					meta["sa_last_auth_days"] = strconv.Itoa(daysSince(now, t))
					break
				}
			}
			// How old the read behind sa_last_auth_days is: 0 = taken this sweep,
			// N = carried forward N days. Emitted whenever the value is, so a
			// consumer never has to guess whether it is looking at a live
			// observation. Bounded by authMaxAge.
			meta["sa_last_auth_observed_days"] = strconv.Itoa(saAuth.observedDays)
		}

		assets = append(assets, asset.Asset{
			ID:           member,
			Name:         sa.Email,
			Type:         "gcp_service_account",
			Provider:     asset.ProviderGCP,
			Region:       "global",
			AccountID:    projectID,
			Metadata:     meta,
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	return append(assets, projectAsset(projectID, eff, now)), nil
}

// effectivePolicy reads the project's own IAM policy plus every ancestor's
// (folders, then the organization), because GCP IAM is inherited: a role granted
// at the org applies to every project beneath it.
//
// Ancestor reads are best-effort. A missing resourcemanager.folders.getIamPolicy
// permission is the normal case for a project-scoped collector credential, and
// losing ancestor coverage must never fail the whole sweep — that would trade a
// partial blind spot for a total one. The project policy itself is still fatal
// on error, unchanged. Whether every ancestor was read is recorded, because the
// audit configuration is inherited too and an unread org policy may be the one
// that enables it.
func effectivePolicy(ctx context.Context, client iamAPI, projectID string) (effectiveIAM, error) {
	project, err := client.Policy(ctx, "projects/"+projectID)
	if err != nil {
		return effectiveIAM{}, fmt.Errorf("effectivePolicy: %w", err)
	}
	eff := effectiveIAM{bindings: project.Bindings, audit: project.AuditConfigs, ancestorsComplete: true}

	ancestors, err := client.Ancestry(ctx, projectID)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("project", projectID).
			Msg("gcp ancestry lookup skipped — org/folder-granted roles not counted this sweep")
		eff.ancestorsComplete = false
		return eff, nil
	}
	for _, res := range ancestors {
		if strings.HasPrefix(res, "organizations/") {
			if d, dErr := client.OrganizationDomain(ctx, res); dErr == nil && d != "" {
				eff.orgDomain = strings.ToLower(d)
			} else {
				log.FromContext(ctx).Warn().Err(dErr).Str("resource", res).
					Msg("gcp organization domain unreadable — non-organization members not graded this sweep")
			}
		}
		inherited, aErr := client.Policy(ctx, res)
		if aErr != nil {
			log.FromContext(ctx).Warn().Err(aErr).Str("resource", res).
				Msg("gcp ancestor policy skipped — roles granted there not counted this sweep")
			eff.ancestorsComplete = false
			continue
		}
		eff.bindings = append(eff.bindings, inherited.Bindings...)
		eff.audit = append(eff.audit, inherited.AuditConfigs...)
	}
	return eff, nil
}

// memberGrants splits a principal's roles by how much we trust them to be live.
type memberGrants struct {
	// effectiveRoles are the roles that actually count toward the principal's
	// permissions: unconditional ones, plus conditional ones we cannot disprove.
	effectiveRoles []string
	// inheritedRoles are the subset granted above the project (folder / org).
	inheritedRoles []string
	// conditionalRoles are the subset gated by an IAM Condition.
	conditionalRoles []string
	// expiredRoles are the subset excluded from effectiveRoles because their
	// condition's time window has demonstrably passed.
	expiredRoles []string
}

// grantsByMember inverts bindings into per-principal role sets.
//
// Conditional bindings are INCLUDED in effectiveRoles unless their time window
// has provably expired. That asymmetry is deliberate and matches the fail-open
// discipline used throughout enrichment: we cannot evaluate a general CEL
// expression at collection time, and dropping every conditional grant would
// manufacture false negatives on grants that are currently in force. We only
// subtract on POSITIVE evidence that the grant cannot apply — which, for a
// `request.time <` bound already in the past, is a fact and not a judgement.
func grantsByMember(bindings []iamBinding, now time.Time) map[string]memberGrants {
	type sets struct {
		effective, inherited, conditional, expired map[string]bool
	}
	acc := map[string]*sets{}
	get := func(m string) *sets {
		s, ok := acc[m]
		if !ok {
			s = &sets{
				effective:   map[string]bool{},
				inherited:   map[string]bool{},
				conditional: map[string]bool{},
				expired:     map[string]bool{},
			}
			acc[m] = s
		}
		return s
	}

	for _, b := range bindings {
		if b.Role == "" {
			continue
		}
		scope := scopeOf(b.Resource)
		expired := b.Condition != "" && conditionExpired(b.Condition, now)
		for _, m := range b.Members {
			if m == "" {
				continue
			}
			s := get(m)
			if b.Condition != "" {
				s.conditional[b.Role] = true
			}
			if expired {
				s.expired[b.Role] = true
				continue // provably cannot grant anything right now
			}
			s.effective[b.Role] = true
			if scope != "project" {
				s.inherited[b.Role] = true
			}
		}
	}

	out := make(map[string]memberGrants, len(acc))
	for m, s := range acc {
		out[m] = memberGrants{
			effectiveRoles:   sortedKeys(s.effective),
			inheritedRoles:   sortedKeys(s.inherited),
			conditionalRoles: sortedKeys(s.conditional),
			expiredRoles:     sortedKeys(s.expired),
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Only a complete single comparison proves expiry here. Matching a subexpression
// would invert the result under NOT or discard a live alternative under OR.
// CEL accepts both single- and double-quoted timestamp strings.
var conditionTimeBound = regexp.MustCompile(`^\s*request\.time\s*(<=|>=|<|>)\s*timestamp\(\s*(?:"([^"\\]+)"|'([^'\\]+)')\s*\)\s*$`)

// conditionExpired reports whether a binding's IAM Condition provably cannot
// hold right now because its time window has passed (or not yet started).
//
// Compound and unsupported expressions retain the grant as a candidate. They
// cannot establish either expiry or unrestricted authority.
func conditionExpired(expr string, now time.Time) bool {
	m := conditionTimeBound.FindStringSubmatch(expr)
	if len(m) == 0 {
		return false
	}
	raw := m[2]
	if raw == "" {
		raw = m[3]
	}
	ts, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return false
	}
	switch m[1] {
	case "<":
		return !now.Before(ts)
	case "<=":
		return now.After(ts)
	case ">":
		return !now.After(ts)
	case ">=":
		return now.Before(ts)
	}
	return false
}

// keyMetadata computes the credential-hygiene metadata for a service account's
// USER_MANAGED keys — field-for-field parity with the AWS iam_user collector
// (key_count/key_age_days/key_last_used_days/key_stale), plus key_exposed for
// keys Google itself flagged as leaked/compromised. Policy Analyzer's
// observation window is up to ~1 year, so a key with NO activity record has
// not authenticated in at least that long — but, exactly like AWS, a
// never-seen key only counts as stale once it is old enough
// (age >= staleKeyDays) that it cannot just be freshly provisioned.
func keyMetadata(keys []gcpSAKey, keyAuth authResult, now time.Time) map[string]string {
	activeCount := 0
	exposed := false
	stale := false
	var oldest time.Time
	mostRecentUsed := -1
	for _, k := range keys {
		if k.Exposed {
			exposed = true // exposed matters even on a disabled key: it must be DELETED
		}
		if k.Disabled {
			continue
		}
		activeCount++
		if oldest.IsZero() || k.ValidAfter.Before(oldest) {
			oldest = k.ValidAfter
		}
		ageDays := daysSince(now, k.ValidAfter)
		usedDays := -1
		if t, ok := keyAuth.values[k.ID]; ok {
			usedDays = daysSince(now, t)
			if mostRecentUsed == -1 || usedDays < mostRecentUsed {
				mostRecentUsed = usedDays
			}
		}
		if keyAuth.ok && (usedDays >= staleKeyDays || (usedDays == -1 && ageDays >= staleKeyDays)) {
			stale = true
		}
	}

	meta := map[string]string{
		"key_count":   strconv.Itoa(activeCount),
		"key_exposed": fmt.Sprintf("%t", exposed),
	}
	if !oldest.IsZero() {
		meta["key_age_days"] = strconv.Itoa(daysSince(now, oldest))
	}
	if keyAuth.ok {
		meta["key_stale"] = fmt.Sprintf("%t", stale)
		meta["key_last_used_days"] = strconv.Itoa(mostRecentUsed) // -1 = never in window
		// Age of the read behind those two — see sa_last_auth_observed_days.
		meta["key_last_used_observed_days"] = strconv.Itoa(keyAuth.observedDays)
	}
	return meta
}

func daysSince(now, t time.Time) int { return int(now.Sub(t).Hours() / 24) }

// effectivePermissions is the deduplicated, sorted union of the included
// permissions of every role bound to a principal.
func effectivePermissions(ctx context.Context, client iamAPI, roles []string) ([]string, error) {
	set := map[string]bool{}
	var readErrors []error
	for _, role := range roles {
		perms, err := client.RolePermissions(ctx, role)
		if err != nil {
			readErrors = append(readErrors, fmt.Errorf("effectivePermissions: role %s: %w", role, err))
			continue
		}
		for _, p := range perms {
			set[p] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, errors.Join(readErrors...)
}

// --- real client ---

type realIAM struct {
	iamSvc *iam.Service
	rmSvc  *cloudresourcemanager.Service
	// folderSvc reads folder IAM policies (v1 has no FoldersService.GetIamPolicy).
	// nil when the v2 service could not be built — folder policies are then
	// skipped, which costs inherited-role coverage but never fails a sweep.
	folderSvc *crmv2.Service
	paSvc     *policyanalyzer.Service
	cache     map[string][]string // role → permissions
}

// foldersPolicy converts a v2 folder policy into the provider-neutral shape.
// Separate from Policy only because the v2 Policy type is a distinct Go type
// from v1's despite the identical wire shape.
func foldersPolicy(p *crmv2.Policy, resource string) iamPolicy {
	out := iamPolicy{Bindings: make([]iamBinding, 0, len(p.Bindings))}
	for _, b := range p.Bindings {
		binding := iamBinding{Role: b.Role, Members: b.Members, Resource: resource}
		if b.Condition != nil {
			binding.Condition = b.Condition.Expression
		}
		out.Bindings = append(out.Bindings, binding)
	}
	for _, ac := range p.AuditConfigs {
		if ac == nil {
			continue
		}
		cfg := auditConfig{Service: ac.Service}
		for _, l := range ac.AuditLogConfigs {
			if l != nil {
				cfg.Logs = append(cfg.Logs, auditLog{Type: l.LogType, Exempted: l.ExemptedMembers})
			}
		}
		out.AuditConfigs = append(out.AuditConfigs, cfg)
	}
	return out
}

func defaultIAMClient(ctx context.Context, cfg map[string]string) (iamAPI, string, error) {
	projectID := cfg["project_id"]
	if projectID == "" {
		return nil, "", fmt.Errorf("defaultIAMClient: project_id is required")
	}
	iamSvc, err := iam.NewService(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("defaultIAMClient: iam: %w", err)
	}
	rmSvc, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("defaultIAMClient: resourcemanager: %w", err)
	}
	paSvc, err := policyanalyzer.NewService(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("defaultIAMClient: policyanalyzer: %w", err)
	}
	// Folder policies are optional: a build failure here degrades inherited-role
	// coverage to org+project rather than failing the sweep.
	folderSvc, err := crmv2.NewService(ctx)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).
			Msg("gcp folder IAM client unavailable — folder-granted roles not counted")
		folderSvc = nil
	}
	return &realIAM{
		iamSvc: iamSvc, rmSvc: rmSvc, folderSvc: folderSvc, paSvc: paSvc,
		cache: map[string][]string{},
	}, projectID, nil
}

func (r *realIAM) ServiceAccounts(ctx context.Context, projectID string) ([]gcpServiceAccount, error) {
	var out []gcpServiceAccount
	name := "projects/" + projectID
	call := r.iamSvc.Projects.ServiceAccounts.List(name)
	err := call.Pages(ctx, func(page *iam.ListServiceAccountsResponse) error {
		for _, sa := range page.Accounts {
			out = append(out, gcpServiceAccount{
				Email: sa.Email, UniqueID: sa.UniqueId,
				DisplayName: sa.DisplayName, Disabled: sa.Disabled,
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ServiceAccounts: %w", err)
	}
	return out, nil
}

// UserManagedKeys lists a service account's USER_MANAGED keys. Keys.List is
// not paginated (a SA holds at most 10 keys).
func (r *realIAM) UserManagedKeys(ctx context.Context, email string) ([]gcpSAKey, error) {
	name := "projects/-/serviceAccounts/" + email
	resp, err := r.iamSvc.Projects.ServiceAccounts.Keys.List(name).
		KeyTypes("USER_MANAGED").Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("UserManagedKeys: %w", err)
	}
	out := make([]gcpSAKey, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		validAfter, _ := time.Parse(time.RFC3339, k.ValidAfterTime)
		out = append(out, gcpSAKey{
			ID:         path.Base(k.Name),
			ValidAfter: validAfter,
			Disabled:   k.Disabled,
			Exposed: k.DisableReason == "SERVICE_ACCOUNT_KEY_DISABLE_REASON_EXPOSED" ||
				k.DisableReason == "SERVICE_ACCOUNT_KEY_DISABLE_REASON_COMPROMISE_DETECTED",
		})
	}
	return out, nil
}

// LastAuthentications queries Policy Analyzer for the project's last-auth
// activity of one type. The activity payload is a loose JSON struct; only
// lastAuthenticatedTime is read. Results are keyed by the fullResourceName's
// last path segment (SA unique ID for serviceAccountLastAuthentication, key ID
// for serviceAccountKeyLastAuthentication).
func (r *realIAM) LastAuthentications(ctx context.Context, projectID, activityType string) (map[string]time.Time, error) {
	parent := fmt.Sprintf("projects/%s/locations/global/activityTypes/%s", projectID, activityType)
	out := map[string]time.Time{}
	err := r.paSvc.Projects.Locations.ActivityTypes.Activities.Query(parent).
		Pages(ctx, func(page *policyanalyzer.GoogleCloudPolicyanalyzerV1QueryActivityResponse) error {
			for _, a := range page.Activities {
				if a == nil || a.FullResourceName == "" || len(a.Activity) == 0 {
					continue
				}
				var payload struct {
					LastAuthenticatedTime string `json:"lastAuthenticatedTime"`
				}
				if err := json.Unmarshal(a.Activity, &payload); err != nil || payload.LastAuthenticatedTime == "" {
					continue
				}
				t, err := time.Parse(time.RFC3339, payload.LastAuthenticatedTime)
				if err != nil {
					continue
				}
				out[path.Base(a.FullResourceName)] = t
			}
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("LastAuthentications: %s: %w", activityType, err)
	}
	return out, nil
}

// requestedPolicyVersion 3 is REQUIRED to see conditional bindings at all: the
// default (version 1) response omits them, so a policy read without this option
// silently under-reports the grants on any resource that uses IAM Conditions.
const requestedPolicyVersion = 3

// Policy reads one resource's IAM policy. The resource is named the way the
// Resource Manager API names it — "projects/x", "folders/1",
// "organizations/2" — and each API has its own GetIamPolicy method, so this
// dispatches on the prefix rather than assuming a project.
func (r *realIAM) Policy(ctx context.Context, resource string) (iamPolicy, error) {
	var (
		policy *cloudresourcemanager.Policy
		err    error
	)
	req := &cloudresourcemanager.GetIamPolicyRequest{
		Options: &cloudresourcemanager.GetPolicyOptions{RequestedPolicyVersion: requestedPolicyVersion},
	}
	kind, id, _ := strings.Cut(resource, "/")
	switch kind {
	case "organizations":
		policy, err = r.rmSvc.Organizations.GetIamPolicy(resource,
			&cloudresourcemanager.GetIamPolicyRequest{
				Options: &cloudresourcemanager.GetPolicyOptions{RequestedPolicyVersion: requestedPolicyVersion},
			}).Context(ctx).Do()
	case "folders":
		if r.folderSvc == nil {
			return iamPolicy{}, fmt.Errorf("Policy %s: folder API unavailable", resource)
		}
		var fp *crmv2.Policy
		fp, err = r.folderSvc.Folders.GetIamPolicy(resource,
			&crmv2.GetIamPolicyRequest{
				Options: &crmv2.GetPolicyOptions{RequestedPolicyVersion: requestedPolicyVersion},
			}).Context(ctx).Do()
		if err == nil {
			return foldersPolicy(fp, resource), nil
		}
	default:
		policy, err = r.rmSvc.Projects.GetIamPolicy(id, req).Context(ctx).Do()
	}
	if err != nil {
		return iamPolicy{}, fmt.Errorf("Policy %s: %w", resource, err)
	}
	out := iamPolicy{Bindings: make([]iamBinding, 0, len(policy.Bindings))}
	for _, b := range policy.Bindings {
		binding := iamBinding{Role: b.Role, Members: b.Members, Resource: resource}
		if b.Condition != nil {
			binding.Condition = b.Condition.Expression
		}
		out.Bindings = append(out.Bindings, binding)
	}
	for _, ac := range policy.AuditConfigs {
		if ac == nil {
			continue
		}
		cfg := auditConfig{Service: ac.Service}
		for _, l := range ac.AuditLogConfigs {
			if l != nil {
				cfg.Logs = append(cfg.Logs, auditLog{Type: l.LogType, Exempted: l.ExemptedMembers})
			}
		}
		out.AuditConfigs = append(out.AuditConfigs, cfg)
	}
	return out, nil
}

// Ancestry returns the project's ancestors nearest-first, as Resource Manager
// resource names. GetAncestry is a single call and returns the whole chain
// (project, folders…, organization); the project itself is dropped because the
// caller already read its own policy.
func (r *realIAM) Ancestry(ctx context.Context, projectID string) ([]string, error) {
	out, err := projectAncestry(ctx, r.rmSvc, projectID)
	if err != nil {
		return nil, fmt.Errorf("Ancestry: %w", err)
	}
	return out, nil
}

func (r *realIAM) OrganizationDomain(ctx context.Context, org string) (string, error) {
	o, err := r.rmSvc.Organizations.Get(org).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("OrganizationDomain: %w", err)
	}
	return o.DisplayName, nil
}

func (r *realIAM) RolePermissions(ctx context.Context, role string) ([]string, error) {
	if perms, ok := r.cache[role]; ok {
		return perms, nil
	}
	def, err := r.iamSvc.Roles.Get(role).Context(ctx).Do()
	if err != nil {
		// Never cache or publish an unread role as an empty grant. The caller
		// retains other observed permissions and marks the union incomplete.
		return nil, fmt.Errorf("RolePermissions %s: %w", role, err)
	}
	if def == nil || def.Name == "" {
		return nil, fmt.Errorf("RolePermissions %s: incomplete role response", role)
	}
	r.cache[role] = def.IncludedPermissions
	return def.IncludedPermissions, nil
}
