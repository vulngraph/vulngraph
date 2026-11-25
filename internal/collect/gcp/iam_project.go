package gcp

import (
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// iamPolicy is a provider-neutral IAM policy: its bindings and the audit
// configuration that rides on the same getIamPolicy response.
type iamPolicy struct {
	Bindings     []iamBinding
	AuditConfigs []auditConfig
}

// auditConfig is one auditConfigs entry: the service it applies to
// ("allServices" or e.g. "storage.googleapis.com") and its log types.
type auditConfig struct {
	Service string
	Logs    []auditLog
}

type auditLog struct {
	Type     string // ADMIN_READ, DATA_READ, DATA_WRITE
	Exempted []string
}

// effectiveIAM is the project's policy plus every ancestor policy that could
// be read. ancestorsComplete is false when the ancestry or any ancestor policy
// was unreadable, so an inherited setting may be missing.
type effectiveIAM struct {
	bindings          []iamBinding
	audit             []auditConfig
	ancestorsComplete bool
	// orgDomain is the organization's primary domain, lower-cased; "" when
	// the project has no organization or its domain could not be read.
	orgDomain string
}

// Roles the CIS GCP separation-of-duties and impersonation controls name.
const (
	roleSAUser         = "roles/iam.serviceAccountUser"
	roleSATokenCreator = "roles/iam.serviceAccountTokenCreator"
	roleSAAdmin        = "roles/iam.serviceAccountAdmin"
	roleKMSAdmin       = "roles/cloudkms.admin"
)

// kmsCryptoRoles are the CryptoKey usage roles CIS 1.12 separates from KMS admin.
var kmsCryptoRoles = []string{
	"roles/cloudkms.cryptoKeyEncrypterDecrypter",
	"roles/cloudkms.cryptoKeyEncrypter",
	"roles/cloudkms.cryptoKeyDecrypter",
}

// consumerDomains are Google consumer-account domains: a member there is a
// personal account, never a corporate identity (CIS GCP 1.2).
var consumerDomains = []string{"gmail.com", "googlemail.com"}

// requiredAuditLogTypes are the log types CIS GCP 2.1 requires on allServices.
var requiredAuditLogTypes = []string{"ADMIN_READ", "DATA_READ", "DATA_WRITE"}

// projectAsset is the project's cloud_account anchor, carrying the
// project-wide IAM posture: one finding per project rather than one per
// principal. Inherited membership can be concluded absent only when every
// ancestor was read. Positive evidence remains useful during a partial read.
func projectAsset(projectID string, eff effectiveIAM, now time.Time) asset.Asset {
	md := map[string]string{
		"account_id":                       projectID,
		"provider":                         "gcp",
		"sa_impersonation_project_members": strings.Join(projectImpersonators(eff.bindings, "projects/"+projectID, now), ","),
	}
	grants := grantsByMember(eff.bindings, now)
	for key, members := range map[string][]string{
		"consumer_account_members": consumerMembers(eff.bindings),
		"sa_admin_user_members":    membersHolding(grants, []string{roleSAAdmin}, []string{roleSAUser}),
		"kms_admin_crypto_members": membersHolding(grants, []string{roleKMSAdmin}, kmsCryptoRoles),
	} {
		if len(members) > 0 || eff.ancestorsComplete {
			md[key] = strings.Join(members, ",")
		}
	}
	// The audit configuration is inherited (the effective config is the union
	// over the hierarchy), so an unread ancestor can both supply a missing log
	// type and add an exemption: either answer needs every policy.
	// CIS GCP 1.2 compares members with the organization's domain. Present
	// only when that domain is known and every policy was read — or when an
	// outside member was already seen, which stands on its own.
	if eff.orgDomain != "" {
		outside := outsideDomainMembers(eff.bindings, eff.orgDomain)
		if len(outside) > 0 || eff.ancestorsComplete {
			md["organization_domain"] = eff.orgDomain
			md["non_org_domain_members"] = strings.Join(outside, ",")
		}
	}
	if eff.ancestorsComplete {
		gaps := auditGaps(eff.audit)
		md["audit_logging_all_services"] = strconv.FormatBool(len(gaps) == 0)
		md["audit_logging_gaps"] = strings.Join(gaps, ",")
	}
	return asset.Asset{
		ID:           "gcp:" + projectID,
		Name:         projectID,
		Type:         "cloud_account",
		Provider:     asset.ProviderGCP,
		Region:       "global",
		AccountID:    projectID,
		Metadata:     md,
		DiscoveredAt: now,
		LastSeen:     now,
	}
}

// consumerMembers returns every user member on a consumer email domain, from
// any binding read (project or inherited).
func consumerMembers(bindings []iamBinding) []string {
	set := map[string]bool{}
	for _, b := range bindings {
		for _, m := range b.Members {
			email, ok := strings.CutPrefix(m, "user:")
			if !ok {
				continue
			}
			_, domain, _ := strings.Cut(strings.ToLower(email), "@")
			if slices.Contains(consumerDomains, domain) {
				set[m] = true
			}
		}
	}
	return sortedKeys(set)
}

// outsideDomainMembers returns the user, group and domain members whose
// domain is neither the organization's domain nor a subdomain of it.
// Consumer accounts are left to consumerMembers (their own, stronger
// finding), and service accounts are workload identities, not logins.
func outsideDomainMembers(bindings []iamBinding, orgDomain string) []string {
	set := map[string]bool{}
	for _, b := range bindings {
		for _, m := range b.Members {
			kind, id, ok := strings.Cut(m, ":")
			if !ok || (kind != "user" && kind != "group" && kind != "domain") {
				continue
			}
			domain := strings.ToLower(id)
			if kind != "domain" {
				_, domain, _ = strings.Cut(domain, "@")
			}
			if domain == "" || slices.Contains(consumerDomains, domain) {
				continue
			}
			if domain != orgDomain && !strings.HasSuffix(domain, "."+orgDomain) {
				set[m] = true
			}
		}
	}
	return sortedKeys(set)
}

// projectImpersonators returns "member=role" for every non-service-account
// principal granted Service Account User or Token Creator on the project
// itself (CIS GCP 1.7): at project scope those roles let the principal act as
// EVERY service account in the project. Inherited grants are not counted — the
// control is about the project policy — and a provably expired condition
// grants nothing.
func projectImpersonators(bindings []iamBinding, projectResource string, now time.Time) []string {
	set := map[string]bool{}
	for _, b := range bindings {
		if b.Resource != projectResource || (b.Role != roleSAUser && b.Role != roleSATokenCreator) {
			continue
		}
		if b.Condition != "" && conditionExpired(b.Condition, now) {
			continue
		}
		for _, m := range b.Members {
			if m == "" || strings.HasPrefix(m, "serviceAccount:") || strings.HasPrefix(m, "deleted:") {
				continue
			}
			set[m+"="+b.Role] = true
		}
	}
	return sortedKeys(set)
}

// membersHolding returns the principals whose live roles include one of
// first AND one of second — the separation-of-duties pairs of CIS GCP 1.9
// (service account admin + user) and 1.12 (KMS admin + crypto key user).
func membersHolding(grants map[string]memberGrants, first, second []string) []string {
	var out []string
	for m, g := range grants {
		if anyRole(g.effectiveRoles, first) && anyRole(g.effectiveRoles, second) {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

func anyRole(have, want []string) bool {
	return slices.ContainsFunc(have, func(h string) bool { return slices.Contains(want, h) })
}

// auditGaps reports what keeps the effective allServices audit configuration
// short of CIS GCP 2.1: each required log type that is not enabled, and each
// exempted member (an exemption silences that principal's activity).
func auditGaps(configs []auditConfig) []string {
	enabled := map[string]bool{}
	exempted := map[string]bool{}
	for _, c := range configs {
		if c.Service != "allServices" {
			continue
		}
		for _, l := range c.Logs {
			enabled[l.Type] = true
			for _, m := range l.Exempted {
				exempted["exempted:"+m] = true
			}
		}
	}
	var gaps []string
	for _, t := range requiredAuditLogTypes {
		if !enabled[t] {
			gaps = append(gaps, "missing:"+t)
		}
	}
	return append(gaps, sortedKeys(exempted)...)
}
