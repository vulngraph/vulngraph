package connector

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// OrgDiscoverer is the AWS side of an aws_org connector: list the
// organization, and test the hub → management → member chain. cfg is the org
// connector's decrypted config.
type OrgDiscoverer interface {
	// ListAccounts lists every account in every state, or fails as a whole —
	// a partial listing must never be returned as complete. withOUs asks for
	// each account's OU path (needed only by OU filters).
	ListAccounts(ctx context.Context, cfg map[string]string, withOUs bool) ([]DiscoveredAccount, error)
	Test(ctx context.Context, cfg map[string]string) OrgTestReport
}

// WithOrgDiscoverer wires aws_org discovery and connection tests.
func (s *Service) WithOrgDiscoverer(d OrgDiscoverer) *Service {
	s.org = d
	return s
}

var (
	roleARNPattern    = regexp.MustCompile(`^arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]{1,512}$`)
	externalIDPattern = regexp.MustCompile(`^[\w+=,.@:/-]+$`)
	roleNamePattern   = regexp.MustCompile(`^[\w+=,.@-]{1,64}$`)
	accountIDPattern  = regexp.MustCompile(`^\d{12}$`)
	ouIDPattern       = regexp.MustCompile(`^(ou-[0-9a-z]{4,32}-[0-9a-z]{8,32}|r-[0-9a-z]{4,32})$`)
)

// validateOrgConfig checks an aws_org config beyond key presence: a value
// AWS would reject fails here, at create, instead of on every discovery.
func validateOrgConfig(cfg map[string]string) error {
	hasKeys := cfg["aws_access_key_id"] != "" || cfg["aws_secret_access_key"] != ""
	switch cfg[OrgKeyHubAuth] {
	case "", HubAuthAmbient:
		if hasKeys {
			return fmt.Errorf("%w: access keys given but hub_auth is ambient — set hub_auth=access_key or drop the keys", ErrInvalidConfig)
		}
	case HubAuthAccessKey:
		if cfg["aws_access_key_id"] == "" || cfg["aws_secret_access_key"] == "" {
			return fmt.Errorf("%w: hub_auth=access_key requires aws_access_key_id and aws_secret_access_key", ErrInvalidConfig)
		}
	default:
		return fmt.Errorf("%w: hub_auth must be %q or %q", ErrInvalidConfig, HubAuthAmbient, HubAuthAccessKey)
	}
	if hub := cfg[OrgKeyHubRoleARN]; hub != "" && !roleARNPattern.MatchString(hub) {
		return fmt.Errorf("%w: hub_role_arn must be an IAM role ARN", ErrInvalidConfig)
	}
	if cfg[OrgKeyHubAuth] == HubAuthAccessKey && cfg[OrgKeyHubRoleARN] == "" {
		return fmt.Errorf("%w: hub_auth=access_key requires hub_role_arn — an IAM user key is never a hub session; deploy graph-hub-role.yaml with TrustType=principal and set its HubRoleArn output", ErrInvalidConfig)
	}
	if !roleARNPattern.MatchString(cfg[OrgKeyManagementRoleARN]) {
		return fmt.Errorf("%w: management_role_arn must be an IAM role ARN", ErrInvalidConfig)
	}
	if ext := cfg[OrgKeyExternalID]; len(ext) < 2 || len(ext) > 1224 || !externalIDPattern.MatchString(ext) {
		return fmt.Errorf("%w: external_id must be 2-1224 characters of [A-Za-z0-9+=,.@:/_-]", ErrInvalidConfig)
	}
	for _, k := range []string{OrgKeyMemberRoleName, OrgKeyExecuteRoleName} {
		if v := cfg[k]; v != "" && !roleNamePattern.MatchString(v) {
			return fmt.Errorf("%w: %s is not a valid IAM role name", ErrInvalidConfig, k)
		}
	}
	if ex := cfg[OrgKeyExecuteRoleName]; ex != "" && ex == memberRoleName(cfg) {
		return fmt.Errorf("%w: execute_role_name must differ from the read-only member role", ErrInvalidConfig)
	}
	for _, k := range []string{OrgKeyIncludeAccounts, OrgKeyExcludeAccounts} {
		for _, v := range splitList(cfg[k]) {
			if !accountIDPattern.MatchString(v) {
				return fmt.Errorf("%w: %s: %q is not a 12-digit account id", ErrInvalidConfig, k, v)
			}
		}
	}
	for _, k := range []string{OrgKeyIncludeOUs, OrgKeyExcludeOUs} {
		for _, v := range splitList(cfg[k]) {
			if !ouIDPattern.MatchString(v) {
				return fmt.Errorf("%w: %s: %q is not an OU (ou-…) or root (r-…) id", ErrInvalidConfig, k, v)
			}
		}
	}
	return nil
}

func splitList(csv string) []string {
	var out []string
	for _, p := range strings.Split(csv, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func memberRoleName(cfg map[string]string) string {
	if n := cfg[OrgKeyMemberRoleName]; n != "" {
		return n
	}
	return DefaultMemberRoleName
}

func orgRegion(cfg map[string]string) string {
	if r := cfg[OrgKeyRegion]; r != "" {
		return r
	}
	return defaultOrgRegion
}

// roleARNIn is roleName in accountID, in the management role's partition.
func roleARNIn(managementRoleARN, accountID, roleName string) string {
	partition := "aws"
	if parts := strings.SplitN(managementRoleARN, ":", 3); len(parts) == 3 && parts[1] != "" {
		partition = parts[1]
	}
	return fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, accountID, roleName)
}

// childConfig is everything an org child stores: references only. The hub
// credential and the ExternalId are resolved from the org on read.
func childConfig(org Connector, accountID string) map[string]string {
	cfg := map[string]string{
		ChildKeyOrgConnectorID: org.ID,
		"role_arn":             roleARNIn(org.Config[OrgKeyManagementRoleARN], accountID, memberRoleName(org.Config)),
		"region":               orgRegion(org.Config),
		"aws_account_id":       accountID,
	}
	if r := org.Config[OrgKeyRegions]; r != "" {
		cfg["regions"] = r
	}
	if ex := org.Config[OrgKeyExecuteRoleName]; ex != "" {
		cfg["execute_role_arn"] = roleARNIn(org.Config[OrgKeyManagementRoleARN], accountID, ex)
	}
	return cfg
}

// checkChildConfig is the write-side guard on the no-copied-keys rule: an org
// child's stored config must never carry a credential or the ExternalId.
func checkChildConfig(cfg map[string]string) error {
	for _, k := range childSecretKeys {
		if cfg[k] != "" {
			return fmt.Errorf("%w: %s", ErrChildStoresSecret, k)
		}
	}
	return nil
}

// resolveChild returns child with its org's hub credential, hub role and
// ExternalId merged in. The org must exist and be an aws_org: anything else fails rather
// than letting the child fall back to whatever ambient identity the pod has.
func (s *Service) resolveChild(ctx context.Context, child map[string]string) (map[string]string, error) {
	org, err := s.getStored(ctx, child[ChildKeyOrgConnectorID])
	if errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("resolveChild: %w", ErrOrgParentMissing)
	}
	if err != nil {
		return nil, fmt.Errorf("resolveChild: %w", err)
	}
	if org.Type != TypeAWSOrg {
		return nil, fmt.Errorf("resolveChild: %s is a %s connector: %w", org.ID, org.Type, ErrOrgParentMissing)
	}
	out := maps.Clone(child)
	if org.Config[OrgKeyHubAuth] == HubAuthAccessKey {
		out["aws_access_key_id"] = org.Config["aws_access_key_id"]
		out["aws_secret_access_key"] = org.Config["aws_secret_access_key"]
	}
	if hub := org.Config[OrgKeyHubRoleARN]; hub != "" {
		out[OrgKeyHubRoleARN] = hub
	}
	out["external_id"] = org.Config[OrgKeyExternalID]
	if out["execute_role_arn"] != "" {
		out["execute_external_id"] = org.Config[OrgKeyExternalID]
	}
	return out, nil
}

// getOrg loads an aws_org connector.
func (s *Service) getOrg(ctx context.Context, id string) (Connector, error) {
	org, err := s.getStored(ctx, id)
	if err != nil {
		return Connector{}, fmt.Errorf("getOrg: %w", err)
	}
	if org.Type != TypeAWSOrg {
		return Connector{}, ErrNotOrgConnector
	}
	return org, nil
}

// OrgAccounts lists an aws_org connector's discovered accounts.
func (s *Service) OrgAccounts(ctx context.Context, orgID string) ([]OrgAccount, error) {
	if _, err := s.getOrg(ctx, orgID); err != nil {
		return nil, fmt.Errorf("OrgAccounts: %w", err)
	}
	out, err := s.repo.ListOrgAccounts(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("OrgAccounts: %w", err)
	}
	return out, nil
}

// TestOrg runs the aws_org connection test.
func (s *Service) TestOrg(ctx context.Context, orgID string) (OrgTestReport, error) {
	if s.org == nil {
		return OrgTestReport{}, fmt.Errorf("TestOrg: %w", ErrNoOrgDiscoverer)
	}
	org, err := s.getOrg(ctx, orgID)
	if err != nil {
		return OrgTestReport{}, fmt.Errorf("TestOrg: %w", err)
	}
	return s.org.Test(ctx, org.Config), nil
}

// ReconcileAllOrgs runs discovery for every enabled aws_org connector. One
// org's failure does not stop the others; all failures are returned joined.
func (s *Service) ReconcileAllOrgs(ctx context.Context) ([]string, error) {
	conns, err := s.List(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("ReconcileAllOrgs: %w", err)
	}
	var created []string
	var errs []error
	for _, c := range conns {
		if c.Type != TypeAWSOrg {
			continue
		}
		res, err := s.ReconcileOrg(ctx, c.ID)
		created = append(created, res.Created...)
		if err != nil {
			errs = append(errs, fmt.Errorf("org %s: %w", c.ID, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return created, fmt.Errorf("ReconcileAllOrgs: %w", err)
	}
	return created, nil
}

// ReconcileOrg lists the organization and brings the org's children in line:
// a child per in-scope ACTIVE account, disabled (never deleted) when the
// account is suspended, closed, removed or filtered out.
//
// A failed or empty listing changes NO child. It is recorded on the org
// connector as a sync error and returned: "could not list" must not read as
// "every account left the organization".
func (s *Service) ReconcileOrg(ctx context.Context, orgID string) (ReconcileResult, error) {
	if s.org == nil {
		return ReconcileResult{}, fmt.Errorf("ReconcileOrg: %w", ErrNoOrgDiscoverer)
	}
	org, err := s.getOrg(ctx, orgID)
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("ReconcileOrg: %w", err)
	}
	filters := parseOrgFilters(org.Config)
	discovered, err := s.org.ListAccounts(ctx, org.Config, filters.needsOUs())
	if err == nil && len(discovered) == 0 {
		err = ErrEmptyDiscovery
	}
	if err != nil {
		s.recordOrgSync(ctx, orgID, err, false)
		return ReconcileResult{}, fmt.Errorf("ReconcileOrg: discovery: %w", err)
	}
	prev, err := s.repo.ListOrgAccounts(ctx, orgID)
	if err != nil {
		s.recordOrgSync(ctx, orgID, err, false)
		return ReconcileResult{}, fmt.Errorf("ReconcileOrg: %w", err)
	}
	owners, err := s.awsAccountOwners(ctx, orgID)
	if err != nil {
		s.recordOrgSync(ctx, orgID, err, false)
		return ReconcileResult{}, fmt.Errorf("ReconcileOrg: %w", err)
	}

	now := time.Now()
	res := ReconcileResult{Discovered: len(discovered)}
	prevByID := make(map[string]OrgAccount, len(prev))
	for _, p := range prev {
		prevByID[p.AccountID] = p
	}
	listed := make(map[string]bool, len(discovered))
	for i := range discovered {
		d := &discovered[i]
		listed[d.ID] = true
		var p *OrgAccount
		if row, ok := prevByID[d.ID]; ok {
			p = &row
		}
		s.applyAccount(ctx, org, owners, filters, d, p, now, &res)
	}
	for _, p := range prev {
		if !listed[p.AccountID] {
			row := p
			s.applyAccount(ctx, org, owners, filters, nil, &row, now, &res)
		}
	}

	var runErr error
	if res.Errors > 0 {
		runErr = fmt.Errorf("%d of %d accounts could not be reconciled — see the accounts list", res.Errors, len(discovered))
	}
	s.recordOrgSync(ctx, orgID, runErr, false)
	log.FromContext(ctx).Info().Str("org_connector_id", orgID).Int("discovered", res.Discovered).
		Int("created", len(res.Created)).Int("adopted", res.Adopted).Int("enabled", res.Enabled).Int("disabled", res.Disabled).
		Int("errors", res.Errors).Msg("aws_org: accounts reconciled")
	return res, nil
}

func (s *Service) recordOrgSync(ctx context.Context, orgID string, runErr error, partial bool) {
	if err := s.RecordSync(ctx, orgID, runErr, time.Now(), false, partial); err != nil {
		log.FromContext(ctx).Error().Err(err).Str("org_connector_id", orgID).Msg("aws_org: recording discovery outcome failed")
	}
}

// accountOwners is who else already collects each account.
type accountOwners struct {
	// owned: account id → an aws connector that is not this org's child and
	// is not an orphan — a conflict, never touched.
	owned map[string]string
	// orphans: account id → a child of an org connector that no longer exists
	// (re-creating an org connector leaves them behind, disabled). Discovery
	// adopts one instead of reporting a conflict.
	orphans map[string]orphanChild
}

type orphanChild struct {
	id      string
	enabled bool
}

// awsAccountOwners finds, for each account, the aws connectors other than
// this org's own children that collect it, so discovery neither creates a
// second connector sweeping an account nor ignores a child it can adopt.
func (s *Service) awsAccountOwners(ctx context.Context, orgID string) (accountOwners, error) {
	conns, err := s.List(ctx, false)
	if err != nil {
		return accountOwners{}, fmt.Errorf("awsAccountOwners: %w", err)
	}
	out := accountOwners{owned: map[string]string{}, orphans: map[string]orphanChild{}}
	parentLive := map[string]bool{}
	for _, c := range conns {
		if c.Type != TypeAWS {
			continue
		}
		full, err := s.getStored(ctx, c.ID)
		if err != nil {
			return accountOwners{}, fmt.Errorf("awsAccountOwners: %s: %w", c.ID, err)
		}
		parent := full.Config[ChildKeyOrgConnectorID]
		if parent == orgID {
			continue
		}
		acct := awsAccountID(full.Config)
		if acct == "" {
			continue
		}
		if parent != "" {
			live, seen := parentLive[parent]
			if !seen {
				if live, err = s.isOrgConnector(ctx, parent); err != nil {
					return accountOwners{}, fmt.Errorf("awsAccountOwners: %w", err)
				}
				parentLive[parent] = live
			}
			if !live {
				out.orphans[acct] = orphanChild{id: c.ID, enabled: c.Enabled}
				continue
			}
		}
		out.owned[acct] = c.ID
	}
	return out, nil
}

// isOrgConnector reports whether id is an existing aws_org connector. Only
// a confirmed absence counts as gone: any other read error is returned, so a
// database blip never turns a live org's children into adoptable orphans.
func (s *Service) isOrgConnector(ctx context.Context, id string) (bool, error) {
	stored, err := s.repo.Get(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("isOrgConnector: %w", err)
	}
	return stored.Type == TypeAWSOrg, nil
}

// applyAccount carries out one account's plan and records its row. A failure
// is the account's own status (error), never the whole pass's.
func (s *Service) applyAccount(ctx context.Context, org Connector, owners accountOwners, f orgFilters,
	d *DiscoveredAccount, p *OrgAccount, now time.Time, res *ReconcileResult) {
	status, detail, action := planAccount(f, d)
	row := OrgAccount{OrgConnectorID: org.ID, Status: status, StatusDetail: detail, LastSeenAt: now}
	if p != nil {
		row = *p
		row.Status, row.StatusDetail = status, detail
		if d != nil {
			row.LastSeenAt = now
		}
	}
	if d != nil {
		row.AccountID, row.Name, row.Email, row.AWSState = d.ID, d.Name, d.Email, d.State
		if d.OUPathKnown {
			row.OUPath = strings.Join(d.OUPath, "/")
		}
	}
	childEnabled := p != nil && p.Child != nil && p.Child.Enabled

	switch action {
	case childEnsure:
		if row.ChildConnectorID == "" {
			orphan, adopt := owners.orphans[row.AccountID]
			if adopt {
				// The orphan keeps its id, name and collected data; refreshChild
				// below points it at this org and enables it.
				row.ChildConnectorID, childEnabled = orphan.id, orphan.enabled
				res.Adopted++
			} else {
				if owner := owners.owned[row.AccountID]; owner != "" {
					row.Status = OrgAccountConflict
					row.StatusDetail = fmt.Sprintf("connector %s already collects this account; delete it to let the organization connector manage the account", owner)
					break
				}
				id, err := s.createChild(ctx, org, row.AccountID)
				if err != nil {
					row.Status, row.StatusDetail = OrgAccountError, err.Error()
					res.Errors++
					break
				}
				row.ChildConnectorID = id
				res.Created = append(res.Created, id)
				break
			}
		}
		if err := s.refreshChild(ctx, org, row.ChildConnectorID, row.AccountID, childEnabled); err != nil {
			row.Status, row.StatusDetail = OrgAccountError, err.Error()
			res.Errors++
			break
		}
		if !childEnabled {
			res.Enabled++
		}
	case childDisable:
		if row.ChildConnectorID != "" && childEnabled {
			if err := s.repo.SetEnabled(ctx, row.ChildConnectorID, false); err != nil {
				row.Status, row.StatusDetail = OrgAccountError, fmt.Sprintf("disabling the child connector failed: %v", err)
				res.Errors++
				break
			}
			res.Disabled++
		}
	case childKeep:
	}
	if err := s.repo.UpsertOrgAccount(ctx, row, now); err != nil {
		res.Errors++
		log.FromContext(ctx).Error().Err(err).Str("org_connector_id", org.ID).Str("account_id", row.AccountID).
			Msg("aws_org: writing the account row failed")
	}
}

// createChild creates the account's child connector, references only.
func (s *Service) createChild(ctx context.Context, org Connector, accountID string) (string, error) {
	cfg := childConfig(org, accountID)
	if err := checkChildConfig(cfg); err != nil {
		return "", fmt.Errorf("createChild: %w", err)
	}
	stored, err := s.repo.Create(ctx, Connector{Type: TypeAWS, Name: org.Name + "-" + accountID, Enabled: true},
		func(id string) ([]byte, error) { return s.encryptConfig(id, cfg) })
	if errors.Is(err, ErrNameTaken) {
		return "", fmt.Errorf("createChild: an aws connector named %q already exists — rename or delete it", org.Name+"-"+accountID)
	}
	if err != nil {
		return "", fmt.Errorf("createChild: %w", err)
	}
	return stored.ID, nil
}

// refreshChild rewrites the child's config when the org's settings moved it
// (member role name, region, execution role) and enables it if disabled.
func (s *Service) refreshChild(ctx context.Context, org Connector, childID, accountID string, enabled bool) error {
	cur, err := s.getStored(ctx, childID)
	if err != nil {
		return fmt.Errorf("refreshChild: %w", err)
	}
	want := childConfig(org, accountID)
	if !maps.Equal(cur.Config, want) {
		if err := checkChildConfig(want); err != nil {
			return fmt.Errorf("refreshChild: %w", err)
		}
		enc, err := s.encryptConfig(childID, want)
		if err != nil {
			return fmt.Errorf("refreshChild: %w", err)
		}
		if err := s.repo.UpdateConfig(ctx, childID, enc); err != nil {
			return fmt.Errorf("refreshChild: %w", err)
		}
	}
	if !enabled {
		if err := s.repo.SetEnabled(ctx, childID, true); err != nil {
			return fmt.Errorf("refreshChild: enable: %w", err)
		}
	}
	return nil
}

// childAction is what discovery does to an account's child connector.
type childAction int

const (
	childKeep    childAction = iota // change nothing
	childEnsure                     // exists, enabled, config current
	childDisable                    // disabled if it exists; never deleted
)

// planAccount decides an account's status and child action from the
// listing. d is nil when a complete listing no longer has the account.
func planAccount(f orgFilters, d *DiscoveredAccount) (OrgAccountStatus, string, childAction) {
	if d == nil {
		return OrgAccountRemoved, "no longer in the organization; its child connector is disabled and its data kept", childDisable
	}
	switch d.State {
	case "ACTIVE":
		in, known := f.inScope(*d)
		switch {
		case !known:
			return OrgAccountUnknown, "an OU filter applies but the listing did not place this account in an OU; its child is left as it was", childKeep
		case !in:
			return OrgAccountExcluded, "out of scope of the connector's account/OU filters", childDisable
		}
		return OrgAccountActive, "", childEnsure
	case "PENDING_ACTIVATION":
		return OrgAccountPending, "the account has not finished activating", childKeep
	case "SUSPENDED":
		return OrgAccountSuspended, "suspended by AWS; its child connector is disabled and its data kept", childDisable
	case "PENDING_CLOSURE", "CLOSED":
		return OrgAccountClosed, "closed; its child connector is disabled and its data kept", childDisable
	}
	return OrgAccountUnknown, fmt.Sprintf("AWS reported account state %q, which graph does not know; its child is left as it was", d.State), childKeep
}

// orgFilters are an org connector's account/OU scope rules.
type orgFilters struct {
	includeAccounts, excludeAccounts, includeOUs, excludeOUs map[string]bool
}

func parseOrgFilters(cfg map[string]string) orgFilters {
	set := func(k string) map[string]bool {
		out := map[string]bool{}
		for _, v := range splitList(cfg[k]) {
			out[v] = true
		}
		return out
	}
	return orgFilters{
		includeAccounts: set(OrgKeyIncludeAccounts), excludeAccounts: set(OrgKeyExcludeAccounts),
		includeOUs: set(OrgKeyIncludeOUs), excludeOUs: set(OrgKeyExcludeOUs),
	}
}

func (f orgFilters) needsOUs() bool { return len(f.includeOUs) > 0 || len(f.excludeOUs) > 0 }

// inScope reports whether the filters keep account a. known is false when the
// answer depends on an OU path the listing did not provide.
func (f orgFilters) inScope(a DiscoveredAccount) (in, known bool) {
	if f.excludeAccounts[a.ID] {
		return false, true
	}
	if f.needsOUs() && !a.OUPathKnown {
		// An explicitly included account with no OU exclude to lose to is in
		// regardless of where it sits.
		if f.includeAccounts[a.ID] && len(f.excludeOUs) == 0 {
			return true, true
		}
		return false, false
	}
	inOUs := func(set map[string]bool) bool {
		for _, ou := range a.OUPath {
			if set[ou] {
				return true
			}
		}
		return false
	}
	if inOUs(f.excludeOUs) {
		return false, true
	}
	if len(f.includeAccounts) == 0 && len(f.includeOUs) == 0 {
		return true, true
	}
	return f.includeAccounts[a.ID] || inOUs(f.includeOUs), true
}
