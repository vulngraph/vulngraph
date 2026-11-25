package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/diskscan"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// assetDeletionRetention matches the ClickHouse assets TTL (last_seen + 180
// days): a deletion record outliving the row it describes proves nothing.
const assetDeletionRetention = 180 * 24 * time.Hour

// Repo is the connector storage the service needs. It deals only in ciphertext.
type Repo interface {
	// Create inserts the connector and seals its config in ONE transaction.
	// encrypt receives the id the row was assigned, because the ciphertext is
	// bound to that id (AAD) and the id does not exist until the insert has
	// run. A failure anywhere rolls the whole thing back rather than leaving a
	// connector whose config cannot be opened.
	Create(ctx context.Context, c Connector, encrypt func(id string) ([]byte, error)) (storedConnector, error)
	// UpdateConfig replaces a connector's sealed config.
	UpdateConfig(ctx context.Context, id string, configEnc []byte) error
	// ResealConfig replaces a connector's sealed config only while it still
	// equals old; ok is false when another writer changed it first.
	ResealConfig(ctx context.Context, id string, old, sealed []byte) (ok bool, err error)
	Get(ctx context.Context, id string) (storedConnector, error)
	List(ctx context.Context, enabledOnly bool) ([]storedConnector, error)
	Delete(ctx context.Context, id string) error
	SetSyncResult(ctx context.Context, id string, status SyncStatus, syncErr string, at time.Time, cleanNoOp, partial bool) error
	SetSyncFingerprint(ctx context.Context, id, fingerprint string) error
	// SetMode stores mode and returns the mode it replaced, read under the
	// same row lock, so the audit row's before value is exact.
	SetMode(ctx context.Context, id string, mode Mode) (Mode, error)
	// SetDiskScan stores the disk-scan mode and who set it, and returns the
	// mode it replaced, read under the same row lock.
	SetDiskScan(ctx context.Context, id string, mode diskscan.DiskScanMode, by string, at time.Time) (diskscan.DiskScanMode, error)
	GetAssetHashes(ctx context.Context, connectorID string) (map[string]StoredAssetHash, error)
	// CollectingAsset lists the enabled connectors whose sync currently
	// collects assetID.
	CollectingAsset(ctx context.Context, assetID string) ([]string, error)
	UpsertAssetHashEntries(ctx context.Context, connectorID string, entries []AssetHashEntry) error
	DeleteAssetHashes(ctx context.Context, connectorID string, ids []string) error
	RecordAssetDeletions(ctx context.Context, connectorID string, ids []string, at time.Time) error
	PruneAssetDeletions(ctx context.Context, cutoff time.Time) (int64, error)
	AssetDeletions(ctx context.Context, ids []string) (map[string]time.Time, error)
	RecordProvenCapability(ctx context.Context, connectorID string, capability ProvenCapability, at time.Time) error
	ListProvenCapabilities(ctx context.Context, connectorID string) ([]ProvenCapability, error)
	SetEnabled(ctx context.Context, id string, enabled bool) error
	// DeleteOrg deletes an aws_org connector and disables its children
	// atomically.
	DeleteOrg(ctx context.Context, id string) error
	ListOrgAccounts(ctx context.Context, orgID string) ([]OrgAccount, error)
	UpsertOrgAccount(ctx context.Context, a OrgAccount, at time.Time) error
}

// AssetPurger is the asset-domain capability PurgeAndDelete needs — hard
// deletion by account, plus the id lookup findings are resolved from before
// those assets are gone. A small interface owned by this service (domains
// talk to each other through service interfaces, never each other's repos)
// rather than depending on the whole asset.Service surface.
type AssetPurger interface {
	PurgeAccount(ctx context.Context, provider, accountID string) (int, error)
	AssetIDsByAccount(ctx context.Context, provider, accountID string) ([]string, error)
	// PurgeEdgesForAssets hard-deletes every graph_edges row touching any of
	// the given asset IDs. Without this, a purged account's edges keep
	// passing the freshness filter for up to 48h and then simply sit in
	// ClickHouse for the full edge TTL, presenting phantom attack paths for
	// an account a human already confirmed was gone.
	PurgeEdgesForAssets(ctx context.Context, ids []string) (int, error)
	// AssetMetadata returns one asset's metadata, nil when it does not exist —
	// how an Azure purge finds the tenant settings asset a subscription shares.
	AssetMetadata(ctx context.Context, id string) (map[string]string, error)
}

// FindingResolver is the one finding-domain capability PurgeAndDelete needs.
type FindingResolver interface {
	ResolveGoneByResourceIDs(ctx context.Context, resourceIDs []string) (int, error)
}

// AuditRecorder writes the audit_events row of an admin action that has taken
// effect, and reports its own write failures (audit.Service).
type AuditRecorder interface {
	Record(ctx context.Context, action, targetType, targetID string, details map[string]any)
}

// Service holds connector business logic: validation and config
// encryption/decryption around the repo.
//
// assets/findings are nilable — most callers (any HTTP request path that
// never triggers a purge) have no reason to wire them up, and PurgeAndDelete
// fails closed with a clear error rather than a nil-pointer panic when they
// are absent.
type Service struct {
	repo     Repo
	cipher   *Cipher
	assets   AssetPurger
	findings FindingResolver
	org      OrgDiscoverer // nil: aws_org discovery and tests are unavailable
	audit    AuditRecorder // nil: no audit rows (the worker and CLI, which make no admin changes)
	now      func() time.Time
}

func NewService(repo Repo, cipher *Cipher) *Service {
	return &Service{repo: repo, cipher: cipher, now: time.Now}
}

// WithPurge wires the asset/finding capabilities PurgeAndDelete needs. Kept
// out of NewService's required parameters because only the one admin path
// that offers connector purging needs them — every other construction site
// (both today's) would otherwise have to wire up two domains it never touches.
func (s *Service) WithPurge(assets AssetPurger, findings FindingResolver) *Service {
	s.assets, s.findings = assets, findings
	return s
}

// WithAudit records connector create, mode change, delete and purge in
// audit_events.
func (s *Service) WithAudit(a AuditRecorder) *Service {
	s.audit = a
	return s
}

func (s *Service) record(ctx context.Context, action, id string, details map[string]any) {
	if s.audit != nil {
		s.audit.Record(ctx, action, AuditTargetConnector, id, details)
	}
}

// anyPresent reports whether at least one of keys has a non-empty value in config.
func anyPresent(config map[string]string, keys []string) bool {
	for _, k := range keys {
		if config[k] != "" {
			return true
		}
	}
	return false
}

// Create validates and persists a new connector, encrypting its config.
func (s *Service) Create(ctx context.Context, typ Type, name string, config map[string]string, eventSource string) (Connector, error) {
	if !typ.Valid() {
		return Connector{}, ErrInvalidType
	}
	if name == "" {
		return Connector{}, ErrMissingName
	}
	for _, key := range requiredKeys[typ] {
		if config[key] == "" {
			return Connector{}, fmt.Errorf("%w: %s requires %q", ErrMissingConfig, typ, key)
		}
	}
	for _, group := range oneOfKeys[typ] {
		if !anyPresent(config, group) {
			return Connector{}, fmt.Errorf("%w: %s requires one of %v", ErrMissingConfig, typ, group)
		}
	}
	if config[ChildKeyOrgConnectorID] != "" {
		return Connector{}, ErrManagedChild
	}
	if typ == TypeAWSOrg {
		if err := validateOrgConfig(config); err != nil {
			return Connector{}, fmt.Errorf("Create: %w", err)
		}
	}

	stored, err := s.repo.Create(ctx, Connector{
		Type: typ, Name: name, Enabled: true, EventSource: eventSource,
	}, func(id string) ([]byte, error) { return s.encryptConfig(id, config) })
	if err != nil {
		return Connector{}, fmt.Errorf("Create: %w", err)
	}
	stored.Config = config // return the plaintext the caller just gave us
	s.record(ctx, AuditActionCreate, stored.ID, map[string]any{
		"type": string(typ), "name": name, "event_source": eventSource,
		"mode": string(stored.Mode), "config_keys": slices.Sorted(maps.Keys(config)),
	})
	return stored.Connector, nil
}

// Get returns a connector with its config decrypted. An aws_org child's
// config comes back with its org's hub credential and ExternalId merged in —
// in memory only; the child's stored config never holds them (resolveChild).
func (s *Service) Get(ctx context.Context, id string) (Connector, error) {
	c, err := s.getStored(ctx, id)
	if err != nil {
		return Connector{}, fmt.Errorf("Get: %w", err)
	}
	if c.Type == TypeAWS && c.Config[ChildKeyOrgConnectorID] != "" {
		if c.Config, err = s.resolveChild(ctx, c.Config); err != nil {
			return Connector{}, fmt.Errorf("Get: connector %s: %w", id, err)
		}
	}
	return c, nil
}

// getStored returns a connector with its config decrypted exactly as stored.
func (s *Service) getStored(ctx context.Context, id string) (Connector, error) {
	stored, err := s.repo.Get(ctx, id)
	if err != nil {
		return Connector{}, fmt.Errorf("getStored: %w", err)
	}
	if err := s.decryptInto(&stored); err != nil {
		return Connector{}, fmt.Errorf("getStored: %w", err)
	}
	return stored.Connector, nil
}

// List returns connectors WITHOUT decrypting config — callers that only need
// metadata never touch credentials. Use Get for the decrypted config.
func (s *Service) List(ctx context.Context, enabledOnly bool) ([]Connector, error) {
	stored, err := s.repo.List(ctx, enabledOnly)
	if err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}
	out := make([]Connector, len(stored))
	for i, sc := range stored {
		out[i] = sc.Connector // Config stays nil
	}
	return out, nil
}

// ConnectorByAccountID returns the enabled AWS connector whose stored role_arn
// (or, for a static-key connector, its aws_account_id config) targets accountID
// — the "which connector can reach this account" lookup the verify_ci_role live
// job needs before attempting a live IAM read. ok is false when no
// connector monitors the account: that account is a blind spot, surfaced as an
// unmonitored_federation finding by the caller rather than an error here.
//
// Decrypts every enabled AWS connector's config to check its account — bounded
// by the (small) count of AWS connectors and called only for the rare
// unmatched-in-batch-sweep targets, so a per-call full decrypt pass is cheap
// enough not to warrant a cached account->connector index.
func (s *Service) ConnectorByAccountID(ctx context.Context, accountID string) (string, bool, error) {
	conns, err := s.List(ctx, true)
	if err != nil {
		return "", false, fmt.Errorf("ConnectorByAccountID: %w", err)
	}
	for _, c := range conns {
		if c.Type != TypeAWS {
			continue
		}
		// The stored config is enough to name the account; an org child need
		// not resolve its credential for that.
		full, err := s.getStored(ctx, c.ID)
		if err != nil {
			return "", false, fmt.Errorf("ConnectorByAccountID: get %q: %w", c.ID, err)
		}
		if awsAccountID(full.Config) == accountID {
			return full.ID, true, nil
		}
	}
	return "", false, nil
}

// awsAccountID extracts the account an AWS connector can reach: an explicit
// aws_account_id key (static-credential connectors) or the account segment of
// its role_arn ("arn:aws:iam::<account>:role/...").
func awsAccountID(cfg map[string]string) string {
	if acc := cfg["aws_account_id"]; acc != "" {
		return acc
	}
	parts := strings.Split(cfg["role_arn"], ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

// Delete removes a connector. Deleting an aws_org connector disables (never
// deletes) its children: they keep their data and history, and cannot sync
// without the org that resolves their credential.
func (s *Service) Delete(ctx context.Context, id string) error {
	stored, err := s.repo.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	if stored.Type == TypeAWSOrg {
		err = s.repo.DeleteOrg(ctx, id)
	} else {
		err = s.repo.Delete(ctx, id)
	}
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	s.record(ctx, AuditActionDelete, id, map[string]any{
		"type": string(stored.Type), "name": stored.Name, "mode": string(stored.Mode),
		"children_disabled": stored.Type == TypeAWSOrg,
	})
	return nil
}

// PurgeAndDelete is the deliberate counterpart to Delete: for a connector
// whose target account/project has been CONFIRMED gone (never inferred from
// staleness alone — see asset.CHRepo.PurgeAccount), it resolves every open
// finding on the account's assets, hard-deletes the assets, then deletes the
// connector itself, in that order — findings must resolve before their
// resource is gone, or ResolveGoneByResourceIDs' lookup finds nothing to act
// on. Requires WithPurge to have wired the asset/finding capabilities;
// without them this returns an error rather than silently deleting only the
// connector row and leaving its data behind.
//
// AWS and Azure resolve an account identity (purgeTargets); any other
// connector type fails with ErrNoAccountIdentity rather than guessing.
func (s *Service) PurgeAndDelete(ctx context.Context, id string) (PurgeResult, error) {
	if s.assets == nil || s.findings == nil {
		return PurgeResult{}, fmt.Errorf("PurgeAndDelete: %w", ErrNoAccountIdentity)
	}
	c, err := s.Get(ctx, id)
	if err != nil {
		return PurgeResult{}, fmt.Errorf("PurgeAndDelete: %w", err)
	}
	targets, err := s.purgeTargets(ctx, c)
	if err != nil {
		return PurgeResult{}, fmt.Errorf("PurgeAndDelete: %w", err)
	}

	result, err := s.purge(ctx, id, targets)
	details := map[string]any{
		"type": string(c.Type), "name": c.Name, "accounts": purgeAccounts(targets),
		"assets_deleted": result.AssetsDeleted, "findings_resolved": result.FindingsResolved,
		"edges_deleted": result.EdgesDeleted,
	}
	if err != nil {
		details["error"] = err.Error()
		s.record(ctx, AuditActionPurgeFailed, id, details)
		return PurgeResult{}, fmt.Errorf("PurgeAndDelete: %w", err)
	}
	s.record(ctx, AuditActionPurge, id, details)
	return result, nil
}

// purge runs PurgeAndDelete's destructive steps. On an error the result
// carries what the steps before it had already removed.
func (s *Service) purge(ctx context.Context, id string, targets []purgeTarget) (PurgeResult, error) {
	var res PurgeResult
	var ids []string
	for _, t := range targets {
		got, err := s.assets.AssetIDsByAccount(ctx, t.provider, t.accountID)
		if err != nil {
			return res, fmt.Errorf("list assets: %w", err)
		}
		ids = append(ids, got...)
	}

	resolved, err := s.findings.ResolveGoneByResourceIDs(ctx, ids)
	if err != nil {
		return res, fmt.Errorf("resolve findings: %w", err)
	}
	res.FindingsResolved = resolved

	// Edges before assets: ids is the only record of what belonged to this
	// account once PurgeAccount below runs — graph_edges carries no
	// account_id column of its own to filter by afterward.
	if res.EdgesDeleted, err = s.assets.PurgeEdgesForAssets(ctx, ids); err != nil {
		return res, fmt.Errorf("purge edges: %w", err)
	}

	for _, t := range targets {
		n, err := s.assets.PurgeAccount(ctx, t.provider, t.accountID)
		if err != nil {
			return res, fmt.Errorf("purge assets: %w", err)
		}
		res.AssetsDeleted += n
	}

	if err := s.repo.Delete(ctx, id); err != nil {
		return res, fmt.Errorf("delete connector: %w", err)
	}
	return res, nil
}

// purgeAccounts names the accounts a purge targets, as provider:account.
func purgeAccounts(targets []purgeTarget) []string {
	out := make([]string, len(targets))
	for i, t := range targets {
		out[i] = t.provider + ":" + t.accountID
	}
	return out
}

// purgeTarget is one provider+account whose assets a purge removes.
type purgeTarget struct{ provider, accountID string }

// azureTenantSettingsAccountKey is the azure_subscription metadata key the
// Azure collector writes with the account of the tenant settings asset the
// subscription shares (internal/collect/azure tenantSettingsAccountKey).
const azureTenantSettingsAccountKey = "tenant_settings_account"

// purgeTargets resolves the accounts a connector's purge removes. For Azure
// that is the subscription, plus the shared tenant settings asset when no
// other Azure connector still writes it — purging it while another connector
// collects the same tenant would only resolve findings that come straight
// back.
func (s *Service) purgeTargets(ctx context.Context, c Connector) ([]purgeTarget, error) {
	switch c.Type {
	case TypeAWS:
		if acct := awsAccountID(c.Config); acct != "" {
			return []purgeTarget{{"aws", acct}}, nil
		}
	case TypeAzure:
		sub := c.Config["subscription_id"]
		if sub == "" {
			break
		}
		targets := []purgeTarget{{"azure", sub}}
		tenant, err := s.tenantAccountOf(ctx, sub)
		if err != nil {
			return nil, fmt.Errorf("purgeTargets: %w", err)
		}
		if tenant == "" {
			return targets, nil
		}
		shared, err := s.tenantSharedByOthers(ctx, c.ID, tenant)
		if err != nil {
			return nil, fmt.Errorf("purgeTargets: %w", err)
		}
		if !shared {
			targets = append(targets, purgeTarget{"azure", tenant})
		}
		return targets, nil
	}
	return nil, fmt.Errorf("purgeTargets: connector type %q: %w", c.Type, ErrNoAccountIdentity)
}

// tenantAccountOf reads which tenant settings account a subscription's
// collector last pointed at; "" when the subscription asset or key is absent.
func (s *Service) tenantAccountOf(ctx context.Context, subscriptionID string) (string, error) {
	md, err := s.assets.AssetMetadata(ctx, "/subscriptions/"+subscriptionID)
	if err != nil {
		return "", fmt.Errorf("tenantAccountOf: %w", err)
	}
	return md[azureTenantSettingsAccountKey], nil
}

// tenantSharedByOthers reports whether any other Azure connector's
// subscription points at the same tenant settings account.
func (s *Service) tenantSharedByOthers(ctx context.Context, selfID, tenant string) (bool, error) {
	conns, err := s.List(ctx, false)
	if err != nil {
		return false, fmt.Errorf("tenantSharedByOthers: %w", err)
	}
	for _, other := range conns {
		if other.ID == selfID || other.Type != TypeAzure {
			continue
		}
		// List leaves config encrypted; the subscription ID needs Get.
		full, err := s.Get(ctx, other.ID)
		if err != nil {
			return false, fmt.Errorf("tenantSharedByOthers: %w", err)
		}
		if full.Config["subscription_id"] == "" {
			continue
		}
		t, err := s.tenantAccountOf(ctx, full.Config["subscription_id"])
		if err != nil {
			return false, fmt.Errorf("tenantSharedByOthers: %w", err)
		}
		if t == tenant {
			return true, nil
		}
	}
	return false, nil
}

// RecordSync stores the outcome of a sync run for a connector.
// UpdateSyncFingerprint stores the connector's current asset content fingerprint.
// Called after a successful ingest so the next sweep can short-circuit
// when nothing changed.
func (s *Service) UpdateSyncFingerprint(ctx context.Context, id, fingerprint string) error {
	if err := s.repo.SetSyncFingerprint(ctx, id, fingerprint); err != nil {
		return fmt.Errorf("UpdateSyncFingerprint: %w", err)
	}
	return nil
}

func (s *Service) GetAssetHashes(ctx context.Context, connectorID string) (map[string]StoredAssetHash, error) {
	hashes, err := s.repo.GetAssetHashes(ctx, connectorID)
	if err != nil {
		return nil, fmt.Errorf("GetAssetHashes: %w", err)
	}
	return hashes, nil
}

// ConnectorsCollecting returns the ids of the enabled connectors whose sync
// currently collects assetID, read from the sync's own per-asset record rather
// than inferred from an account id in the asset. More than one id means the
// asset is reachable through several credentials; the caller decides what an
// ambiguous owner means for it.
func (s *Service) ConnectorsCollecting(ctx context.Context, assetID string) ([]string, error) {
	ids, err := s.repo.CollectingAsset(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("ConnectorsCollecting: %w", err)
	}
	return ids, nil
}

func (s *Service) UpsertAssetHashEntries(ctx context.Context, connectorID string, entries []AssetHashEntry) error {
	if err := s.repo.UpsertAssetHashEntries(ctx, connectorID, entries); err != nil {
		return fmt.Errorf("UpsertAssetHashEntries: %w", err)
	}
	return nil
}

func (s *Service) DeleteAssetHashes(ctx context.Context, connectorID string, ids []string) error {
	if err := s.repo.DeleteAssetHashes(ctx, connectorID, ids); err != nil {
		return fmt.Errorf("DeleteAssetHashes: %w", err)
	}
	return nil
}

// RecordAssetDeletions records the assets a COMPLETE sweep proved deleted — the
// sync's own deletion decision, the same ids whose hashes it drops — so the
// derived-finding jobs can tell a deleted resource from one that merely stopped
// being collected.
func (s *Service) RecordAssetDeletions(ctx context.Context, connectorID string, ids []string, at time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	if err := s.repo.RecordAssetDeletions(ctx, connectorID, ids, at); err != nil {
		return fmt.Errorf("RecordAssetDeletions: %w", err)
	}
	// Housekeeping, best-effort: a record past retention outlives the asset
	// row it describes, and a reader still compares it with last_seen.
	if _, err := s.repo.PruneAssetDeletions(ctx, at.Add(-assetDeletionRetention)); err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("connector: asset deletion prune failed")
	}
	return nil
}

// AssetDeletions returns, for each of ids a sync proved deleted, when.
func (s *Service) AssetDeletions(ctx context.Context, ids []string) (map[string]time.Time, error) {
	out, err := s.repo.AssetDeletions(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("AssetDeletions: %w", err)
	}
	return out, nil
}

// RecordSync stores the outcome of a sync run for a connector. cleanNoOp
// tells the backoff (SyncStreak) whether this was a clean, complete,
// non-backfill sync worth extending the connector's quiet streak for — see
// internal/jobs/sync.go's cleanNoOp helper for how the caller computes it.
//
// partial tells PartialStreak whether some best-effort collector was skipped
// this sync (a permission gap, throttle, or deadline) — kept separate from
// runErr/status: a Partial sync still has runErr == nil and status == SyncOK,
// so without this signal a connector that never once completes a phase reads
// as fully healthy via LastSuccessAt alone (Connector.PartiallyStale is the
// fix — it reads PartialStreak instead).
func (s *Service) RecordSync(ctx context.Context, id string, runErr error, at time.Time, cleanNoOp, partial bool) error {
	status, msg := SyncOK, ""
	if runErr != nil {
		status, msg = SyncError, runErr.Error()
	}
	if err := s.repo.SetSyncResult(ctx, id, status, msg, at, cleanNoOp, partial); err != nil {
		return fmt.Errorf("RecordSync: %w", err)
	}
	return nil
}

// configAAD binds a connector's ciphertext to its row. Without it, the
// ciphertext of a connector holding an admin-scoped credential could be copied
// over a less-privileged connector's row, and the platform would then
// authenticate as the admin credential while every ID, name and audit trail
// still said otherwise.
func configAAD(id string) []byte { return []byte("connector:" + id) }

func (s *Service) encryptConfig(id string, config map[string]string) ([]byte, error) {
	plain, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("encryptConfig: marshal: %w", err)
	}
	enc, err := s.cipher.EncryptWithAAD(plain, configAAD(id))
	if err != nil {
		return nil, fmt.Errorf("encryptConfig: %w", err)
	}
	return enc, nil
}

func (s *Service) decryptInto(sc *storedConnector) error {
	plain, err := s.cipher.DecryptWithAAD(sc.ConfigCiphertext, configAAD(sc.ID))
	if err != nil {
		return fmt.Errorf("decryptInto: %w", err)
	}
	var config map[string]string
	if err := json.Unmarshal(plain, &config); err != nil {
		return fmt.Errorf("decryptInto: unmarshal: %w", err)
	}
	sc.Config = config
	return nil
}

// RewrapAll re-seals every connector whose config is not already an envelope
// under the CURRENT key: the rows still sealed under a retired key after a
// rotation.
//
// It is idempotent and safe to run repeatedly — a row already current is
// skipped, so a second run is a no-op. It is also non-destructive by
// construction: a row is only written after its plaintext has been successfully
// recovered and re-sealed in memory, and a row that cannot be opened is
// reported and LEFT ALONE rather than overwritten. There is no ordering of
// deploy and rewrap that loses a credential, because reads accept the retired
// key throughout. The write is a compare-and-swap on the ciphertext that was read:
// a config edited (UI, org discovery) between the read and the write is not
// clobbered with the stale plaintext — that row is skipped, and it was written
// under the current key anyway.
//
// Returns how many rows were re-sealed.
func (s *Service) RewrapAll(ctx context.Context) (int, error) {
	stored, err := s.repo.List(ctx, false)
	if err != nil {
		return 0, fmt.Errorf("RewrapAll: %w", err)
	}
	var rewrapped int
	for _, sc := range stored {
		if s.cipher.IsCurrentEnvelope(sc.ConfigCiphertext) {
			continue
		}
		plain, err := s.cipher.DecryptWithAAD(sc.ConfigCiphertext, configAAD(sc.ID))
		if err != nil {
			return rewrapped, fmt.Errorf("RewrapAll: connector %s could not be opened (left unchanged): %w", sc.ID, err)
		}
		enc, err := s.cipher.EncryptWithAAD(plain, configAAD(sc.ID))
		if err != nil {
			return rewrapped, fmt.Errorf("RewrapAll: connector %s: %w", sc.ID, err)
		}
		ok, err := s.repo.ResealConfig(ctx, sc.ID, sc.ConfigCiphertext, enc)
		if err != nil {
			return rewrapped, fmt.Errorf("RewrapAll: connector %s: %w", sc.ID, err)
		}
		if ok {
			rewrapped++
		}
	}
	return rewrapped, nil
}

// RecordProvenCapability persists that connectorID's credentials have PROVEN
// capability at least once (monotonic). Idempotent:
// recording an already-proven capability again is a no-op.
func (s *Service) RecordProvenCapability(ctx context.Context, connectorID string, capability ProvenCapability, at time.Time) error {
	if err := s.repo.RecordProvenCapability(ctx, connectorID, capability, at); err != nil {
		return fmt.Errorf("RecordProvenCapability: %w", err)
	}
	return nil
}

// ListProvenCapabilities returns every capability ever proven for a connector.
func (s *Service) ListProvenCapabilities(ctx context.Context, connectorID string) ([]ProvenCapability, error) {
	caps, err := s.repo.ListProvenCapabilities(ctx, connectorID)
	if err != nil {
		return nil, fmt.Errorf("ListProvenCapabilities: %w", err)
	}
	return caps, nil
}

// SetMode upgrades or downgrades a connector between read_only and read_write.
// Changing to read_write signals that the connector's cloud credentials have
// been granted write permissions and executor actions are safe to attempt.
func (s *Service) SetMode(ctx context.Context, id string, mode Mode) error {
	if !mode.Valid() {
		return fmt.Errorf("SetMode: %w", ErrInvalidType)
	}
	before, err := s.repo.SetMode(ctx, id, mode)
	if err != nil {
		return fmt.Errorf("SetMode: %w", err)
	}
	s.record(ctx, AuditActionModeChange, id, map[string]any{"before": string(before), "after": string(mode)})
	return nil
}
