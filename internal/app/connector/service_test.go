package connector

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/diskscan"
)

// fakeRepo stores connectors with their config still encrypted, like the real
// repo — so tests exercise the true encrypt-on-write / decrypt-on-read path.
type fakeRepo struct {
	rows          map[string]storedConnector
	nextID        int
	getCalls      int
	orgBatchCalls int
	orgBatchErr   error
	// provenCapabilities mirrors the real (connector_id, capability) primary
	// key: a map keyed on connector id, of sets of capability, so recording
	// the same capability twice is naturally idempotent like the real
	// ON CONFLICT DO NOTHING.
	provenCapabilities map[string]map[ProvenCapability]time.Time
	collecting         map[string][]string
	orgAccounts        map[string]map[string]OrgAccount
	// beforeReseal, when set, runs inside ResealConfig before the
	// compare — it simulates a concurrent writer landing mid-rewrap.
	beforeReseal func(id string)
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{rows: map[string]storedConnector{}, provenCapabilities: map[string]map[ProvenCapability]time.Time{}}
}

func (f *fakeRepo) Create(_ context.Context, c Connector, encrypt func(id string) ([]byte, error)) (storedConnector, error) {
	for _, existing := range f.rows {
		if existing.Type == c.Type && existing.Name == c.Name {
			return storedConnector{}, ErrNameTaken
		}
	}
	f.nextID++
	c.ID = string(rune('a' + f.nextID))
	if c.Mode == "" {
		c.Mode = ModeReadOnly // the column default
	}
	// Same ordering as the real repo: the id exists before the config is
	// sealed, because the ciphertext is bound to it.
	configEnc, err := encrypt(c.ID)
	if err != nil {
		return storedConnector{}, err
	}
	sc := storedConnector{Connector: c, ConfigCiphertext: configEnc}
	f.rows[c.ID] = sc
	return sc, nil
}

func (f *fakeRepo) UpdateConfig(_ context.Context, id string, configEnc []byte) error {
	sc, ok := f.rows[id]
	if !ok {
		return ErrNotFound
	}
	sc.ConfigCiphertext = configEnc
	f.rows[id] = sc
	return nil
}

func (f *fakeRepo) ResealConfig(_ context.Context, id string, old, sealed []byte) (bool, error) {
	if f.beforeReseal != nil {
		f.beforeReseal(id)
	}
	sc, ok := f.rows[id]
	if !ok || !bytes.Equal(sc.ConfigCiphertext, old) {
		return false, nil
	}
	sc.ConfigCiphertext = sealed
	f.rows[id] = sc
	return true, nil
}

func (f *fakeRepo) Get(_ context.Context, id string) (storedConnector, error) {
	f.getCalls++
	sc, ok := f.rows[id]
	if !ok {
		return storedConnector{}, ErrNotFound
	}
	return sc, nil
}

func (f *fakeRepo) List(_ context.Context, enabledOnly bool) ([]storedConnector, error) {
	var out []storedConnector
	for _, sc := range f.rows {
		if enabledOnly && !sc.Enabled {
			continue
		}
		out = append(out, sc)
	}
	return out, nil
}

func (f *fakeRepo) Delete(_ context.Context, id string) error {
	if _, ok := f.rows[id]; !ok {
		return ErrNotFound
	}
	delete(f.rows, id)
	return nil
}

func (f *fakeRepo) SetDiskScan(_ context.Context, id string, mode diskscan.DiskScanMode, by string, at time.Time) (diskscan.DiskScanMode, error) {
	sc, ok := f.rows[id]
	if !ok {
		return "", ErrNotFound
	}
	prev := sc.DiskScanMode
	sc.DiskScanMode, sc.DiskScanEnabledBy, sc.DiskScanEnabledAt = mode, "", nil
	if mode.Enabled() {
		sc.DiskScanEnabledBy, sc.DiskScanEnabledAt = by, &at
	}
	f.rows[id] = sc
	return prev, nil
}

func (f *fakeRepo) SetSyncResult(_ context.Context, id string, status SyncStatus, syncErr string, at time.Time, cleanNoOp, partial bool) error {
	sc, ok := f.rows[id]
	if !ok {
		return ErrNotFound
	}
	sc.SyncStatus, sc.SyncError, sc.LastSyncedAt = status, syncErr, &at
	if cleanNoOp {
		sc.SyncStreak++
	} else {
		sc.SyncStreak = 0
	}
	if partial {
		sc.PartialStreak++
	} else {
		sc.PartialStreak = 0
	}
	f.rows[id] = sc
	return nil
}

func (f *fakeRepo) SetSyncFingerprint(_ context.Context, id, fp string) error {
	sc, ok := f.rows[id]
	if !ok {
		return ErrNotFound
	}
	sc.SyncFingerprint = fp
	f.rows[id] = sc
	return nil
}

func (f *fakeRepo) GetAssetHashes(_ context.Context, _ string) (map[string]StoredAssetHash, error) {
	return nil, nil
}

func (f *fakeRepo) CollectingAsset(_ context.Context, assetID string) ([]string, error) {
	return f.collecting[assetID], nil
}

func (f *fakeRepo) UpsertAssetHashEntries(_ context.Context, _ string, _ []AssetHashEntry) error {
	return nil
}

func (f *fakeRepo) DeleteAssetHashes(_ context.Context, _ string, _ []string) error {
	return nil
}

func (f *fakeRepo) ObserveDeletionCandidates(_ context.Context, _ string, _ []string, _, _ time.Time, _ int) ([]string, error) {
	return nil, nil
}

func (f *fakeRepo) RecordAssetDeletions(_ context.Context, _ string, ids []string, _ time.Time) ([]string, error) {
	return ids, nil
}

func (f *fakeRepo) PendingAssetRetirements(context.Context, int) (map[string]time.Time, error) {
	return nil, nil
}
func (f *fakeRepo) CompleteAssetRetirements(context.Context, map[string]time.Time) error { return nil }

func (f *fakeRepo) PruneAssetDeletions(_ context.Context, _ time.Time) (int64, error) { return 0, nil }

func (f *fakeRepo) AssetDeletions(_ context.Context, _ []string) (map[string]time.Time, error) {
	return map[string]time.Time{}, nil
}

func (f *fakeRepo) SetMode(_ context.Context, id string, mode Mode) (Mode, error) {
	sc, ok := f.rows[id]
	if !ok {
		return "", ErrNotFound
	}
	prev := sc.Mode
	sc.Mode = mode
	f.rows[id] = sc
	return prev, nil
}

func (f *fakeRepo) RecordProvenCapability(_ context.Context, connectorID string, capability ProvenCapability, at time.Time) error {
	caps, ok := f.provenCapabilities[connectorID]
	if !ok {
		caps = map[ProvenCapability]time.Time{}
		f.provenCapabilities[connectorID] = caps
	}
	// Monotonic, like the real ON CONFLICT DO NOTHING: never overwrite an
	// existing first_proven_at.
	if _, already := caps[capability]; !already {
		caps[capability] = at
	}
	return nil
}

func (f *fakeRepo) ListProvenCapabilities(_ context.Context, connectorID string) ([]ProvenCapability, error) {
	var out []ProvenCapability
	for c := range f.provenCapabilities[connectorID] {
		out = append(out, c)
	}
	return out, nil
}

func newTestService(t *testing.T) (*Service, *fakeRepo) {
	t.Helper()
	cipher, err := NewCipher(testKey(t))
	require.NoError(t, err)
	repo := newFakeRepo()
	return NewService(repo, cipher), repo
}

var awsConfig = map[string]string{"role_arn": "arn:aws:iam::1:role/x", "region": "eu-west-1"}

func TestCreate_EncryptsConfigAtRest(t *testing.T) {
	svc, repo := newTestService(t)

	c, err := svc.Create(context.Background(), TypeAWS, "prod", awsConfig, "")
	require.NoError(t, err)
	require.NotEmpty(t, c.ID)

	stored := repo.rows[c.ID]
	require.NotContains(t, string(stored.ConfigCiphertext), "role/x", "raw credential must not appear in stored bytes")
	require.NotContains(t, string(stored.ConfigCiphertext), "eu-west-1")
}

func TestGet_DecryptsConfig(t *testing.T) {
	svc, _ := newTestService(t)

	created, err := svc.Create(context.Background(), TypeAWS, "prod", awsConfig, "")
	require.NoError(t, err)

	got, err := svc.Get(context.Background(), created.ID)
	require.NoError(t, err)
	require.Equal(t, awsConfig, got.Config)
}

func TestList_NeverReturnsConfig(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.Create(context.Background(), TypeAWS, "prod", awsConfig, "")
	require.NoError(t, err)

	list, err := svc.List(context.Background(), false)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Nil(t, list[0].Config, "List must not decrypt credentials")
}

func TestCreate_Validation(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	tests := []struct {
		name    string
		typ     Type
		cname   string
		config  map[string]string
		wantErr error
	}{
		{"empty name", TypeAWS, "", awsConfig, ErrMissingName},
		{"bad type", Type("bogus"), "x", awsConfig, ErrInvalidType},
		{"missing aws region", TypeAWS, "x", map[string]string{"role_arn": "a"}, ErrMissingConfig},
		{"aws region only, no credential", TypeAWS, "x", map[string]string{"region": "eu-west-1"}, ErrMissingConfig},
		{"missing gcp key", TypeGCP, "x", map[string]string{}, ErrMissingConfig},
		{"missing github key", TypeGitHub, "x", map[string]string{"app_id": "1"}, ErrMissingConfig},
		{"missing azure subscription_id", TypeAzure, "x", map[string]string{}, ErrMissingConfig},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.Create(ctx, tt.typ, tt.cname, tt.config, "")
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// Under OIDC a GCP connector is secretless: project_id alone is a
// complete config, no service-account key required.
// AWS accepts static keys (region + aws_access_key_id) as a migration path
// from an existing asset-inventory tool, not just role_arn.
func TestCreate_AWSStaticKeysAccepted(t *testing.T) {
	svc, _ := newTestService(t)
	c, err := svc.Create(context.Background(), TypeAWS, "static-acct",
		map[string]string{"region": "eu-west-1", "aws_access_key_id": "AKIA", "aws_secret_access_key": "s"}, "")
	require.NoError(t, err)
	require.Equal(t, "static-acct", c.Name)
}

func TestCreate_GCPSecretless(t *testing.T) {
	svc, _ := newTestService(t)
	c, err := svc.Create(context.Background(), TypeGCP, "prod", map[string]string{"project_id": "p"}, "")
	require.NoError(t, err)
	require.Equal(t, TypeGCP, c.Type)
}

func TestCreate_DuplicateNamePerType(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	_, err := svc.Create(ctx, TypeAWS, "prod", awsConfig, "")
	require.NoError(t, err)
	_, err = svc.Create(ctx, TypeAWS, "prod", awsConfig, "")
	require.ErrorIs(t, err, ErrNameTaken)

	// Same name under a different type is allowed.
	_, err = svc.Create(ctx, TypeGitHub, "prod",
		map[string]string{"app_id": "1", "installation_id": "2", "private_key_pem": "k"}, "")
	require.NoError(t, err)
}

func TestRecordSync(t *testing.T) {
	svc, repo := newTestService(t)
	created, err := svc.Create(context.Background(), TypeAWS, "prod", awsConfig, "")
	require.NoError(t, err)
	at := time.Now()

	require.NoError(t, svc.RecordSync(context.Background(), created.ID, nil, at, true, false))
	require.Equal(t, SyncOK, repo.rows[created.ID].SyncStatus)
	require.EqualValues(t, 1, repo.rows[created.ID].SyncStreak, "a clean no-op sync advances the streak")
	require.Zero(t, repo.rows[created.ID].PartialStreak)

	require.NoError(t, svc.RecordSync(context.Background(), created.ID, errors.New("boom"), at, false, false))
	require.Equal(t, SyncError, repo.rows[created.ID].SyncStatus)
	require.Equal(t, "boom", repo.rows[created.ID].SyncError)
	require.Zero(t, repo.rows[created.ID].SyncStreak, "a failed sync resets the streak")
}

// TestRecordSync_PartialStreak pins the invisibility gap that lets an AWS
// connector repeatedly fail its global-services phase while still reading as
// fully healthy: a Partial sync
// still has runErr == nil (status stays SyncOK, LastSuccessAt still
// advances), so PartialStreak — not SyncStatus/LastSuccessAt — is the only
// signal that catches it.
func TestRecordSync_PartialStreak(t *testing.T) {
	svc, repo := newTestService(t)
	created, err := svc.Create(context.Background(), TypeAWS, "prod", awsConfig, "")
	require.NoError(t, err)
	at := time.Now()

	require.NoError(t, svc.RecordSync(context.Background(), created.ID, nil, at, false, true))
	require.Equal(t, SyncOK, repo.rows[created.ID].SyncStatus, "a Partial sync with runErr==nil still reports SyncOK")
	require.EqualValues(t, 1, repo.rows[created.ID].PartialStreak)

	require.NoError(t, svc.RecordSync(context.Background(), created.ID, nil, at, false, true))
	require.EqualValues(t, 2, repo.rows[created.ID].PartialStreak, "consecutive Partial syncs accumulate")
	require.True(t, Connector{Enabled: true, PartialStreak: repo.rows[created.ID].PartialStreak}.PartiallyStale(DefaultPartialStreakThreshold+1) == false)

	require.NoError(t, svc.RecordSync(context.Background(), created.ID, nil, at, false, false))
	require.Zero(t, repo.rows[created.ID].PartialStreak, "a non-Partial sync resets the streak even though nothing else changed")
}

// ---- envelope migration ----

// End-to-end version of the replay guard: two connectors, one privileged. The
// privileged row's ciphertext copied over the other row must not open, so the
// platform can never be made to authenticate as the wrong credential while
// every id, name and audit row says otherwise.
func TestService_ConfigCiphertextIsBoundToItsConnector(t *testing.T) {
	svc, repo := newTestService(t)
	ctx := context.Background()

	admin, err := svc.Create(ctx, TypeAWS, "admin-account",
		map[string]string{"region": "eu-west-1", "role_arn": "arn:aws:iam::1:role/admin"}, "")
	require.NoError(t, err)
	limited, err := svc.Create(ctx, TypeAWS, "limited-account",
		map[string]string{"region": "eu-west-1", "role_arn": "arn:aws:iam::2:role/limited"}, "")
	require.NoError(t, err)

	// Someone with Postgres write access swaps the ciphertext.
	stolen := repo.rows[admin.ID].ConfigCiphertext
	require.NoError(t, repo.UpdateConfig(ctx, limited.ID, stolen))

	_, err = svc.Get(ctx, limited.ID)
	require.Error(t, err, "an admin credential replayed onto another row must not be usable")

	// The row it legitimately belongs to is unaffected.
	got, err := svc.Get(ctx, admin.ID)
	require.NoError(t, err)
	require.Equal(t, "arn:aws:iam::1:role/admin", got.Config["role_arn"])
}

func TestService_CreateSealsUnderTheCurrentKey(t *testing.T) {
	svc, repo := newTestService(t)
	c, err := svc.Create(context.Background(), TypeGCP, "proj", map[string]string{"project_id": "p"}, "")
	require.NoError(t, err)
	require.True(t, svc.cipher.IsCurrentEnvelope(repo.rows[c.ID].ConfigCiphertext))
}

// Key rotation: rows sealed under the previous key are re-sealed under the new
// one while the old key is trusted for reads only, and stay readable after the
// old key is dropped.
func TestService_RewrapAllMovesRetiredKeyRowsToCurrentKey(t *testing.T) {
	ctx := context.Background()
	oldKey, newKey := testKey(t), testKey(t)
	oldCipher, err := NewCipher(oldKey)
	require.NoError(t, err)
	repo := newFakeRepo()
	c, err := NewService(repo, oldCipher).Create(ctx, TypeGCP, "proj", map[string]string{"project_id": "p"}, "")
	require.NoError(t, err)

	rotating, err := NewCipher(newKey)
	require.NoError(t, err)
	rotating, err = rotating.WithRetiredKey(oldKey)
	require.NoError(t, err)
	n, err := NewService(repo, rotating).RewrapAll(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)

	newOnly, err := NewCipher(newKey)
	require.NoError(t, err)
	got, err := NewService(repo, newOnly).Get(ctx, c.ID)
	require.NoError(t, err)
	require.Equal(t, "p", got.Config["project_id"])
}

// A row that cannot be opened must be reported and LEFT ALONE — overwriting it
// would turn an unreadable credential into a destroyed one.
func TestService_RewrapAllLeavesUnopenableRowsUntouched(t *testing.T) {
	svc, repo := newTestService(t)
	ctx := context.Background()

	c, err := svc.Create(ctx, TypeGCP, "proj", map[string]string{"project_id": "p"}, "")
	require.NoError(t, err)

	garbage := []byte("this was never a ciphertext")
	require.NoError(t, repo.UpdateConfig(ctx, c.ID, garbage))

	_, err = svc.RewrapAll(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), c.ID, "the error must name the row that needs attention")
	require.Equal(t, garbage, repo.rows[c.ID].ConfigCiphertext, "an unopenable row must not be overwritten")
}

// A config written between RewrapAll's read and its write (a UI edit, org
// discovery) must win: re-sealing the stale plaintext over it would silently
// revert the edit.
func TestService_RewrapAllDoesNotClobberConcurrentEdit(t *testing.T) {
	ctx := context.Background()
	oldKey, newKey := testKey(t), testKey(t)
	oldCipher, err := NewCipher(oldKey)
	require.NoError(t, err)
	repo := newFakeRepo()
	c, err := NewService(repo, oldCipher).Create(ctx, TypeGCP, "proj", map[string]string{"project_id": "old"}, "")
	require.NoError(t, err)

	// A rotation in progress: the row is sealed under the now-retired key.
	rotating, err := NewCipher(newKey)
	require.NoError(t, err)
	rotating, err = rotating.WithRetiredKey(oldKey)
	require.NoError(t, err)
	svc := NewService(repo, rotating)

	edited, err := svc.cipher.EncryptWithAAD([]byte(`{"project_id":"new"}`), configAAD(c.ID))
	require.NoError(t, err)
	repo.beforeReseal = func(id string) {
		require.NoError(t, repo.UpdateConfig(ctx, id, edited))
	}

	n, err := svc.RewrapAll(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, n, "a lost compare-and-swap is not a rewrap")
	got, err := svc.Get(ctx, c.ID)
	require.NoError(t, err)
	require.Equal(t, "new", got.Config["project_id"], "the concurrent edit must survive")
}

// fakeAssetPurger records what it was asked to purge/list, scoped by
// provider+accountID exactly like the real ClickHouse repo.
type fakeAssetPurger struct {
	idsByAccount   map[string][]string // "provider/accountID" -> asset IDs
	purged         []string            // "provider/accountID" entries actually purged
	purgeErr       error
	edgesPurgedIDs []string // ids PurgeEdgesForAssets was called with
	edgesPurgeErr  error
	metadata       map[string]map[string]string // asset ID -> metadata
}

func (f *fakeAssetPurger) AssetMetadata(_ context.Context, id string) (map[string]string, error) {
	return f.metadata[id], nil
}

func (f *fakeAssetPurger) AssetIDsByAccount(_ context.Context, provider, accountID string) ([]string, error) {
	return f.idsByAccount[provider+"/"+accountID], nil
}

func (f *fakeAssetPurger) PurgeAccount(_ context.Context, provider, accountID string) (int, error) {
	if f.purgeErr != nil {
		return 0, f.purgeErr
	}
	key := provider + "/" + accountID
	f.purged = append(f.purged, key)
	return len(f.idsByAccount[key]), nil
}

func (f *fakeAssetPurger) PurgeEdgesForAssets(_ context.Context, ids []string) (int, error) {
	if f.edgesPurgeErr != nil {
		return 0, f.edgesPurgeErr
	}
	f.edgesPurgedIDs = append(f.edgesPurgedIDs, ids...)
	return len(ids), nil
}

// fakeFindingResolver records which resource IDs it was asked to resolve.
type fakeFindingResolver struct {
	resolvedIDs []string
	resolveErr  error
}

func (f *fakeFindingResolver) ResolveGoneByResourceIDs(_ context.Context, ids []string) (int, error) {
	if f.resolveErr != nil {
		return 0, f.resolveErr
	}
	f.resolvedIDs = append(f.resolvedIDs, ids...)
	return len(ids), nil
}

func TestPurgeAndDelete_HappyPath(t *testing.T) {
	svc, repo := newTestService(t)
	ctx := context.Background()

	c, err := svc.Create(ctx, TypeAWS, "aws-123456789012", map[string]string{
		"role_arn": "arn:aws:iam::123456789012:role/x", "region": "eu-west-1",
	}, "")
	require.NoError(t, err)

	assets := &fakeAssetPurger{idsByAccount: map[string][]string{
		"aws/123456789012": {"asset-1", "asset-2", "asset-3"},
	}}
	findings := &fakeFindingResolver{}
	svc.WithPurge(assets, findings)

	result, err := svc.PurgeAndDelete(ctx, c.ID)
	require.NoError(t, err)
	require.Equal(t, 3, result.AssetsDeleted)
	require.Equal(t, 3, result.FindingsResolved)
	require.Equal(t, 3, result.EdgesDeleted)
	require.ElementsMatch(t, []string{"asset-1", "asset-2", "asset-3"}, findings.resolvedIDs)
	// Edges must be purged using the asset ID list gathered BEFORE PurgeAccount
	// runs — it's the only record of what belonged to this account once the
	// assets table row is gone.
	require.ElementsMatch(t, []string{"asset-1", "asset-2", "asset-3"}, assets.edgesPurgedIDs)
	require.Contains(t, assets.purged, "aws/123456789012")

	_, err = repo.Get(ctx, c.ID)
	require.ErrorIs(t, err, ErrNotFound, "the connector row must be gone too")
}

// TestPurgeAndDelete_EdgePurgeFailure_StopsBeforeAssetsDeleted guards the
// ordering: if the edges purge fails, PurgeAccount must never run — otherwise
// the asset ID list needed to retry the edge purge is gone for good.
func TestPurgeAndDelete_EdgePurgeFailure_StopsBeforeAssetsDeleted(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	c, err := svc.Create(ctx, TypeAWS, "aws-999", map[string]string{
		"role_arn": "arn:aws:iam::999:role/x", "region": "eu-west-1",
	}, "")
	require.NoError(t, err)

	assets := &fakeAssetPurger{
		idsByAccount:  map[string][]string{"aws/999": {"asset-1"}},
		edgesPurgeErr: errors.New("boom"),
	}
	svc.WithPurge(assets, &fakeFindingResolver{})

	_, err = svc.PurgeAndDelete(ctx, c.ID)
	require.Error(t, err)
	require.Empty(t, assets.purged, "PurgeAccount must not run when the edge purge failed")

	// The connector must still exist — nothing was actually purged.
	_, err = svc.Get(ctx, c.ID)
	require.NoError(t, err)
}

func TestPurgeAndDelete_NotWired_ErrNoAccountIdentity(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	c, err := svc.Create(ctx, TypeAWS, "aws-123", awsConfig, "")
	require.NoError(t, err)

	// WithPurge was never called — e.g. a server wiring gap.
	_, err = svc.PurgeAndDelete(ctx, c.ID)
	require.ErrorIs(t, err, ErrNoAccountIdentity)
}

func TestPurgeAndDelete_NonAWSConnector_ErrNoAccountIdentity(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	c, err := svc.Create(ctx, TypeGCP, "gcp-proj", map[string]string{"project_id": "p"}, "")
	require.NoError(t, err)
	svc.WithPurge(&fakeAssetPurger{idsByAccount: map[string][]string{}}, &fakeFindingResolver{})

	_, err = svc.PurgeAndDelete(ctx, c.ID)
	require.ErrorIs(t, err, ErrNoAccountIdentity)
}

// An Azure purge removes the subscription's assets, and the tenant settings
// asset it shares only when no other Azure connector still writes it.
func TestPurgeAndDelete_AzureTenantAssetGoesWithTheLastConnector(t *testing.T) {
	ctx := context.Background()
	const tenant = "azure-tenant:t1:app1"
	setup := func(t *testing.T, otherSub string) (*Service, *fakeAssetPurger, *fakeFindingResolver, string) {
		svc, _ := newTestService(t)
		c, err := svc.Create(ctx, TypeAzure, "sub-a", map[string]string{"subscription_id": "sub-a", "tenant_id": "t1"}, "")
		require.NoError(t, err)
		_, err = svc.Create(ctx, TypeAzure, otherSub, map[string]string{"subscription_id": otherSub, "tenant_id": "t1"}, "")
		require.NoError(t, err)
		assets := &fakeAssetPurger{
			idsByAccount: map[string][]string{
				"azure/sub-a":     {"/subscriptions/sub-a", "/subscriptions/sub-a/vm1"},
				"azure/" + tenant: {tenant},
			},
			metadata: map[string]map[string]string{
				"/subscriptions/sub-a": {"tenant_settings_account": tenant},
				"/subscriptions/sub-b": {"tenant_settings_account": tenant},
				"/subscriptions/sub-c": {"tenant_settings_account": "azure-tenant:t1:other-app"},
			},
		}
		findings := &fakeFindingResolver{}
		svc.WithPurge(assets, findings)
		return svc, assets, findings, c.ID
	}

	t.Run("last connector for the tenant and app", func(t *testing.T) {
		svc, assets, findings, id := setup(t, "sub-c")
		res, err := svc.PurgeAndDelete(ctx, id)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"azure/sub-a", "azure/" + tenant}, assets.purged)
		require.Contains(t, findings.resolvedIDs, tenant, "the tenant asset's findings resolve before it is deleted")
		require.Equal(t, 3, res.AssetsDeleted)
	})
	t.Run("another connector still writes the tenant asset", func(t *testing.T) {
		svc, assets, findings, id := setup(t, "sub-b")
		_, err := svc.PurgeAndDelete(ctx, id)
		require.NoError(t, err)
		require.Equal(t, []string{"azure/sub-a"}, assets.purged)
		require.NotContains(t, findings.resolvedIDs, tenant)
	})
}

func TestPurgeAndDelete_ConnectorNotFound(t *testing.T) {
	svc, _ := newTestService(t)
	svc.WithPurge(&fakeAssetPurger{idsByAccount: map[string][]string{}}, &fakeFindingResolver{})

	_, err := svc.PurgeAndDelete(context.Background(), "ghost")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestProvenCapability_RoundTrip(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	c, err := svc.Create(ctx, TypeAWS, "aws-123", awsConfig, "")
	require.NoError(t, err)

	caps, err := svc.ListProvenCapabilities(ctx, c.ID)
	require.NoError(t, err)
	require.Empty(t, caps, "nothing proven yet")

	at := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	require.NoError(t, svc.RecordProvenCapability(ctx, c.ID, CapabilitySSOAdmin, at))

	caps, err = svc.ListProvenCapabilities(ctx, c.ID)
	require.NoError(t, err)
	require.Equal(t, []ProvenCapability{CapabilitySSOAdmin}, caps)
}

func TestProvenCapability_RecordingTwiceIsIdempotent(t *testing.T) {
	svc, repo := newTestService(t)
	ctx := context.Background()

	c, err := svc.Create(ctx, TypeAWS, "aws-123", awsConfig, "")
	require.NoError(t, err)

	first := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	second := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	require.NoError(t, svc.RecordProvenCapability(ctx, c.ID, CapabilitySSOAdmin, first))
	require.NoError(t, svc.RecordProvenCapability(ctx, c.ID, CapabilitySSOAdmin, second))

	caps, err := svc.ListProvenCapabilities(ctx, c.ID)
	require.NoError(t, err)
	require.Equal(t, []ProvenCapability{CapabilitySSOAdmin}, caps, "recording twice must not duplicate the capability")
	require.Equal(t, first, repo.provenCapabilities[c.ID][CapabilitySSOAdmin],
		"proof is monotonic: the second, later call must not overwrite first_proven_at")
}

func TestConnectorsCollecting_ReturnsEveryCollector(t *testing.T) {
	repo := newFakeRepo()
	repo.collecting = map[string][]string{"sg-1": {"c1", "c2"}}
	cipher, err := NewCipher(testKey(t))
	require.NoError(t, err)
	svc := NewService(repo, cipher)

	ids, err := svc.ConnectorsCollecting(context.Background(), "sg-1")
	require.NoError(t, err)
	require.Equal(t, []string{"c1", "c2"}, ids, "both owners come back; choosing one is the caller's call")

	ids, err = svc.ConnectorsCollecting(context.Background(), "sg-unknown")
	require.NoError(t, err)
	require.Empty(t, ids)
}
