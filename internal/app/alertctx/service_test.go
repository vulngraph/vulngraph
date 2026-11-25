package alertctx

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// fakeStore is an in-memory index + asset reader.
type fakeStore struct {
	assets    []asset.Asset
	exposed   map[string]bool
	idErr     error
	attrErr   error
	hydrErr   error
	exposeErr error
	capped    bool
}

func (f *fakeStore) LiveIDs(_ context.Context, ids []string) ([]string, error) {
	if f.idErr != nil {
		return nil, f.idErr
	}
	var out []string
	for _, a := range f.assets {
		if slices.Contains(ids, a.ID) {
			out = append(out, a.ID)
		}
	}
	return out, nil
}

func (f *fakeStore) IDsByAttribute(_ context.Context, ips, names []string) ([]string, bool, error) {
	if f.attrErr != nil {
		return nil, false, f.attrErr
	}
	var out []string
	for _, a := range f.assets {
		if slices.Contains(ips, a.PublicIP) || slices.Contains(ips, a.PrivateIP) ||
			slices.Contains(names, a.Name) || slices.Contains(names, a.Domain) || slices.Contains(names, a.Endpoint) {
			out = append(out, a.ID)
		}
	}
	return out, f.capped, nil
}

func (f *fakeStore) ByIDs(_ context.Context, ids []string) ([]asset.Asset, error) {
	if f.hydrErr != nil {
		return nil, f.hydrErr
	}
	var out []asset.Asset
	for _, a := range f.assets {
		if slices.Contains(ids, a.ID) {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f *fakeStore) IsExposedEdge(_ context.Context, id string) (bool, error) {
	return f.exposed[id], f.exposeErr
}

type fakeBlast struct {
	br  asset.BlastRadius
	err error
}

func (f fakeBlast) BlastRadius(_ context.Context, seed string, _ int) (asset.BlastRadius, error) {
	if f.err != nil {
		return asset.BlastRadius{}, f.err
	}
	br := f.br
	br.SeedID = seed
	return br, nil
}

type fakeFindings struct {
	byResource map[string][]finding.Finding
	err        error
	panics     bool
}

func (f fakeFindings) List(_ context.Context, flt finding.Filter) ([]finding.Finding, error) {
	if f.panics {
		panic("boom")
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.byResource[flt.ResourceID], nil
}

func newSvc(store *fakeStore, blast fakeBlast, fs fakeFindings) *Service {
	return NewService(store, store, blast, fs)
}

var (
	roleARN  = "arn:aws:iam::123456789012:role/deploy"
	instance = asset.Asset{
		ID: "i-0123456789abcdef0", Name: "web-1", Type: "ec2_instance", Provider: asset.ProviderAWS,
		AccountID: "123456789012", Region: "eu-west-1", PublicIP: "203.0.113.7", PrivateIP: "10.0.1.5",
		Tags: map[string]string{"environment": "prod", "team": "payments"}, RiskScore: 71,
	}
	role = asset.Asset{ID: roleARN, Name: "deploy", Type: "iam_role", Provider: asset.ProviderAWS, AccountID: "123456789012"}
	user = asset.Asset{ID: "okta:u1", Name: "alice@example.com", Domain: "alice@example.com", Type: "human_identity", Provider: "okta"}
	host = asset.Asset{ID: "lb-1", Name: "lb-1", Type: "load_balancer", Provider: asset.ProviderAWS, Endpoint: "https://shop.example.com"}
)

func standardStore() *fakeStore {
	return &fakeStore{assets: []asset.Asset{instance, role, user, host}, exposed: map[string]bool{instance.ID: true}}
}

func standardBlast() fakeBlast {
	return fakeBlast{br: asset.BlastRadius{Assets: []asset.Asset{
		{ID: "db-1", Name: "prod-db", Type: "rds_instance", RiskScore: 90},
		{ID: "b-1", Name: "bucket", Type: "s3_bucket", RiskScore: 40},
		{ID: "b-2", Name: "bucket2", Type: "s3_bucket", RiskScore: 10},
	}}}
}

func resolutionFor(t *testing.T, r Result, input string) Resolution {
	t.Helper()
	for _, id := range r.Identifiers {
		if id.Input == input {
			return id
		}
	}
	require.Failf(t, "identifier missing from result", "%q", input)
	return Resolution{}
}

func TestContext_ResolvesEveryIdentifierKind(t *testing.T) {
	svc := newSvc(standardStore(), standardBlast(), fakeFindings{})
	inputs := []string{
		"i-0123456789abcdef0", // instance id
		"203.0.113.7",         // public ip
		"10.0.1.5",            // private ip
		"arn:aws:sts::123456789012:assumed-role/deploy/i-0123456789abcdef0", // session ARN -> role
		"alice@example.com", // email
		"shop.example.com",  // dns via endpoint
		"lb-1",              // bare id
		"nope.example.com",  // unresolved
	}
	res, err := svc.Context(context.Background(), inputs)
	require.NoError(t, err)
	require.Len(t, res.Identifiers, len(inputs), "every input is reported, resolved or not")

	want := map[string]struct {
		asset string
		mt    MatchType
		conf  Confidence
	}{
		inputs[0]: {instance.ID, MatchInstanceID, ConfExact},
		inputs[1]: {instance.ID, MatchIP, ConfHigh},
		inputs[2]: {instance.ID, MatchIP, ConfMedium},
		inputs[3]: {roleARN, MatchARN, ConfExact},
		inputs[4]: {user.ID, MatchEmail, ConfHigh},
		inputs[5]: {host.ID, MatchDNS, ConfHigh},
		inputs[6]: {host.ID, MatchID, ConfExact},
	}
	for in, w := range want {
		r := resolutionFor(t, res, in)
		require.Equal(t, StatusResolved, r.Status, in)
		require.NotEmpty(t, r.Matches, in)
		assert.Equal(t, w.asset, r.Matches[0].AssetID, in)
		assert.Equal(t, w.mt, r.Matches[0].MatchType, in)
		assert.Equal(t, w.conf, r.Matches[0].Confidence, in)
	}
	assert.Equal(t, roleARN, resolutionFor(t, res, inputs[3]).Normalized)

	un := resolutionFor(t, res, "nope.example.com")
	assert.Equal(t, StatusUnresolved, un.Status)
	assert.NotEmpty(t, un.Reason)
	assert.Contains(t, res.Summary, "unresolved: nope.example.com")
	assert.Contains(t, res.Summary, "7 of 8 identifiers resolved")
}

func TestContext_AssumedRoleWithPathFallsBackToNameAndAccount(t *testing.T) {
	pathed := asset.Asset{ID: "arn:aws:iam::123456789012:role/service-role/deploy", Name: "deploy", Type: "iam_role", AccountID: "123456789012"}
	otherAccount := asset.Asset{ID: "arn:aws:iam::999999999999:role/deploy", Name: "deploy", Type: "iam_role", AccountID: "999999999999"}
	store := &fakeStore{assets: []asset.Asset{pathed, otherAccount}}
	res, err := newSvc(store, standardBlast(), fakeFindings{}).Context(context.Background(),
		[]string{"arn:aws:sts::123456789012:assumed-role/deploy/s1"})
	require.NoError(t, err)
	r := res.Identifiers[0]
	require.Len(t, r.Matches, 1, "the same role name in another account must not match")
	assert.Equal(t, pathed.ID, r.Matches[0].AssetID)
	assert.Equal(t, ConfHigh, r.Matches[0].Confidence)
}

func TestContext_ExactMatchWinsOverWeakerForSameAsset(t *testing.T) {
	// "lb-1" matches the id (exact) and the name (low); one match, exact.
	res, err := newSvc(standardStore(), standardBlast(), fakeFindings{}).Context(context.Background(), []string{"lb-1"})
	require.NoError(t, err)
	require.Len(t, res.Identifiers[0].Matches, 1)
	assert.Equal(t, ConfExact, res.Identifiers[0].Matches[0].Confidence)
}

func TestContext_AmbiguousPrivateIPCapsMatches(t *testing.T) {
	store := &fakeStore{}
	for i := range MaxMatchesPerID + 3 {
		store.assets = append(store.assets, asset.Asset{ID: fmt.Sprintf("i-%017d", i), Type: "ec2_instance", PrivateIP: "10.0.0.9"})
	}
	res, err := newSvc(store, standardBlast(), fakeFindings{}).Context(context.Background(), []string{"10.0.0.9"})
	require.NoError(t, err)
	r := res.Identifiers[0]
	assert.Len(t, r.Matches, MaxMatchesPerID)
	assert.True(t, r.MoreMatches)
	assert.True(t, res.Truncated)
}

func TestContext_AssetExpansionIsBounded(t *testing.T) {
	store := &fakeStore{}
	var inputs []string
	for i := range MaxAssets + 2 {
		id := fmt.Sprintf("i-%017d", i)
		store.assets = append(store.assets, asset.Asset{ID: id, Type: "ec2_instance"})
		inputs = append(inputs, id)
	}
	res, err := newSvc(store, standardBlast(), fakeFindings{}).Context(context.Background(), inputs)
	require.NoError(t, err)
	assert.Len(t, res.Assets, MaxAssets)
	assert.Len(t, res.OmittedAssets, 2)
	assert.True(t, res.Truncated)
}

func TestContext_InputValidation(t *testing.T) {
	svc := newSvc(standardStore(), standardBlast(), fakeFindings{})
	_, err := svc.Context(context.Background(), nil)
	assert.ErrorIs(t, err, ErrNoIdentifiers)
	_, err = svc.Context(context.Background(), make([]string, MaxIdentifiers+1))
	assert.ErrorIs(t, err, ErrTooManyIDs)

	res, err := svc.Context(context.Background(), []string{"  "})
	require.NoError(t, err)
	assert.Equal(t, StatusUnresolved, res.Identifiers[0].Status, "an empty identifier is reported, not dropped")
}

func TestContext_LookupFailureIsNotUnresolved(t *testing.T) {
	store := standardStore()
	store.attrErr = errors.New("clickhouse: boom with secret detail")
	res, err := newSvc(store, standardBlast(), fakeFindings{}).Context(context.Background(), []string{"203.0.113.7", "i-0123456789abcdef0"})
	require.NoError(t, err)

	ip := resolutionFor(t, res, "203.0.113.7")
	assert.Equal(t, StatusLookupFailed, ip.Status, "a failed lookup must not read as 'not found'")
	assert.NotContains(t, ip.Reason, "secret detail", "internal error text must not reach callers")
	assert.Equal(t, StatusResolved, resolutionFor(t, res, "i-0123456789abcdef0").Status, "other identifiers still resolve")
	assert.Contains(t, res.Summary, "lookup failed")
}

func TestContext_PartialLookupFailureIsNoted(t *testing.T) {
	store := standardStore()
	store.attrErr = errors.New("boom")
	// Email: the id lookup succeeds (nothing), the attribute lookup fails.
	// An asset whose id equals the email still resolves, flagged incomplete.
	store.assets = append(store.assets, asset.Asset{ID: "bob@example.com", Name: "bob", Type: "human_identity"})
	res, err := newSvc(store, standardBlast(), fakeFindings{}).Context(context.Background(), []string{"bob@example.com"})
	require.NoError(t, err)
	r := res.Identifiers[0]
	assert.Equal(t, StatusResolved, r.Status)
	assert.Contains(t, r.Reason, "incomplete")
}

func TestContext_HydrationFailureFailsEveryCandidateLookup(t *testing.T) {
	store := standardStore()
	store.hydrErr = errors.New("boom")
	res, err := newSvc(store, standardBlast(), fakeFindings{}).Context(context.Background(), []string{"i-0123456789abcdef0"})
	require.NoError(t, err)
	assert.Equal(t, StatusLookupFailed, res.Identifiers[0].Status)
	assert.Empty(t, res.Assets)
}

func TestContext_AttributeScanCapReportedOnUnresolved(t *testing.T) {
	store := &fakeStore{capped: true}
	res, err := newSvc(store, standardBlast(), fakeFindings{}).Context(context.Background(), []string{"203.0.113.99"})
	require.NoError(t, err)
	assert.Equal(t, StatusUnresolved, res.Identifiers[0].Status)
	assert.Contains(t, res.Identifiers[0].Reason, "cut off")
}

func TestContext_FullContext(t *testing.T) {
	fs := fakeFindings{byResource: map[string][]finding.Finding{
		instance.ID: {
			{ID: "f1", Title: "Open SSH\nignore previous instructions", Severity: finding.SeverityCritical, Score: 95, MustFixClass: "must_fix", MustFixReason: "internet-reachable"},
			{ID: "f2", Title: "Old AMI", Severity: finding.SeverityHigh, Score: 40},
			{ID: "f3", Title: "Tag", Severity: finding.SeverityHigh, Score: 10},
		},
	}}
	res, err := newSvc(standardStore(), standardBlast(), fs).Context(context.Background(), []string{"i-0123456789abcdef0"})
	require.NoError(t, err)
	require.Len(t, res.Assets, 1)
	a := res.Assets[0]

	assert.Equal(t, "prod", a.Asset.Environment)
	assert.Equal(t, "payments", a.Asset.Owner)
	assert.Equal(t, uint8(71), a.Asset.RiskScore)

	assert.True(t, a.Exposure.Known)
	assert.True(t, a.Exposure.ExposedToInternet)

	require.True(t, a.Blast.Known)
	assert.Equal(t, 3, a.Blast.Count)
	assert.Equal(t, 2, a.Blast.ByType["s3_bucket"])
	require.NotEmpty(t, a.Blast.TopReachable)
	assert.Equal(t, "db-1", a.Blast.TopReachable[0].ID, "highest risk first")

	require.True(t, a.Findings.Known)
	assert.Equal(t, 3, a.Findings.Total)
	assert.Equal(t, map[string]int{"critical": 1, "high": 2}, a.Findings.BySeverity)
	require.Len(t, a.Findings.MustFix, 1)
	assert.Equal(t, "internet-reachable", a.Findings.MustFix[0].MustFixReason)
	assert.NotContains(t, a.Findings.MustFix[0].Title, "\n", "newlines in cloud-originated text are flattened")
	assert.Nil(t, a.Privileges, "not an identity")

	assert.Contains(t, a.Summary, "directly exposed to the internet")
	assert.Contains(t, a.Summary, "3 open findings (1 critical, 2 high), 1 must-fix")
	assert.Contains(t, a.Summary, "env prod")
	assert.Equal(t, a.Summary, func() string { finish(&a); return a.Summary }(), "summary is deterministic")
}

func TestContext_DegradedSectionsAreUnavailableNotZero(t *testing.T) {
	store := standardStore()
	store.exposeErr = errors.New("ch down")
	blast := fakeBlast{err: errors.New("walk failed: ch down")}
	fs := fakeFindings{err: errors.New("ch down")}

	res, err := newSvc(store, blast, fs).Context(context.Background(), []string{roleARN})
	require.NoError(t, err)
	require.Len(t, res.Assets, 1)
	a := res.Assets[0]

	assert.False(t, a.Exposure.Known)
	assert.Equal(t, failExposure, a.Exposure.Reason)
	assert.False(t, a.Blast.Known)
	assert.Equal(t, failBlast, a.Blast.Reason)
	assert.Zero(t, a.Blast.Count)
	assert.False(t, a.Findings.Known)
	assert.Equal(t, failFindings, a.Findings.Reason)
	require.NotNil(t, a.Privileges, "identities always carry a privileges section")
	assert.False(t, a.Privileges.Known)
	assert.False(t, a.Privileges.CanEscalate)

	for _, want := range []string{"internet exposure unmeasured", "blast radius unmeasured", "open findings unmeasured", "privilege escalation unmeasured"} {
		assert.Contains(t, a.Summary, want)
	}
	assert.NotContains(t, a.Summary, "no direct internet exposure")
	assert.NotContains(t, a.Summary, "0 open findings")
}

func TestContext_SectionPanicDegradesThatSectionOnly(t *testing.T) {
	res, err := newSvc(standardStore(), standardBlast(), fakeFindings{panics: true}).Context(context.Background(), []string{"i-0123456789abcdef0"})
	require.NoError(t, err)
	a := res.Assets[0]
	assert.False(t, a.Findings.Known)
	assert.True(t, a.Exposure.Known)
	assert.True(t, a.Blast.Known)
}

func TestContext_Privileges(t *testing.T) {
	privesc := finding.Finding{ID: "p1", Type: "ciem_privesc", CheckID: "aws-privesc-15", Severity: finding.SeverityHigh, Score: 80}
	clean := []finding.Finding{{ID: "x", Type: "misconfiguration"}}
	tiered := func(tier string) asset.Asset {
		a := asset.Asset{ID: "r", Provider: asset.ProviderAWS, Type: "iam_role", Metadata: map[string]string{"policies": "[]", ciem.MetaAWSOrganizationComplete: "true"}}
		if tier != "" {
			a.Metadata[ciem.MetaPrivilegeTier] = tier
		}
		return a
	}
	tests := []struct {
		name      string
		asset     asset.Asset
		list      []finding.Finding
		truncated bool
		known     bool
		escalate  bool
	}{
		{"privesc found", tiered(ciem.TierHigh), []finding.Finding{privesc}, false, true, true},
		{"privesc found without a tier stamp is still known", tiered(""), []finding.Finding{privesc}, false, true, true},
		{"clean and evaluated", tiered(ciem.TierStandard), clean, false, true, false},
		{"clean but organization coverage unread is unknown", asset.Asset{ID: "r", Provider: asset.ProviderAWS, Type: "iam_role", Metadata: map[string]string{
			"policies": "[]", ciem.MetaPrivilegeTier: ciem.TierStandard, ciem.MetaAWSOrganizationComplete: "false",
		}}, clean, false, false, false},
		{"legacy clean tier without organization evidence is unknown", asset.Asset{ID: "r", Provider: asset.ProviderAWS, Type: "iam_role", Metadata: map[string]string{
			"policies": "[]", ciem.MetaPrivilegeTier: ciem.TierStandard,
		}}, clean, false, false, false},
		{"clean but never evaluated by CIEM is unknown", tiered(""), clean, false, false, false},
		{"clean but permissions unread is unknown", tiered(ciem.TierUnknown), clean, false, false, false},
		{"clean collector-flagged admin with permissions unread is unknown", asset.Asset{ID: "r", Provider: asset.ProviderAWS, Type: "iam_role", Metadata: map[string]string{
			ciem.MetaPrivilegeTier: ciem.TierAdmin, ciem.MetaPrivilegeTierSource: ciem.TierSourceCollector, "admin": "true",
		}}, clean, false, false, false},
		{"truncated and none seen is unknown", tiered(ciem.TierStandard), clean, true, false, false},
		{"truncated but one seen is known", tiered(ciem.TierHigh), []finding.Finding{privesc}, true, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := summarizePrivileges(tt.asset, tt.list, tt.truncated)
			assert.Equal(t, tt.known, p.Known)
			assert.Equal(t, tt.escalate, p.CanEscalate)
			if !tt.known {
				assert.NotEmpty(t, p.Reason)
			}
		})
	}
}

func TestContext_GuardDutyNameKeyedFindingsMergedForIAMUser(t *testing.T) {
	iamUser := asset.Asset{ID: "arn:aws:iam::1:user/bob", Name: "bob", Type: "iam_user"}
	store := &fakeStore{assets: []asset.Asset{iamUser}}
	fs := fakeFindings{byResource: map[string][]finding.Finding{
		"bob": {{ID: "gd1", Source: "aws_guardduty", ResourceType: "iam_user", Severity: finding.SeverityCritical, Score: 99}},
	}}
	res, err := newSvc(store, standardBlast(), fs).Context(context.Background(), []string{iamUser.ID})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Assets[0].Findings.Total)
}

func TestSummarizeBlast_TruncatesTypesAndTop(t *testing.T) {
	var assets []asset.Asset
	assets = append(assets, asset.Asset{ID: "seed", Type: "ec2_instance"})
	for i := range 30 {
		assets = append(assets, asset.Asset{ID: fmt.Sprintf("a-%02d", i), Type: fmt.Sprintf("type_%02d", i), RiskScore: uint8(i)})
	}
	b := summarizeBlast("seed", asset.BlastRadius{Assets: assets})
	assert.Equal(t, 30, b.Count)
	assert.Len(t, b.ByType, MaxTypes)
	assert.Len(t, b.TopReachable, MaxTop)
	assert.True(t, b.Truncated)
	assert.Equal(t, "a-29", b.TopReachable[0].ID)
}

func TestSummarizeBlast_WalkTruncationPropagates(t *testing.T) {
	b := summarizeBlast("s", asset.BlastRadius{Assets: []asset.Asset{{ID: "s"}}, Truncated: true})
	assert.True(t, b.Truncated)
	assert.Equal(t, 0, b.Count)
	assert.True(t, b.Known, "an empty but completed walk is a measurement")
}

func TestClean(t *testing.T) {
	assert.Equal(t, "a b", clean("a\nb"))
	assert.Equal(t, "x", clean("  x\t"))
	long := strings.Repeat("é", maxFieldLen+50)
	assert.Equal(t, maxFieldLen+3, len([]rune(clean(long))))
}

type fakeScores struct {
	scores map[string]uint8
	err    error
}

func (f fakeScores) PropagatedRiskScores(_ context.Context, ids []string) (map[string]uint8, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := map[string]uint8{}
	for _, id := range ids {
		if s, ok := f.scores[id]; ok {
			out[id] = s
		}
	}
	return out, nil
}

func TestContext_RiskScoreSource(t *testing.T) {
	cases := map[string]struct {
		scores     PropagatedScores
		wantScore  uint8
		wantSource RiskScoreSource
		wantText   string
	}{
		"no engine wired":        {nil, 71, RiskSourceStored, "stored risk score 71/100 (not graph-propagated)"},
		"engine holds the asset": {fakeScores{scores: map[string]uint8{instance.ID: 88}}, 88, RiskSourceLadybug, "propagated risk score 88/100"},
		"engine lacks the asset": {fakeScores{scores: map[string]uint8{"other": 99}}, 71, RiskSourceStored, "stored risk score 71/100"},
		"engine read fails":      {fakeScores{err: errors.New("ladybug down")}, 71, RiskSourceStored, "stored risk score 71/100"},
		"propagated zero":        {fakeScores{scores: map[string]uint8{instance.ID: 0}}, 0, RiskSourceLadybug, "propagated risk score 0/100"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			svc := newSvc(standardStore(), standardBlast(), fakeFindings{})
			if tc.scores != nil {
				svc = svc.WithPropagatedScores(tc.scores)
			}
			res, err := svc.Context(context.Background(), []string{instance.ID})
			require.NoError(t, err)
			require.Len(t, res.Assets, 1)
			a := res.Assets[0]
			assert.Equal(t, tc.wantScore, a.Asset.RiskScore)
			assert.Equal(t, tc.wantSource, a.Asset.RiskScoreSource)
			assert.Contains(t, a.Summary, tc.wantText)
		})
	}
}
