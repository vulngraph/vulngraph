package reasoncache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fingerprintWithVersion recomputes Fingerprint's hash construction with an
// arbitrary version prefix instead of the real LogicVersion constant, so
// tests can simulate "what a caller would compute after a bump" without
// editing the package constant.
func fingerprintWithVersion(in FingerprintInput, version string) string {
	var b strings.Builder
	b.WriteString(version)
	b.WriteByte('\n')
	writeLegacyBody(&b, in)
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// fakeRepo is an in-memory Repo for exercising Service without Postgres.
type fakeRepo struct {
	entries map[string]Entry
}

func newFakeRepo() *fakeRepo { return &fakeRepo{entries: map[string]Entry{}} }

func (f *fakeRepo) Get(_ context.Context, findingID string) (Entry, error) {
	e, ok := f.entries[findingID]
	if !ok {
		return Entry{}, ErrNotFound
	}
	return e, nil
}

func (f *fakeRepo) ListPending(context.Context, int, string) ([]Entry, error) { return nil, nil }

func (f *fakeRepo) Upsert(_ context.Context, e Entry) error {
	f.entries[e.FindingID] = e
	return nil
}

func (f *fakeRepo) IncrementRepeat(context.Context, string) error { return nil }

func (f *fakeRepo) TopEscalatedRepeats(context.Context, int) ([]Entry, error) { return nil, nil }

func (f *fakeRepo) DeleteForFindings(_ context.Context, findingIDs []string) error {
	for _, id := range findingIDs {
		delete(f.entries, id)
	}
	return nil
}

func (f *fakeRepo) PurgeAll(_ context.Context) (int64, error) {
	n := int64(len(f.entries))
	f.entries = map[string]Entry{}
	return n, nil
}

func TestService_DeleteForFindings_ForcesAMiss(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := NewService(repo)

	require.NoError(t, svc.Put(ctx, Entry{FindingID: "f1", Fingerprint: "fp-1"}))
	require.NoError(t, svc.Put(ctx, Entry{FindingID: "f2", Fingerprint: "fp-2"}))

	require.NoError(t, svc.DeleteForFindings(ctx, []string{"f1"}))

	_, err := svc.Get(ctx, "f1")
	require.ErrorIs(t, err, ErrNotFound, "deleted finding must miss")

	got, err := svc.Get(ctx, "f2")
	require.NoError(t, err, "untouched finding must survive")
	require.Equal(t, "fp-2", got.Fingerprint)
}

func TestService_InvalidateAll_PurgesEveryEntry(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := NewService(repo)

	require.NoError(t, svc.Put(ctx, Entry{FindingID: "f1", Fingerprint: "fp-1"}))
	require.NoError(t, svc.Put(ctx, Entry{FindingID: "f2", Fingerprint: "fp-2"}))

	n, err := svc.InvalidateAll(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(2), n)

	for _, id := range []string{"f1", "f2"} {
		_, err := svc.Get(ctx, id)
		require.ErrorIs(t, err, ErrNotFound, "InvalidateAll must purge %s", id)
	}
}

// TestService_LogicVersionBump_ForcesRecompute is the end-to-end shape of the
// hard requirement: a caller (respond.planFor in production) comparing a
// freshly computed fingerprint against a stored one must treat a version-N
// entry as a miss once the fingerprint scheme has moved to version N+1.
func TestService_LogicVersionBump_ForcesRecompute(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := NewService(repo)

	in := FingerprintInput{FindingID: "f1", CheckID: "c1", Type: "exposure", ScoreBand: "pipeline"}
	fpUnderCurrent := Fingerprint(in)
	require.NoError(t, svc.Put(ctx, Entry{FindingID: "f1", Fingerprint: fpUnderCurrent}))

	got, err := svc.Get(ctx, "f1")
	require.NoError(t, err)
	require.Equal(t, fpUnderCurrent, got.Fingerprint, "cache hit under the same version")

	// Simulate the fingerprint a caller would compute after a LogicVersion
	// bump: same inputs, different version prefix. It must not equal what is
	// stored, which is what makes respond.planFor treat the entry as stale.
	fpUnderNext := fingerprintWithVersion(in, "v5")
	require.NotEqual(t, got.Fingerprint, fpUnderNext,
		"a key computed under the next version must not be served as a hit under the current one")
}
