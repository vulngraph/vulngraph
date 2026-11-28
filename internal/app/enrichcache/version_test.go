package enrichcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeVersionRepo records SetLastFullPassVersion calls and serves a canned version.
type fakeVersionRepo struct {
	sweep   SweepProgress
	stored  string
	readErr error
	setTo   []string
}

func (f *fakeVersionRepo) GetSweepProgress(context.Context) (SweepProgress, error) {
	return f.sweep, f.readErr
}

func (f *fakeVersionRepo) AdvanceSweepProgress(_ context.Context, revision int64, next SweepProgress) (bool, error) {
	if f.sweep.Revision != revision {
		return false, nil
	}
	next.Revision = revision + 1
	f.sweep = next
	return true, nil
}

func (f *fakeVersionRepo) Get(context.Context, string) (Entry, error) { return Entry{}, ErrNotFound }
func (f *fakeVersionRepo) Upsert(context.Context, Entry) error        { return nil }
func (f *fakeVersionRepo) InvalidateFingerprints(context.Context, []string) error {
	return nil
}

func (f *fakeVersionRepo) AlertState(context.Context, string) (AlertState, error) {
	return AlertState{}, ErrNotFound
}
func (f *fakeVersionRepo) RecordAlert(context.Context, AlertState) error { return nil }
func (f *fakeVersionRepo) ClearAlertStates(context.Context, []string) error {
	return nil
}
func (f *fakeVersionRepo) PruneAlertStates(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (f *fakeVersionRepo) LastFullPassVersion(context.Context) (string, error) {
	return f.stored, f.readErr
}

func (f *fakeVersionRepo) SetLastFullPassVersion(_ context.Context, v string) error {
	f.setTo = append(f.setTo, v)
	return nil
}

func TestFullPassNeeded(t *testing.T) {
	tests := []struct {
		name    string
		repo    *fakeVersionRepo
		want    bool
		wantErr bool
	}{
		{
			name: "same version — corpus already processed, no pass",
			repo: &fakeVersionRepo{stored: LogicVersion},
			want: false,
		},
		{
			name: "older version — semantics changed, pass needed",
			repo: &fakeVersionRepo{stored: "v0"},
			want: true,
		},
		{
			// The migration seeds "", so a new deployment runs one pass on first
			// boot.
			name: "never passed (empty) — pass needed",
			repo: &fakeVersionRepo{stored: ""},
			want: true,
		},
		{
			// Fail-safe: a redundant pass is recoverable; a skipped one leaves the
			// corpus silently serving stale verdicts, which is the bug this exists to
			// prevent. So a read error must report "needed", never "no".
			name:    "read error fails SAFE — reports needed",
			repo:    &fakeVersionRepo{readErr: errors.New("pg down")},
			want:    true,
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			needed, _, err := NewService(tc.repo).FullPassNeeded(context.Background())
			require.Equal(t, tc.want, needed)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestMarkFullPassComplete_RecordsDeployedVersion(t *testing.T) {
	repo := &fakeVersionRepo{stored: "v0"}
	require.NoError(t, NewService(repo).MarkFullPassComplete(context.Background()))
	require.Equal(t, []string{LogicVersion}, repo.setTo,
		"must record the version actually deployed, not the one previously stored")
}

// The fingerprint prefix and the full-pass watermark must be driven by ONE constant.
// Two constants would let the change-gate recompute while the trigger stayed quiet
// (or the reverse) — a half-applied engine change, which is exactly the failure this
// mechanism exists to close. This recomputes the hash independently, prefixed with
// LogicVersion, and requires it to match: if Fingerprint stopped using the constant,
// this fails.
func TestLogicVersionDrivesTheFingerprintPrefix(t *testing.T) {
	in := FingerprintInput{
		FindingID: "f1", CheckID: "c", Type: "misconfiguration", Severity: "high",
		ResourceID: "r", PrivescBucket: "0",
	}

	var b strings.Builder
	b.WriteString(LogicVersion)
	b.WriteByte('\n')
	b.WriteString(in.FindingID)
	b.WriteByte('\n')
	b.WriteString(in.CheckID)
	b.WriteByte('\n')
	b.WriteString(in.Type)
	b.WriteByte('\n')
	b.WriteString(in.Severity)
	b.WriteByte('\n')
	b.WriteString(in.ResourceID)
	b.WriteByte('\n')
	b.WriteString(in.PrivescBucket)
	b.WriteByte('\n')
	b.WriteString(in.ReachBucket)
	b.WriteByte('\n')
	sum := sha256.Sum256([]byte(b.String()))

	require.NotEmpty(t, LogicVersion)
	require.Equal(t, hex.EncodeToString(sum[:]), Fingerprint(in),
		"Fingerprint must prefix its hashed material with LogicVersion — otherwise bumping "+
			"the version invalidates nothing and the change-gate keeps serving stale scores")
}

func TestFullPassNeeded_DoesNotRecordAPass(t *testing.T) {
	repo := &fakeVersionRepo{stored: "v0"}
	_, _, err := NewService(repo).FullPassNeeded(context.Background())
	require.NoError(t, err)
	require.Empty(t, repo.setTo, "checking whether a pass is needed must never record one as done")
}

// clearingRepo records which ids lost alert state and fingerprints.
type clearingRepo struct {
	fakeVersionRepo
	cleared, invalidated []string
	clearErr             error
}

func (r *clearingRepo) ClearAlertStates(_ context.Context, ids []string) error {
	r.cleared = append(r.cleared, ids...)
	return r.clearErr
}

func (r *clearingRepo) InvalidateFingerprints(_ context.Context, ids []string) error {
	r.invalidated = append(r.invalidated, ids...)
	return nil
}

// Resolving ends the alert episode (a regression re-alerts) and clears the
// fingerprint (the regression is re-enriched on its first visit). Both writes
// run even when one fails.
func TestFindingsResolved_EndsTheAlertEpisode(t *testing.T) {
	repo := &clearingRepo{}
	require.NoError(t, NewService(repo).FindingsResolved(context.Background(), []string{"f1"}))
	require.Equal(t, []string{"f1"}, repo.cleared)
	require.Equal(t, []string{"f1"}, repo.invalidated)

	repo = &clearingRepo{clearErr: errors.New("pg down")}
	require.Error(t, NewService(repo).FindingsResolved(context.Background(), []string{"f2"}))
	require.Equal(t, []string{"f2"}, repo.invalidated)
}

// v1 could store a monitor-band score from a role name alone. Unchanged graph
// inputs must not keep that score fresh after the scoring repair.
func TestNameSuppressionRepairInvalidatesV1Scores(t *testing.T) {
	in := FingerprintInput{FindingID: "f1", CheckID: "aws-privesc-16", Type: "misconfiguration", Severity: "critical", ResourceID: "arn:aws:iam::111:role/github-actions-deploy", PrivescBucket: "1", ReachBucket: "none"}
	const oldBody = "f1\naws-privesc-16\nmisconfiguration\ncritical\narn:aws:iam::111:role/github-actions-deploy\n1\nnone\n"
	oldInput := sha256.Sum256([]byte("v1\n" + oldBody))
	oldContext := sha256.Sum256([]byte(oldBody))
	require.NotEqual(t, hex.EncodeToString(oldInput[:]), Fingerprint(in))
	require.Equal(t, hex.EncodeToString(oldContext[:]), ContextFingerprint(in))
	repo := &fakeVersionRepo{stored: "v1"}
	needed, previous, err := NewService(repo).FullPassNeeded(t.Context())
	require.NoError(t, err)
	require.True(t, needed, "standing v1 findings must receive a full rescore")
	require.Equal(t, "v1", previous)
}
