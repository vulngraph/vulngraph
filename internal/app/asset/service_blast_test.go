package asset

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func assertBlastAccounts(t *testing.T, full BlastRadius, counts BlastAccountCounts) {
	t.Helper()
	want, unknown := map[string]int{}, 0
	for _, a := range full.Assets {
		if a.ID == full.SeedID {
			continue
		}
		if a.AccountID == "" {
			unknown++
		} else {
			want[a.AccountID]++
		}
	}
	require.Equal(t, len(full.Assets)-1, counts.Total)
	require.Equal(t, full.Truncated, counts.Truncated)
	for account, n := range want {
		require.Equal(t, n, counts.ByAccount[account], account)
	}
	gotUnknown := 0
	for account, n := range counts.ByAccount {
		if _, known := want[account]; !known {
			require.Equal(t, 1, n, "accountless nodes must not share a discount")
			gotUnknown++
		}
	}
	require.Equal(t, unknown, gotUnknown)
}

func TestBlastAccountSummaryMatchesFullWalk(t *testing.T) {
	for _, size := range []int{0, 20, 520} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			repo := newFakeRepo()
			repo.addAsset("seed")
			for i := range size {
				id := fmt.Sprint(i)
				if i%7 != 0 {
					account := ""
					if i%5 != 0 {
						account = fmt.Sprint("account-", i%3)
					}
					repo.assets[id] = Asset{ID: id, AccountID: account, Name: id}
				}
				repo.link("seed", id, "runs_in")
				repo.link(id, "seed", "runs_in")
			}
			svc := NewService(repo)
			for _, depth := range []int{0, 1, 2, 3} {
				full, err := svc.BlastRadius(t.Context(), "seed", depth)
				require.NoError(t, err)
				counts, err := svc.BlastRadiusAccounts(t.Context(), "seed", depth)
				require.NoError(t, err)
				assertBlastAccounts(t, full, counts)
			}
		})
	}
}

type failedAccountRepo struct {
	*fakeRepo
	calls   int
	lookups [][]string
	failAt  int
	err     error
}

func (r *failedAccountRepo) AccountsByIDs(ctx context.Context, ids []string) (map[string]string, error) {
	r.calls++
	r.lookups = append(r.lookups, append([]string(nil), ids...))
	if r.calls == r.failAt {
		return nil, r.err
	}
	return r.fakeRepo.AccountsByIDs(ctx, ids)
}

func TestBlastAccountFailuresCannotEstablishDistribution(t *testing.T) {
	svc := NewService(newFakeRepo())
	_, err := svc.BlastRadiusAccounts(t.Context(), "missing", 2)
	require.ErrorIs(t, err, ErrNotFound)
	repo := &failedAccountRepo{fakeRepo: newFakeRepo(), failAt: 1, err: errors.New("read failed")}
	repo.addAsset("seed")
	repo.addAsset("other")
	repo.link("seed", "other", "runs_in")
	counts, err := NewService(repo).BlastRadiusAccounts(t.Context(), "seed", 2)
	require.ErrorIs(t, err, repo.err)
	require.Nil(t, counts.ByAccount)
}

func TestBlastAccountSummaryReadsSeedAndAccountsTogether(t *testing.T) {
	repo := &failedAccountRepo{fakeRepo: newFakeRepo()}
	repo.addAsset("seed")
	repo.addAsset("other")
	repo.link("seed", "other", "runs_in")
	counts, err := NewService(repo).BlastRadiusAccounts(t.Context(), "seed", 2)
	require.NoError(t, err)
	require.Equal(t, 1, counts.Total)
	require.Equal(t, 1, repo.calls, "seed validation and account hydration need only one current-version read")
	require.ElementsMatch(t, []string{"seed", "other"}, repo.lookups[0])
	delete(repo.assets, "seed")
	counts, err = NewService(repo).BlastRadiusAccounts(t.Context(), "seed", 2)
	require.ErrorIs(t, err, ErrNotFound, "orphaned edges must not establish a measured distribution for an absent seed")
	require.Nil(t, counts.ByAccount)
}
