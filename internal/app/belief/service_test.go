package belief

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type memStore struct {
	saved   []Belief
	crystIn []CrystallizationInput // returned by CrystallizationInputs
}

func (m *memStore) CrystallizationInputs(context.Context) ([]CrystallizationInput, error) {
	return m.crystIn, nil
}

func (m *memStore) AdjudicationCandidates(context.Context, uint8, time.Time, int) ([]string, error) {
	return nil, nil
}

func (m *memStore) Upsert(_ context.Context, bs []Belief) error {
	m.saved = append(m.saved, bs...)
	return nil
}

// latestByProvenance mirrors the CH read: the latest write per (finding,
// provenance), as argMax(created_at) over the ReplacingMergeTree returns.
func (m *memStore) latestByProvenance(id string) []Belief {
	byProv := map[string]Belief{}
	var order []string
	for _, b := range m.saved {
		if b.FindingID != id {
			continue
		}
		if _, seen := byProv[b.Provenance]; !seen {
			order = append(order, b.Provenance)
		}
		byProv[b.Provenance] = b
	}
	out := make([]Belief, 0, len(order))
	for _, p := range order {
		out = append(out, byProv[p])
	}
	return out
}

func (m *memStore) GetByFinding(_ context.Context, id string) (Belief, error) {
	b, ok := Effective(m.latestByProvenance(id))
	if !ok {
		return Belief{}, ErrNotFound
	}
	return b, nil
}

func (m *memStore) GetByProvenance(_ context.Context, id, provenance string) (Belief, error) {
	for _, b := range m.latestByProvenance(id) {
		if b.Provenance == provenance {
			return b, nil
		}
	}
	return Belief{}, ErrNotFound
}

func TestService_FormPersistsGroundedBelief(t *testing.T) {
	st := &memStore{}
	s := NewService(st)
	s.now = func() time.Time { return time.Unix(0, 0) }

	b, err := s.Form(context.Background(), SeverityInputs{
		FindingID: "f1", ResourceID: "role/admin", Score: 92, Band: "page",
		MustFixClass: "controlled", MustFixReason: "IdP federation", TrustEntry: "federated",
	})
	require.NoError(t, err)
	require.Equal(t, finding.SeverityLow, b.Severity)
	require.Len(t, st.saved, 1, "belief persisted")

	got, err := s.Get(context.Background(), "f1")
	require.NoError(t, err)
	require.Equal(t, "role/admin", got.ResourceID)

	_, err = s.Get(context.Background(), "missing")
	require.ErrorIs(t, err, ErrNotFound)
}
