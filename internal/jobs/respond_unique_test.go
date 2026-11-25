package jobs

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// River keys a ByArgs-unique job on its river:"unique" fields when any exist,
// else on the whole encoded args. DecideArgs must key on the finding ID alone:
// hashing the whole Finding let a score/timestamp refresh enqueue a second
// concurrent decide for the same finding.
func TestDecideArgs_UniqueOnFindingIDOnly(t *testing.T) {
	typ := reflect.TypeOf(DecideArgs{})
	var unique []string
	for i := range typ.NumField() {
		if typ.Field(i).Tag.Get("river") == "unique" {
			unique = append(unique, typ.Field(i).Name)
		}
	}
	require.Equal(t, []string{"FindingID"}, unique)
	require.True(t, DecideArgs{}.InsertOpts().UniqueOpts.ByArgs)
}

func TestDecideArgs_MarshalFillsFindingID(t *testing.T) {
	a := DecideArgs{Finding: finding.Finding{ID: "f1", Score: 40}}
	b := DecideArgs{Finding: finding.Finding{ID: "f1", Score: 90, EnrichedAt: time.Now()}}

	var gotA, gotB struct {
		FindingID string `json:"finding_id"`
	}
	rawA, err := json.Marshal(a)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(rawA, &gotA))
	rawB, err := json.Marshal(b)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(rawB, &gotB))
	require.Equal(t, "f1", gotA.FindingID)
	require.Equal(t, gotA, gotB)

	var round DecideArgs
	require.NoError(t, json.Unmarshal(rawA, &round))
	require.Equal(t, "f1", round.Finding.ID, "the worker still reads the full finding")

	explicit, err := json.Marshal(DecideArgs{FindingID: "x", Finding: finding.Finding{ID: "f1"}})
	require.NoError(t, err)
	require.Contains(t, string(explicit), `"finding_id":"x"`)
}
