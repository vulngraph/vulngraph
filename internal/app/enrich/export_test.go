package enrich

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestExportBandsJSONIsFresh fails when the frontend's copy of the band
// boundaries drifts from the Go constants. Regenerate with
// `go run ./cmd/scoreband-gen`.
func TestExportBandsJSONIsFresh(t *testing.T) {
	want, err := ExportBandsJSON()
	require.NoError(t, err)
	got, err := os.ReadFile("../../../" + BandsJSONPath)
	require.NoError(t, err, "generated file missing — run `go run ./cmd/scoreband-gen`")
	require.Equal(t, string(want), string(got),
		BandsJSONPath+" is stale — run `go run ./cmd/scoreband-gen`")
}

// TestExportBandsMatchBandFor pins each exported min_score to the boundary
// bandFor actually uses, so the export cannot list a threshold the scorer
// does not apply.
func TestExportBandsMatchBandFor(t *testing.T) {
	b, err := ExportBandsJSON()
	require.NoError(t, err)
	var doc exportBandsDoc
	require.NoError(t, json.Unmarshal(b, &doc))
	require.Len(t, doc.Bands, 4)
	for i, eb := range doc.Bands {
		require.Equal(t, eb.Band, bandFor(uint8(eb.MinScore)), "min_score %d of %s", eb.MinScore, eb.Band)
		if eb.MinScore > 0 {
			require.NotEqual(t, eb.Band, bandFor(uint8(eb.MinScore-1)), "%s must start at %d", eb.Band, eb.MinScore)
		}
		if i > 0 {
			require.Less(t, eb.MinScore, doc.Bands[i-1].MinScore, "bands are listed highest first")
		}
	}
}
