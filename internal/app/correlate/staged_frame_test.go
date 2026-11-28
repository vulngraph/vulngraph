package correlate

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

func TestStagedSourceFrameOwnsEveryProjectedField(t *testing.T) {
	for _, values := range []map[string]string{nil, {}, {"nul\x00key": "value\x00quoted\" café", "invalid": string([]byte{255, 254})}} {
		want := asset.Asset{ID: "id", Name: "name", Type: "ec2_instance", AccountID: "account", PublicIP: "203.0.113.1", PrivateIP: "10.0.0.1", Domain: "example.invalid", Tags: values, Metadata: values}
		data := appendStagedSourceFrame(nil, want)
		var got asset.Asset
		require.NoError(t, decodeStagedSourceFrame(data, &got))
		clear(data)
		require.Equal(t, want, got, "decoded data owns its strings/maps; nil and empty remain distinct")
	}
}

func TestStagedSourceFrameRejectsMalformedLengths(t *testing.T) {
	valid := appendStagedSourceFrame(nil, asset.Asset{ID: "id", Tags: map[string]string{"key": "value"}})
	var row asset.Asset
	for i := range len(valid) {
		require.Error(t, decodeStagedSourceFrame(valid[:i], &row), "truncation at %d", i)
	}
	require.Error(t, decodeStagedSourceFrame(append(valid, 0), &row))
	require.Error(t, decodeStagedSourceFrame([]byte{2}, &row))
	tooLong := binary.AppendUvarint([]byte{1}, ^uint64(0))
	require.Error(t, decodeStagedSourceFrame(tooLong, &row))
	// Seven empty source fields followed by an impossible map size.
	mapCount := binary.AppendUvarint([]byte{1, 0, 0, 0, 0, 0, 0, 0}, ^uint64(0))
	require.Error(t, decodeStagedSourceFrame(mapCount, &row))
}

func TestCompactFrameKeepsOriginalContextAdmissionCharge(t *testing.T) {
	s, err := newStagedFile(DefaultStagedViewLimits())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	row := asset.Asset{ID: "id", Type: "ec2_instance", Metadata: map[string]string{"escaped": strings.Repeat("\x00", 100)}}
	require.NoError(t, s.appendInput(s.input, row))
	ref := s.groups[row.Type][""][0]
	require.Less(t, ref.size, ref.charge)
	require.ErrorIs(t, s.CheckContext([]string{row.Type}, nil, 2, ref.charge-1), ErrStagedBudget)
	require.NoError(t, s.CheckContext([]string{row.Type}, nil, 2, ref.charge))
	require.Equal(t, dbutil.CHWriteMaxRows, DefaultStagedViewLimits().PageRows, "avoid a partial second insert per publication page")
}
