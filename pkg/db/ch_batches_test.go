package db

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCHStringBatchesBoundEscapedLongIDsAndDeduplicate(t *testing.T) {
	var ids []string
	for i := range 1200 {
		ids = append(ids, fmt.Sprintf("%d-%s", i, strings.Repeat("'\\", 100)))
	}
	ids = append(ids, ids...)
	batches, err := CHStringBatches(ids)
	require.NoError(t, err)
	seen := map[string]bool{}
	for _, batch := range batches {
		require.LessOrEqual(t, len(batch), 500)
		bytes := 0
		for _, id := range batch {
			require.False(t, seen[id])
			seen[id] = true
			bytes += len(id)
		}
		require.LessOrEqual(t, bytes, 32<<10)
	}
	require.Len(t, seen, 1200)
	_, err = CHStringBatches([]string{strings.Repeat("x", (32<<10)+1)})
	require.Error(t, err)
}
