package driftanalysis

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassifyChange(t *testing.T) {
	tests := []struct {
		name                 string
		c                    AssetChange
		count                int
		prevName, prevIP     string
		kind, field, old, nw string
	}{
		{"new asset", AssetChange{Name: "n", PublicIP: "1.1.1.1"}, 0, "", "", KindNewAsset, "", "", ""},
		{"gained public ip", AssetChange{Name: "n", PublicIP: "1.1.1.1"}, 1, "n", "", KindNewExposure, "public_ip", "", "1.1.1.1"},
		{"lost public ip", AssetChange{Name: "n"}, 1, "n", "1.1.1.1", KindRemovedExposure, "public_ip", "1.1.1.1", ""},
		{"ip moved", AssetChange{Name: "n", PublicIP: "2.2.2.2"}, 2, "n", "1.1.1.1", KindChanged, "public_ip", "1.1.1.1", "2.2.2.2"},
		{"rename", AssetChange{Name: "new"}, 1, "old", "", KindChanged, "name", "old", "new"},
		{"rename and gain ip", AssetChange{Name: "new", PublicIP: "1.1.1.1"}, 1, "old", "", KindNewExposure, "public_ip,name", " / old", "1.1.1.1 / new"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.c
			classifyChange(&c, tc.count, tc.prevName, tc.prevIP)
			require.Equal(t, tc.kind, c.Kind)
			require.Equal(t, tc.field, c.Field)
			require.Equal(t, tc.old, c.OldValue)
			require.Equal(t, tc.nw, c.NewValue)
		})
	}
}
