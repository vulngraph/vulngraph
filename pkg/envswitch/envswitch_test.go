package envswitch

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	const key = "SOME_SWITCH"
	tests := []struct {
		val     string
		want    bool
		wantErr bool
	}{
		{val: "", want: false},
		{val: "   ", want: false},
		{val: "0", want: false},
		{val: "false", want: false},
		{val: " FALSE ", want: false},
		{val: "no", want: false},
		{val: "No", want: false},
		{val: "off", want: false},
		{val: "OFF", want: false},
		{val: "1", want: true},
		{val: "true", want: true},
		{val: " True ", want: true},
		{val: "yes", want: true},
		{val: "YES", want: true},
		{val: "on", want: true},
		{val: "On", want: true},
		{val: "ture", wantErr: true},
		{val: "2", wantErr: true},
		{val: "enabled", wantErr: true},
		{val: "y", wantErr: true},
		{val: "-1", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(key+"="+tc.val, func(t *testing.T) {
			got, err := Parse(func(k string) string {
				if k == key {
					return tc.val
				}
				return ""
			}, key)
			if tc.wantErr {
				require.ErrorContains(t, err, key)
				require.False(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
