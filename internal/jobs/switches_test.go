package jobs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The kill switches share envswitch.Parse's spellings and reject the rest.
func TestSwitchFromEnv(t *testing.T) {
	tests := []struct {
		val     string
		want    bool
		wantErr bool
	}{
		{val: "", want: false},
		{val: "false", want: false},
		{val: " FALSE ", want: false},
		{val: "0", want: false},
		{val: "off", want: false},
		{val: "true", want: true},
		{val: " True ", want: true},
		{val: "1", want: true},
		{val: "yes", want: true},
		{val: "ture", wantErr: true},
		{val: "disabled", wantErr: true},
	}
	for _, key := range []string{ScanWorkerDisabledEnv, ImageScanDisabledEnv, AdjudicatorEnabledEnv, DriftAnalysisEnabledEnv} {
		for _, tc := range tests {
			t.Run(key+"="+tc.val, func(t *testing.T) {
				got, err := SwitchFromEnv(func(k string) string {
					if k == key {
						return tc.val
					}
					return ""
				}, key)
				if tc.wantErr {
					require.ErrorContains(t, err, key)
					return
				}
				require.NoError(t, err)
				require.Equal(t, tc.want, got)
			})
		}
	}
}
