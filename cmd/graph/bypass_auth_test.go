package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBypassAuthEnabled(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		want    bool
		wantErr bool
	}{
		{"unset", map[string]string{}, false, false},
		{"bypass false", map[string]string{"BYPASS_AUTH": "false", bypassAuthAckEnv: "yes"}, false, false},
		{"ack alone does nothing", map[string]string{bypassAuthAckEnv: "yes"}, false, false},
		{"bypass without ack refuses", map[string]string{"BYPASS_AUTH": "true"}, false, true},
		{"bypass with wrong ack refuses", map[string]string{"BYPASS_AUTH": "true", bypassAuthAckEnv: "true"}, false, true},
		{"bypass with ack", map[string]string{"BYPASS_AUTH": "true", bypassAuthAckEnv: "yes"}, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bypassAuthEnabled(func(k string) string { return tc.env[k] })
			if tc.wantErr {
				require.ErrorIs(t, err, errBypassAuthUnacknowledged)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}
