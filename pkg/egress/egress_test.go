package egress

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDisabled(t *testing.T) {
	const key = "INTEL_KEV_DISABLED"
	cases := []struct {
		name    string
		env     map[string]string
		want    bool
		wantErr string
	}{
		{name: "unset: on by default", env: map[string]string{}, want: false},
		{name: "true disables", env: map[string]string{key: "true"}, want: true},
		{name: "surrounding space tolerated", env: map[string]string{key: " true "}, want: true},
		{name: "1 disables", env: map[string]string{key: "1"}, want: true},
		{name: "TRUE disables", env: map[string]string{key: "TRUE"}, want: true},
		{name: "yes disables", env: map[string]string{key: "yes"}, want: true},
		{name: "false does not disable", env: map[string]string{key: "false"}, want: false},
		{name: "0 does not disable", env: map[string]string{key: "0"}, want: false},
		{name: "typo is an error and fails closed", env: map[string]string{key: "ture"}, want: true, wantErr: key},
		{name: "offline mode disables", env: map[string]string{OfflineEnv: "true"}, want: true},
		{name: "offline mode 1 disables", env: map[string]string{OfflineEnv: "1"}, want: true},
		{name: "offline mode ON disables", env: map[string]string{OfflineEnv: "ON"}, want: true},
		{name: "offline mode wins over an explicit false", env: map[string]string{OfflineEnv: "true", key: "false"}, want: true},
		{name: "offline mode off leaves the feed on", env: map[string]string{OfflineEnv: "off"}, want: false},
		{name: "offline mode typo is an error and fails closed", env: map[string]string{OfflineEnv: "enabled", key: "false"}, want: true, wantErr: OfflineEnv},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string { return tc.env[k] }
			got, err := Disabled(getenv, key)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestEnabled(t *testing.T) {
	const key = "NUCLEI_INTERACTSH_ENABLED"
	cases := []struct {
		name    string
		env     map[string]string
		want    bool
		wantErr string
	}{
		{name: "unset: off by default", env: map[string]string{}, want: false},
		{name: "true enables", env: map[string]string{key: "true"}, want: true},
		{name: "1 enables", env: map[string]string{key: "1"}, want: true},
		{name: "false leaves it off", env: map[string]string{key: "false"}, want: false},
		{name: "typo is an error and stays off", env: map[string]string{key: "ture"}, want: false, wantErr: key},
		{name: "offline mode wins over an explicit true", env: map[string]string{OfflineEnv: "true", key: "true"}, want: false},
		{name: "offline mode off leaves the opt-in on", env: map[string]string{OfflineEnv: "off", key: "yes"}, want: true},
		{name: "offline mode typo is an error and stays off", env: map[string]string{OfflineEnv: "enabled", key: "true"}, want: false, wantErr: OfflineEnv},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Enabled(func(k string) string { return tc.env[k] }, key)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestOfflineFailsClosed(t *testing.T) {
	for _, v := range []string{"y", "2", "offline", "enable"} {
		on, err := Offline(func(k string) string { return map[string]string{OfflineEnv: v}[k] })
		require.ErrorContains(t, err, OfflineEnv, v)
		assert.True(t, on, "OFFLINE_MODE=%q must read as offline", v)
	}
	on, err := Offline(func(string) string { return "" })
	require.NoError(t, err)
	assert.False(t, on)
}
