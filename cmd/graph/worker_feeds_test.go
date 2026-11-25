package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/jobs"
)

// A disabled feed must reach jobs.Deps as a TRUE nil interface: a typed nil
// (*kev.Fetcher)(nil) reads as wired, so the periodic would still be scheduled
// and the job would nil-deref instead of no-op.
func TestFeedConstructorsHonourSwitches(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
	}{
		{"defaults", map[string]string{}},
		{"offline", map[string]string{"OFFLINE_MODE": "true"}},
		{"kev+osv off", map[string]string{"INTEL_KEV_DISABLED": "true", "INTEL_OSV_DISABLED": "true"}},
		{"epss+malfeed+ct off", map[string]string{
			"INTEL_EPSS_DISABLED": "true", "INTEL_MALFEED_DISABLED": "true", "DOMAIN_MONITOR_DISABLED": "true",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string { return tc.env[k] }
			f, err := jobs.FeedsFromEnv(getenv)
			require.NoError(t, err)

			assert.Equal(t, f.KEV, kevFetcher(f) != nil, "KEV")
			assert.Equal(t, f.OSV, osvQuerier(f) != nil, "OSV")
			assert.Equal(t, f.MalFeed, malFeedQuerier(f, "") != nil, "MalFeed")
			assert.Equal(t, f.EPSS, epssFetcher(f) != nil, "EPSS")
			assert.Equal(t, f.DomainMonitor, domainMonitor(f, nil, nil, nil) != nil, "domain monitor")
			if !f.OSV {
				scanner, err := imageVulnSource(t.Context(), getenv, f, nil)
				require.NoError(t, err)
				assert.Nil(t, scanner, "image sweep follows OSV")
			}
		})
	}
}

func TestTakeoverProbeSwitch(t *testing.T) {
	cases := []struct {
		env     map[string]string
		want    bool
		wantErr bool
	}{
		{env: map[string]string{}, want: true},
		{env: map[string]string{"TAKEOVER_PROBE_DISABLED": "true"}, want: false},
		{env: map[string]string{"TAKEOVER_PROBE_DISABLED": "1"}, want: false},
		{env: map[string]string{"TAKEOVER_PROBE_DISABLED": "off"}, want: true},
		{env: map[string]string{"OFFLINE_MODE": "true"}, want: false},
		{env: map[string]string{"TAKEOVER_PROBE_DISABLED": "ture"}, wantErr: true},
		{env: map[string]string{"OFFLINE_MODE": "y"}, wantErr: true},
	}
	for _, tc := range cases {
		got, err := takeoverProbeHTTP(t.Context(), func(k string) string { return tc.env[k] })
		if tc.wantErr {
			require.Errorf(t, err, "env %v", tc.env)
			assert.Nilf(t, got, "env %v: an unreadable switch must not probe", tc.env)
			continue
		}
		require.NoErrorf(t, err, "env %v", tc.env)
		assert.Equalf(t, tc.want, got != nil, "env %v", tc.env)
	}
}

// A typo in OFFLINE_MODE or a feed switch stops the worker instead of leaving
// every feed on.
func TestIntelFeedsRejectsUnrecognisedSwitch(t *testing.T) {
	for _, env := range []map[string]string{
		{"OFFLINE_MODE": "enabled"},
		{"INTEL_OSV_DISABLED": "ture"},
	} {
		_, err := intelFeeds(t.Context(), func(k string) string { return env[k] })
		require.Errorf(t, err, "env %v", env)
	}
	f, err := intelFeeds(t.Context(), func(k string) string { return map[string]string{"OFFLINE_MODE": "1"}[k] })
	require.NoError(t, err)
	assert.Equal(t, jobs.Feeds{}, f)
}
