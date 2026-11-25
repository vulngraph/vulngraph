package main

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/graphstore"
	"github.com/vulngraph/vulngraph/internal/app/scan"
)

// A misspelt SCAN_SCANNERS stops startup and names the bundled scanners; left
// running it would enable none, and every profile run would report its targets
// clean.
func TestBundledScanner_SCANSCANNERS(t *testing.T) {
	for _, tc := range []struct {
		value   string
		wantErr bool
	}{
		{"", false},
		{"nuclei", false},
		{" nuclei , ", false},
		{"Nuclei", true},
		{"nucleii", true},
		{"nuclei,naabu", true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			s, err := bundledScanner(func(k string) string {
				if k == "SCAN_SCANNERS" {
					return tc.value
				}
				return ""
			})
			if !tc.wantErr {
				require.NoError(t, err)
				assert.True(t, s.Capabilities().Has(scan.CapWeb), "the bundled scanner is enabled")
				return
			}
			require.ErrorIs(t, err, scan.ErrUnknownScanner)
			require.ErrorContains(t, err, "SCAN_SCANNERS")
			require.ErrorContains(t, err, "valid: nuclei")
			assert.Nil(t, s)
		})
	}
}

// An engine the operator asked for (LADYBUG_INTERNAL_PORT set) that fails to
// open stops the worker. Returning nil would be indistinguishable from "no
// graph configured", and reach and blast-radius signals would silently vanish.
func TestOpenGraphDB_RequestedEngineThatFailsStopsStartup(t *testing.T) {
	failing := func(string, int, int, int, string) (*graphstore.Service, error) {
		return nil, errors.New("buffer pool allocation failed")
	}
	env := map[string]string{"LADYBUG_INTERNAL_PORT": "8090"}
	db, err := openGraphDBWith(func(k string) string { return env[k] }, failing)
	require.ErrorContains(t, err, "LADYBUG_INTERNAL_PORT")
	require.ErrorContains(t, err, "buffer pool allocation failed")
	assert.Nil(t, db)
}

func TestOpenGraphDB_UnsetPortIsDisabledNotAnError(t *testing.T) {
	called := false
	opener := func(string, int, int, int, string) (*graphstore.Service, error) {
		called = true
		return nil, errors.New("must not be called")
	}
	db, err := openGraphDBWith(func(string) string { return "" }, opener)
	require.NoError(t, err)
	assert.Nil(t, db)
	assert.False(t, called, "no engine is opened when none was requested")
}

// SERVE_LADYBUG_ENABLED is an on/off switch: "false" must not start a ~512 MB
// replica, and an unrecognised value stops serve at startup.
func TestServeLadybugEnabledIsAStrictSwitch(t *testing.T) {
	cases := []struct {
		val     string
		wantMB  int
		wantErr bool
	}{
		{val: "", wantMB: 0},
		{val: "false", wantMB: 0},
		{val: "0", wantMB: 0},
		{val: "off", wantMB: 0},
		{val: "true", wantMB: defaultServeLadybugBufferMB},
		{val: "1", wantMB: defaultServeLadybugBufferMB},
		{val: "YES", wantMB: defaultServeLadybugBufferMB},
		{val: "ture", wantErr: true},
		{val: "enabled", wantErr: true},
	}
	for _, tc := range cases {
		getenv := func(k string) string { return map[string]string{"SERVE_LADYBUG_ENABLED": tc.val}[k] }
		mb, err := serveLadybugBufferMB(getenv)
		if tc.wantErr {
			require.ErrorContainsf(t, err, "SERVE_LADYBUG_ENABLED", "value %q", tc.val)
			continue
		}
		require.NoErrorf(t, err, "value %q", tc.val)
		assert.Equalf(t, tc.wantMB, mb, "value %q", tc.val)
	}
}

// A serve replica the operator asked for that fails to open stops serve, the
// same rule as the worker's engine; an unrequested one is never opened.
func TestOpenServeReplica(t *testing.T) {
	failing := func(string, int, int, int, string) (*graphstore.Service, error) {
		return nil, errors.New("buffer pool allocation failed")
	}
	on := func(k string) string { return map[string]string{"SERVE_LADYBUG_ENABLED": "true"}[k] }
	svc, mb, err := openServeReplica(on, failing)
	require.ErrorContains(t, err, "SERVE_LADYBUG_ENABLED")
	require.ErrorContains(t, err, "buffer pool allocation failed")
	assert.Nil(t, svc)
	assert.Zero(t, mb)

	called := false
	opener := func(string, int, int, int, string) (*graphstore.Service, error) {
		called = true
		return nil, errors.New("must not be called")
	}
	svc, mb, err = openServeReplica(func(string) string { return "" }, opener)
	require.NoError(t, err)
	assert.Nil(t, svc)
	assert.Zero(t, mb)
	assert.False(t, called, "no replica is opened when none was requested")

	_, _, err = openServeReplica(func(k string) string { return map[string]string{"SERVE_LADYBUG_ENABLED": "ture"}[k] }, opener)
	require.ErrorContains(t, err, "SERVE_LADYBUG_ENABLED")
	assert.False(t, called)
}

// ADJUDICATOR_ENABLED spends LLM budget, so "false" must not turn it on.
func TestSeverityAdjudicatorSwitch(t *testing.T) {
	for _, v := range []string{"", "false", "0", "no"} {
		adj, err := severityAdjudicator(t.Context(), func(k string) string {
			return map[string]string{"ADJUDICATOR_ENABLED": v}[k]
		}, nil, nil)
		require.NoErrorf(t, err, "value %q", v)
		assert.Nilf(t, adj, "value %q", v)
	}
	_, err := severityAdjudicator(t.Context(), func(k string) string {
		return map[string]string{"ADJUDICATOR_ENABLED": "ture"}[k]
	}, nil, nil)
	require.ErrorContains(t, err, "ADJUDICATOR_ENABLED")
}
