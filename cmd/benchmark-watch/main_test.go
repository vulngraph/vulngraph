package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/checks/benchmarks"
	"github.com/vulngraph/vulngraph/internal/checks/upstream"
)

// The recorded bundle shared with internal/checks/upstream's tests. It is
// trimmed, so against the real matrices it reports drift — which is what the
// offline path is checked for here.
const fixtureBundle = "../../internal/checks/upstream/testdata/bundle"

func TestOfflineRunReportsDriftAndExitCode(t *testing.T) {
	snaps := t.TempDir()
	var out, errOut bytes.Buffer
	code, err := run([]string{"-offline", fixtureBundle, "-snapshots", snaps, "-json", "-fail-on-drift", "-date", "2026-10-10"}, &out, &errOut)
	require.NoError(t, err)
	require.Equal(t, exitDrift, code)
	var rep upstream.Report
	require.NoError(t, json.Unmarshal(out.Bytes(), &rep))
	require.True(t, rep.Drift)
	require.Equal(t, "2026-10-10", rep.Checked)

	code, err = run([]string{"-offline", fixtureBundle, "-snapshots", snaps}, &out, &errOut)
	require.NoError(t, err)
	require.Zero(t, code, "without -fail-on-drift drift is reported, not an exit status")
}

func TestUpdateRecordsSnapshots(t *testing.T) {
	snaps := t.TempDir()
	var out bytes.Buffer
	_, err := run([]string{"-offline", fixtureBundle, "-snapshots", snaps, "-update", "-date", "2026-10-10"}, &out, &out)
	require.NoError(t, err)
	got, err := benchmarks.ReadSnapshots(snaps)
	require.NoError(t, err)
	require.Equal(t, "2026-10-10", got["cis-aws-foundations"].Checked)
	require.Equal(t, []string{"1.1", "1.2", "1.4"}, got["cis-aws-foundations"].ControlIDs)
	require.FileExists(t, filepath.Join(snaps, "aws-fsbp.json"))
}

func TestRemoteRefusesUnsafePaths(t *testing.T) {
	_, err := remote("prowler/../../etc/passwd")
	require.Error(t, err)
	_, err = remote("unknown/x")
	require.Error(t, err)
	u, err := remote(upstream.ProwlerFilePath("aws", "cis_7.0_aws.json"))
	require.NoError(t, err)
	require.Equal(t, "https://raw.githubusercontent.com/prowler-cloud/prowler/master/prowler/compliance/aws/cis_7.0_aws.json", u)
	u, err = remote(upstream.PathAzurePolicyIndex)
	require.NoError(t, err)
	require.Contains(t, u, "Regulatory%20Compliance")
}
