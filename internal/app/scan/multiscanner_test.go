package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// bothTarget carries a URL and a host, so it is relevant to web and network
// scanners alike.
var bothTarget = Target{URL: "https://x", Host: "x"}

func mustMultiScanner(t *testing.T, enabled map[string]bool, all ...Scanner) Scanner {
	t.Helper()
	ms, err := NewMultiScanner(enabled, all...)
	require.NoError(t, err)
	return ms
}

func TestMultiScanner_FansOutTagsAndDedups(t *testing.T) {
	web := &fakeScanner{name: "nuclei", caps: CapWeb, results: []Result{
		{TemplateID: "CVE-1", MatchedURL: "https://x"},           // untagged → multiScanner tags "nuclei"
		{TemplateID: "CVE-1", MatchedURL: "https://x"},           // exact dup within scanner → dropped
		{Scanner: "nuclei", TemplateID: "CVE-2", MatchedURL: ""}, // already tagged
	}}
	net := &fakeScanner{name: "naabu", caps: CapNetwork, results: []Result{
		{TemplateID: "CVE-1", Host: "x", Port: 443}, // same CVE, different scanner+host+port → kept
	}}

	ms := mustMultiScanner(t, nil, web, net)
	got, err := ms.Scan(context.Background(), []Target{bothTarget}, nil)
	require.NoError(t, err)

	require.Len(t, got.Results, 3, "exact intra-scanner duplicate dropped; cross-scanner match kept")
	for _, r := range got.Results {
		require.NotEmpty(t, r.Scanner, "every result is attributed to a producing scanner")
	}
	require.ElementsMatch(t, []Target{bothTarget}, web.gotTargets)
	require.ElementsMatch(t, []Target{bothTarget}, net.gotTargets)
}

func TestMultiScanner_RoutesByCapability(t *testing.T) {
	web := &fakeScanner{name: "nuclei", caps: CapWeb}
	net := &fakeScanner{name: "naabu", caps: CapNetwork}

	ms := mustMultiScanner(t, nil, web, net)
	_, err := ms.Scan(context.Background(), []Target{
		{URL: "https://only-web"},       // web-only
		{Host: "only-host", Port: 1234}, // network-only
	}, []string{"cve"})
	require.NoError(t, err)

	require.Equal(t, []Target{{URL: "https://only-web"}}, web.gotTargets, "web scanner gets only URL targets")
	require.Equal(t, []Target{{Host: "only-host", Port: 1234}}, net.gotTargets, "network scanner gets only host targets")
	require.Equal(t, []string{"cve"}, web.gotTags, "template tags reach every scanner")
	require.Equal(t, []string{"cve"}, net.gotTags, "template tags reach every scanner")
}

func TestMultiScanner_Capabilities_IsUnion(t *testing.T) {
	ms := mustMultiScanner(t, nil,
		&fakeScanner{name: "nuclei", caps: CapWeb},
		&fakeScanner{name: "naabu", caps: CapNetwork},
	)
	require.True(t, ms.Capabilities().Has(CapWeb))
	require.True(t, ms.Capabilities().Has(CapNetwork))
}

func TestMultiScanner_EnabledFilter(t *testing.T) {
	web := &fakeScanner{name: "nuclei", caps: CapWeb, results: []Result{{TemplateID: "CVE-1", MatchedURL: "https://x"}}}
	net := &fakeScanner{name: "naabu", caps: CapNetwork, results: []Result{{TemplateID: "CVE-2", Host: "x", Port: 443}}}

	ms := mustMultiScanner(t, map[string]bool{"nuclei": true}, web, net)
	got, err := ms.Scan(context.Background(), []Target{bothTarget}, nil)
	require.NoError(t, err)

	require.Len(t, got.Results, 1)
	require.Equal(t, "nuclei", got.Results[0].Scanner)
	require.Nil(t, net.gotTargets, "disabled scanner is never invoked")
}

func TestMultiScanner_ScannerError_FailsRun(t *testing.T) {
	web := &fakeScanner{name: "nuclei", caps: CapWeb, results: []Result{{TemplateID: "CVE-1", MatchedURL: "https://x"}}}
	bad := &fakeScanner{name: "naabu", caps: CapNetwork, err: errors.New("boom")}

	ms := mustMultiScanner(t, nil, web, bad)
	_, err := ms.Scan(context.Background(), []Target{bothTarget}, nil)
	require.ErrorContains(t, err, "naabu")
	require.ErrorContains(t, err, "boom")
}

func TestNewMultiScanner_UnknownNameRefused(t *testing.T) {
	for _, name := range []string{"Nuclei", "nucleii", "naabu"} {
		t.Run(name, func(t *testing.T) {
			_, err := NewMultiScanner(map[string]bool{name: true}, &fakeScanner{name: "nuclei"})
			require.ErrorIs(t, err, ErrUnknownScanner)
			require.ErrorContains(t, err, name)
			require.ErrorContains(t, err, "valid: nuclei", "the error lists the bundled names")
		})
	}
}

func TestNewMultiScanner_UnknownAmongKnownRefused(t *testing.T) {
	_, err := NewMultiScanner(map[string]bool{"nuclei": true, "nucleii": true}, &fakeScanner{name: "nuclei"})
	require.ErrorIs(t, err, ErrUnknownScanner, "one valid name does not excuse a misspelt one")
}

// A target no enabled scanner can act on must fail the scan, not come back as
// an empty, successful result that would resolve its confirmed findings.
func TestMultiScanner_UncoveredTarget_FailsRun(t *testing.T) {
	web := &fakeScanner{name: "nuclei", caps: CapWeb, results: []Result{{TemplateID: "CVE-1", MatchedURL: "https://x"}}}
	ms := mustMultiScanner(t, nil, web)

	got, err := ms.Scan(context.Background(), []Target{bothTarget, {Host: "only-host", Port: 22}}, nil)
	require.ErrorIs(t, err, ErrNoScannerForTarget)
	require.ErrorContains(t, err, "only-host")
	require.Empty(t, got.Results)
	require.Nil(t, web.gotTargets, "no scanner runs when any target is uncovered")
}

func TestMultiScanner_NoTargets_IsEmptySuccess(t *testing.T) {
	ms := mustMultiScanner(t, nil, &fakeScanner{name: "nuclei"})
	got, err := ms.Scan(context.Background(), nil, nil)
	require.NoError(t, err)
	require.Empty(t, got.Results)
}
