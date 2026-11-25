package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestCheckTargetHost(t *testing.T) {
	tests := []struct {
		host                       string
		refusedDefault, refusedInt bool
	}{
		{"1.2.3.4", false, false},
		{"2606:4700::1111", false, false},
		{"10.0.0.5", true, false},
		{"127.0.0.1", true, false},
		{"::", true, false},
		{"[::1]", true, false},
		{"::ffff:127.0.0.1", true, false},
		{"169.254.169.254", true, true},
		{"169.254.1.1", true, true},
		{"fe80::1", true, true},
		{"fd00:ec2::254", true, true},
		{"100.100.100.200", true, true},
		{"192.0.0.192", true, true},
		{"168.63.129.16", true, true},
		{"64:ff9b::a9fe:a9fe", true, true},
		{"::ffff:169.254.169.254", true, true},
		{"metadata.google.internal", true, true},
		{"Metadata.Google.Internal.", true, true},
		{"metadata.goog", true, true},
		{"", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			err := checkTargetHost(context.Background(), tt.host, false)
			assert.Equal(t, tt.refusedDefault, err != nil, "default: %v", err)
			if err != nil {
				assert.ErrorIs(t, err, ErrTargetRefused)
			}
			err = checkTargetHost(context.Background(), tt.host, true)
			assert.Equal(t, tt.refusedInt, err != nil, "internal allowed: %v", err)
		})
	}
}

func TestGuardTargets_ChecksURLHostToo(t *testing.T) {
	targets := []Target{
		{URL: "https://1.2.3.4", Host: "1.2.3.4"},
		{URL: "http://169.254.169.254/latest/meta-data/", Host: "1.2.3.4"}, // URL disagrees with Host
		{URL: "http://[fd00:ec2::254]/"},
		{Host: "10.0.0.1"},
	}
	kept, refused := guardTargets(context.Background(), targets, true)
	require.Len(t, kept, 2)
	assert.Equal(t, "https://1.2.3.4", kept[0].URL)
	assert.Equal(t, "10.0.0.1", kept[1].Host, "internal opt-in keeps ordinary private space")
	assert.Len(t, refused, 2)
}

func TestRunScan_DropsPrivateTargetsByDefault(t *testing.T) {
	scanner := &fakeScanner{}
	assets := fakeAssets{external: []asset.Asset{
		{ID: "pub", PublicIP: "1.2.3.4"},
		{ID: "priv", PublicIP: "10.0.0.5"},
		{ID: "imds", PublicIP: "169.254.169.254"},
	}}
	svc := NewService(&fakeRepo{}, assets, &fakeResolver{}, scanner, &fakeFindings{})
	svc.allowInternal = false

	run, _, err := svc.RunScan(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"https://1.2.3.4"}, scanner.gotURLs())
	assert.Equal(t, []string{"https://1.2.3.4"}, run.TargetURLs)
}

func TestScanTargets_RefusesMetadataEvenWhenInternalAllowed(t *testing.T) {
	scanner := &fakeScanner{}
	svc := NewService(&fakeRepo{}, fakeAssets{}, &fakeResolver{}, scanner, &fakeFindings{})
	svc.allowInternal = true

	_, err := svc.ScanTargets(context.Background(), []Target{{URL: "http://169.254.169.254", Host: "169.254.169.254"}}, nil)
	require.ErrorIs(t, err, ErrTargetRefused)
	assert.Nil(t, scanner.gotTargets, "the scanner must never be handed the metadata endpoint")

	_, err = svc.ScanTargets(context.Background(), []Target{{URL: "http://10.0.0.1", Host: "10.0.0.1"}}, nil)
	require.NoError(t, err)
	assert.Len(t, scanner.gotTargets, 1)
}

func TestSnapshotClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	_, err := CaptureHTTP(t.Context(), srv.URL, time.Second, false)
	require.Error(t, err, "loopback is refused by default")

	_, err = CaptureHTTP(t.Context(), srv.URL, time.Second, true)
	require.NoError(t, err, "internal opt-in reaches loopback")

	for _, metadata := range []string{"http://169.254.169.254/", "http://[fd00:ec2::254]/", "http://100.100.100.200/"} {
		_, err = CaptureHTTP(t.Context(), metadata, time.Second, true)
		require.ErrorContains(t, err, "SSRF blocked", "%s must stay blocked with internal targets allowed", metadata)
	}
}

// A profile's template tags must reach the scanner: dropping them made the
// profile's strategy and tags decorative.
func TestScanTargets_PassesTemplateTagsToScanner(t *testing.T) {
	scanner := &fakeScanner{}
	svc := NewService(&fakeRepo{}, fakeAssets{}, &fakeResolver{}, scanner, &fakeFindings{})
	svc.allowInternal = true

	_, err := svc.ScanTargets(context.Background(), []Target{{URL: "http://10.0.0.1", Host: "10.0.0.1"}}, []string{"cve", "apache"})
	require.NoError(t, err)
	assert.Equal(t, []string{"cve", "apache"}, scanner.gotTags)

	_, _, err = svc.RunScan(context.Background())
	require.NoError(t, err)
	assert.Nil(t, scanner.gotTags, "an estate scan lets the scanner choose")
}
