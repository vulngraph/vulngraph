package nuclei

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/scan"
)

func TestScanTags(t *testing.T) {
	targets := []scan.Target{{URL: "https://x", AssetType: "dns_record"}}
	heurInclude, heurExclude := templateTagsFor(targets)
	without := func(drop ...string) []string {
		var out []string
		for _, t := range heurExclude {
			if !slices.Contains(drop, t) {
				out = append(out, t)
			}
		}
		return out
	}

	tests := []struct {
		name        string
		tags        []string
		wantInclude []string
		wantExclude []string
		wantErr     bool
	}{
		{name: "nil keeps the asset-type heuristic", tags: nil, wantInclude: heurInclude, wantExclude: heurExclude},
		{name: "profile tags replace the heuristic", tags: []string{"cve", " Apache "}, wantInclude: []string{"cve", "apache"}, wantExclude: heurExclude},
		{name: "excluded tags are stripped", tags: []string{"cve", "dos", "intrusive"}, wantInclude: []string{"cve"}, wantExclude: heurExclude},
		{name: "only excluded tags is an error", tags: []string{"dos", " "}, wantErr: true},
		{name: "a named opt-in tag leaves the exclusion list", tags: []string{"jenkins", " Default-Login "}, wantInclude: []string{"jenkins", "default-login"}, wantExclude: without("default-login")},
		{name: "opting into one credential tag keeps the others excluded", tags: []string{"bruteforce"}, wantInclude: []string{"bruteforce"}, wantExclude: without("bruteforce")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			include, exclude, err := scanTags(targets, tc.tags)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.ElementsMatch(t, tc.wantInclude, include)
			require.ElementsMatch(t, tc.wantExclude, exclude)
		})
	}
}

// Automatic selection never tries a login: a target whose technology hint
// pulls in jenkins or database templates still excludes every
// credential-attempt tag, because upstream default-login templates carry a
// technology tag plus default-login and are rated high.
func TestTemplateTagsFor_ExcludesCredentialAttempts(t *testing.T) {
	targets := []scan.Target{
		{URL: "https://ci", AssetType: "ec2_instance", Tags: map[string]string{"service": "jenkins"}},
		{URL: "https://db", AssetType: "ec2_instance", Tags: map[string]string{"app": "postgres"}},
	}
	include, exclude := templateTagsFor(targets)
	require.Contains(t, include, "jenkins")
	require.Contains(t, include, "database")
	for _, tag := range []string{"default-login", "brute-force", "bruteforce", "intrusive", "fuzzing", "dos"} {
		require.Contains(t, exclude, tag)
		require.NotContains(t, include, tag)
	}
}
