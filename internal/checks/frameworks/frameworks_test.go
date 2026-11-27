package frameworks

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/checks/benchmarks"
)

// TestFrameworksAreWellFormed: every requirement has a short title and every
// control it maps is a real matrix row. A dangling reference would silently
// drop evidence from a requirement's rollup.
func TestFrameworksAreWellFormed(t *testing.T) {
	bs, err := benchmarks.Load()
	require.NoError(t, err)
	fws, err := Load()
	require.NoError(t, err)
	require.Len(t, fws, 1, "NIST SP 800-53 is the only built-in framework; others load from FRAMEWORKS_DIR")
	require.Equal(t, "nist-800-53-r5", fws[0].ID)
	require.Equal(t, SourceBuiltIn, fws[0].Source)
	require.NoError(t, Validate(fws[0], bs))
}

// TestDocsExampleFrameworksAreValid keeps the copy-and-adapt examples in
// docs/frameworks loadable against the real benchmark matrices, so a matrix
// change that removes a row they map cannot leave them quietly broken.
func TestDocsExampleFrameworksAreValid(t *testing.T) {
	bs, err := benchmarks.Load()
	require.NoError(t, err)
	fws, err := LoadCustom("../../../docs/frameworks", nil, bs)
	require.NoError(t, err)
	require.Len(t, fws, 4)
	for _, fw := range fws {
		require.True(t, strings.HasPrefix(fw.Source, "custom: "), "%s: source %q", fw.ID, fw.Source)
	}
}

// TestFrameworkFilesAreCanonical: the committed files are exactly what the
// generator writes, so a hand edit (other than a title) shows up as drift
// in review rather than being silently reverted by the next regeneration.
func TestFrameworkFilesAreCanonical(t *testing.T) {
	fws, err := Load()
	require.NoError(t, err)
	for _, fw := range fws {
		raw, err := os.ReadFile(FileName(fw.ID))
		require.NoError(t, err)
		require.Equal(t, string(Encode(fw)), string(raw), "%s is not in generator format", FileName(fw.ID))
		require.LessOrEqual(t, bytes.Count(raw, []byte("\n")), 800, "%s: split the framework, files stay ≤800 lines", fw.ID)
	}
}

func TestValidateRejectsBrokenRequirements(t *testing.T) {
	bs := []benchmarks.Benchmark{{ID: "b", Controls: []benchmarks.Control{{ID: "1.1"}}}}
	base := Framework{ID: "f", Name: "F", Version: "1", Sources: []string{"s"}}
	cases := []struct {
		name string
		r    Requirement
		ok   bool
	}{
		{"resolving ref", Requirement{ID: "R1", Title: "t", Controls: []string{"b/1.1"}}, true},
		{"no controls", Requirement{ID: "R1", Title: "t"}, true},
		{"dangling ref", Requirement{ID: "R1", Title: "t", Controls: []string{"b/9.9"}}, false},
		{"duplicate ref", Requirement{ID: "R1", Title: "t", Controls: []string{"b/1.1", "b/1.1"}}, false},
		{"empty title", Requirement{ID: "R1"}, false},
		{"title too long", Requirement{ID: "R1", Title: "one two three four five six seven eight nine ten eleven twelve thirteen"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fw := base
			fw.Requirements = []Requirement{tc.r}
			if tc.ok {
				require.NoError(t, Validate(fw, bs))
			} else {
				require.Error(t, Validate(fw, bs))
			}
		})
	}
}

func TestParseRejectsUnknownKeys(t *testing.T) {
	_, err := Parse([]byte("framework: f\nrequirements:\n  - {id: R1, title: t, control: [b/1.1]}\n"))
	require.Error(t, err, "a misspelt key must not parse as a requirement with no controls")
}

func TestIndexResolvesAndReportsMissing(t *testing.T) {
	bs := []benchmarks.Benchmark{{ID: "b", Providers: []string{"aws"}, Controls: []benchmarks.Control{
		{ID: "1.1", CheckIDs: []string{"c1"}}, {ID: "1.2"},
	}}}
	ix := NewIndex(bs)
	found, missing := ix.Controls(Requirement{Controls: []string{"b/1.1", "b/1.2", "b/gone"}})
	require.Len(t, found, 2)
	require.Equal(t, []string{"aws"}, found[0].Providers)
	require.Equal(t, []string{"b/gone"}, missing)
	require.True(t, ix.HasCheck(Requirement{Controls: []string{"b/1.2", "b/1.1"}}))
	require.False(t, ix.HasCheck(Requirement{Controls: []string{"b/1.2"}}))
}

func TestCanPassNeedsNoStructuralGap(t *testing.T) {
	bs := []benchmarks.Benchmark{{ID: "b", Controls: []benchmarks.Control{
		{ID: "cov", Status: benchmarks.StatusCovered, CheckIDs: []string{"c1"}},
		{ID: "part", Status: benchmarks.StatusPartial, CheckIDs: []string{"c2"}},
		{ID: "miss", Status: benchmarks.StatusMissing},
	}}}
	ix := NewIndex(bs)
	tests := []struct {
		name string
		req  Requirement
		want bool
	}{
		{"every control covered", Requirement{Controls: []string{"b/cov"}}, true},
		{"no controls", Requirement{}, false},
		{"unjoined source mapping", Requirement{Controls: []string{"b/cov"}, Unjoined: 1}, false},
		{"partial control", Requirement{Controls: []string{"b/cov", "b/part"}}, false},
		{"missing control", Requirement{Controls: []string{"b/cov", "b/miss"}}, false},
		{"unresolvable reference", Requirement{Controls: []string{"b/cov", "b/gone"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ix.CanPass(tt.req))
		})
	}
}

const customFramework = `framework: acme-baseline
name: "Acme baseline"
version: "1"
sources:
  - "Acme security team"
requirements:
  - {id: "A.1", title: "Rotate access keys", controls: ["b/1.1"]}
`

func customMatrices() []benchmarks.Benchmark {
	return []benchmarks.Benchmark{{ID: "b", Controls: []benchmarks.Control{{ID: "1.1"}}}}
}

func writeFramework(t *testing.T, dir, name, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
}

func TestLoadCustomLoadsFilesAndRecordsTheirSource(t *testing.T) {
	dir := t.TempDir()
	writeFramework(t, dir, "acme.yaml", customFramework)
	writeFramework(t, dir, "notes.txt", "not a framework")
	fws, err := LoadCustom(dir, []Framework{{ID: "nist-800-53-r5", Source: SourceBuiltIn}}, customMatrices())
	require.NoError(t, err)
	require.Len(t, fws, 1)
	require.Equal(t, "acme-baseline", fws[0].ID)
	require.Equal(t, "custom: acme.yaml", fws[0].Source)
}

func TestLoadCustomUnsetDirLoadsNothing(t *testing.T) {
	fws, err := LoadCustom("", nil, customMatrices())
	require.NoError(t, err)
	require.Empty(t, fws)
}

func TestLoadCustomEmptyDirLoadsNothing(t *testing.T) {
	fws, err := LoadCustom(t.TempDir(), nil, customMatrices())
	require.NoError(t, err)
	require.Empty(t, fws)
}

func TestLoadCustomRefusesWhatItCannotTrust(t *testing.T) {
	dup := strings.Replace(customFramework, "acme-baseline", "nist-800-53-r5", 1)
	cases := []struct {
		name, file, body, want string
	}{
		{"unparseable yaml", "broken.yaml", "framework: [unclosed", "broken.yaml"},
		{"unknown key", "typo.yaml", strings.Replace(customFramework, "controls:", "control:", 1), "typo.yaml"},
		{"dangling control", "dangling.yaml", strings.Replace(customFramework, "b/1.1", "b/9.9", 1), "dangling.yaml"},
		{"built-in id", "clash.yaml", dup, "already defined by built-in"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFramework(t, dir, c.file, c.body)
			_, err := LoadCustom(dir, []Framework{{ID: "nist-800-53-r5", Source: SourceBuiltIn}}, customMatrices())
			require.Error(t, err)
			require.Contains(t, err.Error(), c.want)
			require.Contains(t, err.Error(), c.file)
		})
	}
}

func TestLoadCustomRefusesTwoFilesWithOneID(t *testing.T) {
	dir := t.TempDir()
	writeFramework(t, dir, "a.yaml", customFramework)
	writeFramework(t, dir, "b.yaml", customFramework)
	_, err := LoadCustom(dir, nil, customMatrices())
	require.ErrorContains(t, err, "already defined by custom: a.yaml")
}

func TestLoadCustomRefusesAMissingDirOrAFile(t *testing.T) {
	_, err := LoadCustom(filepath.Join(t.TempDir(), "absent"), nil, customMatrices())
	require.Error(t, err)
	file := filepath.Join(t.TempDir(), "f.yaml")
	require.NoError(t, os.WriteFile(file, []byte(customFramework), 0o600))
	_, err = LoadCustom(file, nil, customMatrices())
	require.ErrorContains(t, err, "not a directory")
}
