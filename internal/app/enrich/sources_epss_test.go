package enrich

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type fakeEPSS map[string]float64

func (f fakeEPSS) Score(cve string) (float64, bool) { s, ok := f[cve]; return s, ok }
func (f fakeEPSS) Loaded() bool                     { return len(f) > 0 }

// TestEPSS_CatalogNotLoadedIsUnmeasured pins the cold-start gap: before the
// first EPSS load every CVE lookup misses, which must read as "unmeasured", not
// as "below 1%" — the latter was cached as settled until the 24h backstop.
func TestEPSS_CatalogNotLoadedIsUnmeasured(t *testing.T) {
	_, applied, err := EPSS{Scores: fakeEPSS{}}.Evaluate(context.Background(), finding.Finding{CheckID: "CVE-2021-44228"})
	require.ErrorIs(t, err, ErrSourceNotReady)
	require.False(t, applied)

	_, applied, err = EPSS{Scores: fakeEPSS{}}.Evaluate(context.Background(), finding.Finding{CheckID: "aws-s3-public"})
	require.NoError(t, err, "a non-CVE finding never needed EPSS, so it is not unmeasured")
	require.False(t, applied)

	svc := NewService(&fakeFindingWriter{}, &fakeSignalRepo{}, []Source{BaseSeverity{}, EPSS{Scores: fakeEPSS{}}})
	score, err := svc.Enrich(context.Background(), finding.Finding{ID: "f", CheckID: "CVE-2021-44228", Severity: finding.SeverityHigh})
	require.NoError(t, err)
	require.Equal(t, []string{"epss"}, score.Unmeasured)
}

func TestEPSS_ScoresByBand(t *testing.T) {
	src := EPSS{Scores: fakeEPSS{
		"CVE-2021-44228": 0.97,  // high
		"CVE-2020-0002":  0.15,  // medium
		"CVE-2020-0003":  0.02,  // low
		"CVE-2020-0004":  0.001, // negligible
	}}

	for _, tc := range []struct {
		cve     string
		points  int
		applied bool
	}{
		{"CVE-2021-44228", 15, true},
		{"CVE-2020-0002", 8, true},
		{"CVE-2020-0003", 3, true},
		{"CVE-2020-0004", 0, false}, // below the 1% floor → not applied
		{"CVE-9999-9999", 0, false}, // not in catalog
	} {
		f := finding.Finding{Source: "supply_chain", CheckID: tc.cve}
		factor, applied, err := src.Evaluate(context.Background(), f)
		require.NoError(t, err)
		require.Equal(t, tc.applied, applied, tc.cve)
		require.Equal(t, tc.points, factor.Points, tc.cve)
	}
}

func TestEPSS_NonCVEFindingIgnored(t *testing.T) {
	src := EPSS{Scores: fakeEPSS{"CVE-2021-44228": 0.97}}
	f := finding.Finding{Source: "cspm", CheckID: "aws-s3-public-bucket"}
	_, applied, err := src.Evaluate(context.Background(), f)
	require.NoError(t, err)
	require.False(t, applied)
}

func TestEPSS_NilProvider(t *testing.T) {
	_, applied, err := EPSS{}.Evaluate(context.Background(), finding.Finding{CheckID: "CVE-2021-44228"})
	require.NoError(t, err)
	require.False(t, applied)
}

func TestEPSS_MatchesCVEInMetadata(t *testing.T) {
	// A nuclei template keyed on a slug carries the CVE in metadata.
	src := EPSS{Scores: fakeEPSS{"CVE-2021-44228": 0.97}}
	f := finding.Finding{Source: "nuclei", CheckID: "log4j-rce", Metadata: map[string]string{"cve": "CVE-2021-44228"}}
	factor, applied, err := src.Evaluate(context.Background(), f)
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, 15, factor.Points)
}
