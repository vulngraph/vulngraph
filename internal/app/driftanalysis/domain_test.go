package driftanalysis

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func gateInput() AnalysisInput {
	return AnalysisInput{
		Batch: Batch{ID: "b1"},
		Changes: []AssetChange{
			{AssetID: "arn:a1", Kind: KindNewExposure, PublicIP: "1.2.3.4"},
			{AssetID: "arn:a2", Kind: KindChanged},
		},
		Facts: Facts{
			ExposureKnown: true, FindingsKnown: true,
		},
	}
}

func goodVerdict() Verdict {
	return Verdict{
		Summary:              "a1 gained a public IP",
		Changes:              []ChangeItem{{Kind: KindNewExposure, AssetID: "arn:a1", Note: "public"}},
		ExposureJudgement:    ExposureIncreased,
		ScanRecommended:      true,
		ScanRecommendedKnown: true,
		Confidence:           ConfidenceHigh,
		Evidence:             []EvidenceRef{{Source: EvidenceAsset, Ref: "arn:a1", Fact: "public_ip 1.2.3.4"}},
	}
}

func TestGate(t *testing.T) {
	tests := []struct {
		name    string
		mutIn   func(*AnalysisInput)
		mutV    func(*Verdict)
		wantErr error
		check   func(t *testing.T, v Verdict)
	}{
		{name: "grounded verdict passes unchanged", check: func(t *testing.T, v Verdict) {
			require.Equal(t, goodVerdict(), v)
		}},
		{name: "foreign evidence ref rejected", mutV: func(v *Verdict) {
			v.Evidence = []EvidenceRef{{Source: EvidenceAsset, Ref: "arn:other", Fact: "x"}}
		}, wantErr: ErrUngrounded},
		{name: "profile id cited as asset rejected", mutV: func(v *Verdict) {
			v.Evidence = []EvidenceRef{{Source: EvidenceAsset, Ref: "p1", Fact: "x"}}
		}, wantErr: ErrUngrounded},
		{name: "empty evidence rejected", mutV: func(v *Verdict) { v.Evidence = nil }, wantErr: ErrUngrounded},
		{name: "evidence without a fact dropped", mutV: func(v *Verdict) {
			v.Evidence = []EvidenceRef{{Source: EvidenceAsset, Ref: "arn:a1"}}
		}, wantErr: ErrUngrounded},
		{name: "foreign evidence dropped when one citation survives", mutV: func(v *Verdict) {
			v.Evidence = append(v.Evidence, EvidenceRef{Source: EvidenceAsset, Ref: "arn:other", Fact: "x"})
		}, check: func(t *testing.T, v Verdict) { require.Len(t, v.Evidence, 1) }},
		{name: "retired profile evidence is refused", wantErr: ErrUngrounded, mutV: func(v *Verdict) {
			v.Evidence = []EvidenceRef{{Source: EvidenceProfile, Ref: "p1", Fact: "web profile exists"}}
		}},
		{name: "change item for a foreign asset dropped", mutV: func(v *Verdict) {
			v.Changes = append(v.Changes, ChangeItem{AssetID: "arn:other"})
		}, check: func(t *testing.T, v Verdict) { require.Len(t, v.Changes, 1) }},
		{name: "no with exposure unknown becomes unknown", mutIn: func(in *AnalysisInput) { in.Facts.ExposureKnown = false },
			mutV: func(v *Verdict) { v.ScanRecommended = false },
			check: func(t *testing.T, v Verdict) {
				require.False(t, v.ScanRecommendedKnown)
				require.Equal(t, RecommendationUnknown, v.Recommendation())
				require.Equal(t, ConfidenceLow, v.Confidence)
				require.Equal(t, ExposureUnknown, v.ExposureJudgement)
			}},
		{name: "no with findings unknown becomes unknown", mutIn: func(in *AnalysisInput) { in.Facts.FindingsKnown = false },
			mutV:  func(v *Verdict) { v.ScanRecommended = false },
			check: func(t *testing.T, v Verdict) { require.Equal(t, RecommendationUnknown, v.Recommendation()) }},
		{name: "no on a truncated batch becomes unknown", mutIn: func(in *AnalysisInput) { in.Batch.Truncated = true },
			mutV: func(v *Verdict) { v.ScanRecommended = false },
			check: func(t *testing.T, v Verdict) {
				require.Equal(t, RecommendationUnknown, v.Recommendation())
				require.Equal(t, ConfidenceLow, v.Confidence)
			}},
		{name: "no with every fact known survives", mutV: func(v *Verdict) { v.ScanRecommended = false },
			check: func(t *testing.T, v Verdict) { require.Equal(t, RecommendationNotNeeded, v.Recommendation()) }},
		{name: "yes survives missing facts but confidence drops", mutIn: func(in *AnalysisInput) { in.Facts.FindingsKnown = false },
			check: func(t *testing.T, v Verdict) {
				require.Equal(t, RecommendationRecommended, v.Recommendation())
				require.Equal(t, ConfidenceLow, v.Confidence)
			}},
		{name: "invalid confidence clamps to low", mutV: func(v *Verdict) { v.Confidence = "certain" },
			check: func(t *testing.T, v Verdict) { require.Equal(t, ConfidenceLow, v.Confidence) }},
		{name: "invalid exposure judgement becomes unknown", mutV: func(v *Verdict) { v.ExposureJudgement = "worse" },
			check: func(t *testing.T, v Verdict) { require.Equal(t, ExposureUnknown, v.ExposureJudgement) }},
		{name: "an unknown recommendation never carries a true bool", mutV: func(v *Verdict) { v.ScanRecommendedKnown = false },
			check: func(t *testing.T, v Verdict) { require.False(t, v.ScanRecommended) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in, v := gateInput(), goodVerdict()
			if tc.mutIn != nil {
				tc.mutIn(&in)
			}
			if tc.mutV != nil {
				tc.mutV(&v)
			}
			got, err := Gate(v, in)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Equal(t, Verdict{}, got, "a rejected verdict must not leak")
				return
			}
			require.NoError(t, err)
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

func TestBatchID_Deterministic(t *testing.T) {
	at := time.Date(2026, 5, 1, 12, 0, 0, 123456000, time.UTC)
	require.Equal(t, BatchID("c1", at), BatchID("c1", at.In(time.FixedZone("x", 7200))))
	require.NotEqual(t, BatchID("c1", at), BatchID("c2", at))
	require.NotEqual(t, BatchID("c1", at), BatchID("c1", at.Add(time.Microsecond)))
	require.Len(t, BatchID("c1", at), 64)
}

func TestVerdictZeroValueIsUnknown(t *testing.T) {
	require.Equal(t, RecommendationUnknown, Verdict{}.Recommendation())
	require.Equal(t, RecommendationUnknown, Verdict{ScanRecommended: true}.Recommendation())
}

func TestExternalChanged(t *testing.T) {
	got := ExternalChanged([]AssetChange{
		{AssetID: "a", Kind: KindNewExposure},
		{AssetID: "b", Kind: KindNewAsset, PublicIP: "1.1.1.1"},
		{AssetID: "c", Kind: KindNewAsset},
		{AssetID: "d", Kind: KindRemovedExposure},
	})
	require.Equal(t, []string{"a", "b"}, got)
}
