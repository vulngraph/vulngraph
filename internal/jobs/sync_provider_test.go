package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/collect"
)

// fakeProviderReconciler serves stored findings the way the real repo does:
// keys are the open rows of one source tagged with one connector.
type fakeProviderReconciler struct {
	stored     []finding.Finding
	resolved   []finding.Finding
	reasons    []finding.ResolutionReason
	reasonByID map[string]finding.ResolutionReason
	keysErr    error
	byIDsErr   error
}

func (f *fakeProviderReconciler) OpenKeysByConnector(_ context.Context, source, connectorID string) ([]finding.OpenKey, error) {
	if f.keysErr != nil {
		return nil, f.keysErr
	}
	var out []finding.OpenKey
	for _, fnd := range f.stored {
		if fnd.Source == source && !fnd.Resolved() && fnd.Metadata[finding.ProvenanceConnectorKey] == connectorID {
			out = append(out, finding.OpenKey{ID: fnd.ID, Region: fnd.Region, Type: fnd.Type})
		}
	}
	return out, nil
}

func (f *fakeProviderReconciler) ByIDs(_ context.Context, ids []string) ([]finding.Finding, error) {
	if f.byIDsErr != nil {
		return nil, f.byIDsErr
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []finding.Finding
	for _, fnd := range f.stored {
		if want[fnd.ID] {
			out = append(out, fnd)
		}
	}
	return out, nil
}

func (f *fakeProviderReconciler) Resolve(_ context.Context, findings []finding.Finding, reason finding.ResolutionReason) error {
	f.resolved = append(f.resolved, findings...)
	f.reasons = append(f.reasons, reason)
	if f.reasonByID == nil {
		f.reasonByID = map[string]finding.ResolutionReason{}
	}
	for _, fnd := range findings {
		f.reasonByID[fnd.ID] = reason
	}
	return nil
}

func gdStored(id, region, typ, connector string) finding.Finding {
	return finding.Finding{
		ID: id, Source: guardDutySource, Type: typ, Region: region,
		Metadata: map[string]string{finding.ProvenanceConnectorKey: connector},
	}
}

func gdScope(region string) collect.ScopeEnumeration {
	return collect.ScopeEnumeration{
		Scope: region + "/" + collect.GuardDutyFindingsFamily,
		Types: []string{collect.GuardDutyFindingType},
	}
}

func resolvedIDs(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

// A stored GuardDuty finding is closed only when every fact lines up: open,
// a threat from the listing, emitted by THIS connector, in a region whose
// listing was proven complete, and not returned anywhere this sweep.
func TestReconcileGuardDutyFindings_ResolvesOnlyProvenAbsence(t *testing.T) {
	resolvedRow := gdStored("already-resolved", "eu-west-1", "threat", "conn-a")
	resolvedRow.ResolvedAt = time.Now()
	svc := &fakeProviderReconciler{stored: []finding.Finding{
		gdStored("archived", "eu-west-1", "threat", "conn-a"),         // resolve
		gdStored("still-listed", "eu-west-1", "threat", "conn-a"),     // re-emitted
		gdStored("listed-elsewhere", "eu-west-1", "threat", "conn-a"), // emitted from us-east-1
		gdStored("capped-region", "ap-south-1", "threat", "conn-a"),   // region not complete
		gdStored("other-connector", "eu-west-1", "threat", "conn-b"),  // another account's listing
		gdStored("coverage", "eu-west-1", "coverage", "conn-a"),       // derived from the EKS listing too
		resolvedRow,
		{ID: "untagged", Source: guardDutySource, Type: "threat", Region: "eu-west-1"}, // pre-provenance row
		{ID: "cspm", Source: "cspm", Type: "threat", Region: "eu-west-1",
			Metadata: map[string]string{finding.ProvenanceConnectorKey: "conn-a"}},
	}}
	emitted := []finding.Finding{
		{ID: "still-listed", Region: "eu-west-1"},
		{ID: "listed-elsewhere", Region: "us-east-1"},
	}

	reconcileGuardDutyFindings(context.Background(), svc, "conn-a",
		[]collect.ScopeEnumeration{gdScope("eu-west-1"), gdScope("us-east-1"),
			{Scope: "ap-south-1/ec2:instances", Types: []string{"ec2_instance"}}},
		emitted)

	require.Equal(t, []string{"archived"}, resolvedIDs(svc.resolved))
	require.Equal(t, []finding.ResolutionReason{finding.ReasonProviderClosed}, svc.reasons,
		"archived by the provider is not proof of remediation")
}

// No completed GuardDuty scope — the listing was capped, failed, or denied
// everywhere — means nothing is provable, so nothing is read or resolved.
func TestReconcileGuardDutyFindings_NoCompleteScopeResolvesNothing(t *testing.T) {
	svc := &fakeProviderReconciler{
		stored:  []finding.Finding{gdStored("archived", "eu-west-1", "threat", "conn-a")},
		keysErr: errors.New("must not be called"),
	}
	reconcileGuardDutyFindings(context.Background(), svc, "conn-a",
		[]collect.ScopeEnumeration{{Scope: "eu-west-1/ec2:vpcs", Types: []string{"vpc"}}}, nil)
	require.Empty(t, svc.resolved)
}

// A failed read is not an empty one: neither the key read nor the hydrate may
// fall through to a resolve.
func TestReconcileGuardDutyFindings_ReadErrorsResolveNothing(t *testing.T) {
	stored := []finding.Finding{gdStored("archived", "eu-west-1", "threat", "conn-a")}
	scopes := []collect.ScopeEnumeration{gdScope("eu-west-1")}

	keys := &fakeProviderReconciler{stored: stored, keysErr: errors.New("timeout")}
	reconcileGuardDutyFindings(context.Background(), keys, "conn-a", scopes, nil)
	require.Empty(t, keys.resolved)

	hydrate := &fakeProviderReconciler{stored: stored, byIDsErr: errors.New("timeout")}
	reconcileGuardDutyFindings(context.Background(), hydrate, "conn-a", scopes, nil)
	require.Empty(t, hydrate.resolved)
}

// The hydrated row has the final say: a finding re-observed (or re-tagged by
// another connector) between the key read and the hydrate stays open.
func TestReconcileGuardDutyFindings_HydratedRowWins(t *testing.T) {
	svc := &fakeProviderReconciler{stored: []finding.Finding{gdStored("moved", "eu-west-1", "threat", "conn-a")}}
	keys, err := svc.OpenKeysByConnector(context.Background(), guardDutySource, "conn-a")
	require.NoError(t, err)
	require.Len(t, keys, 1)
	svc.stored[0].Metadata[finding.ProvenanceConnectorKey] = "conn-b"

	stale := &staleKeysReconciler{fakeProviderReconciler: svc, keys: keys}
	reconcileGuardDutyFindings(context.Background(), stale, "conn-a", []collect.ScopeEnumeration{gdScope("eu-west-1")}, nil)
	require.Empty(t, svc.resolved)
}

// staleKeysReconciler serves a fixed key set regardless of what is stored now.
type staleKeysReconciler struct {
	*fakeProviderReconciler
	keys []finding.OpenKey
}

func (s *staleKeysReconciler) OpenKeysByConnector(context.Context, string, string) ([]finding.OpenKey, error) {
	return s.keys, nil
}

func TestStampFindingProvenance(t *testing.T) {
	fs := []finding.Finding{{ID: "a"}, {ID: "b", Metadata: map[string]string{"occurrences": "3"}}}
	stampFindingProvenance(fs, "conn-a")
	require.Equal(t, "conn-a", fs[0].Metadata[finding.ProvenanceConnectorKey])
	require.Equal(t, "conn-a", fs[1].Metadata[finding.ProvenanceConnectorKey])
	require.Equal(t, "3", fs[1].Metadata["occurrences"], "existing metadata is kept")
}

func ghasStored(id, source, connector string) finding.Finding {
	return finding.Finding{
		ID: id, Source: source,
		Metadata: map[string]string{finding.ProvenanceConnectorKey: connector},
	}
}

// A closure GitHub reported resolves the stored open finding with the reason
// GitHub's state maps to, and records GitHub's own words beside it — but only
// for an open finding of that source this connector emitted, and never for one
// this sweep's open listing returned (reopened between the two listings).
func TestReconcileProviderClosures_ResolvesWithProviderReason(t *testing.T) {
	alreadyResolved := ghasStored("ghas_secrets:o/r:9", "ghas_secrets", "conn-a")
	alreadyResolved.ResolvedAt = time.Now()
	svc := &fakeProviderReconciler{stored: []finding.Finding{
		ghasStored("ghas_code_scanning:o/r:1", "ghas_code_scanning", "conn-a"), // fixed
		ghasStored("ghas_code_scanning:o/r:2", "ghas_code_scanning", "conn-a"), // dismissed
		ghasStored("ghas_secrets:o/r:3", "ghas_secrets", "conn-a"),             // pattern deleted
		ghasStored("ghas_secrets:o/r:4", "ghas_secrets", "conn-a"),             // reopened: emitted open
		ghasStored("ghas_secrets:o/r:5", "ghas_secrets", "conn-b"),             // another connector's
		alreadyResolved,
		ghasStored("ghas_code_scanning:o/r:6", "ghas_code_scanning", "conn-a"),
	}}
	closures := []collect.FindingClosure{
		{ID: "ghas_code_scanning:o/r:1", Source: "ghas_code_scanning", Reason: finding.ReasonFixed, Note: "fixed on GitHub"},
		{ID: "ghas_code_scanning:o/r:2", Source: "ghas_code_scanning", Reason: finding.ReasonManual, Note: "dismissed on GitHub: won't fix"},
		{ID: "ghas_secrets:o/r:3", Source: "ghas_secrets", Reason: finding.ReasonProviderClosed, Note: "resolved on GitHub: pattern deleted"},
		{ID: "ghas_secrets:o/r:4", Source: "ghas_secrets", Reason: finding.ReasonFixed},
		{ID: "ghas_secrets:o/r:5", Source: "ghas_secrets", Reason: finding.ReasonFixed},
		{ID: "ghas_secrets:o/r:9", Source: "ghas_secrets", Reason: finding.ReasonFixed},
		{ID: "ghas_secrets:o/r:404", Source: "ghas_secrets", Reason: finding.ReasonFixed},     // never stored
		{ID: "ghas_code_scanning:o/r:6", Source: "ghas_secrets", Reason: finding.ReasonFixed}, // source mismatch
	}
	emitted := []finding.Finding{{ID: "ghas_secrets:o/r:4"}}

	reconcileProviderClosures(context.Background(), svc, "conn-a", closures, emitted)

	require.Len(t, svc.reasons, 3, "one Resolve per reason")
	require.Equal(t, map[string]finding.ResolutionReason{
		"ghas_code_scanning:o/r:1": finding.ReasonFixed,
		"ghas_code_scanning:o/r:2": finding.ReasonManual,
		"ghas_secrets:o/r:3":       finding.ReasonProviderClosed,
	}, svc.reasonByID)
	notes := map[string]string{}
	for _, f := range svc.resolved {
		notes[f.ID] = f.Metadata["resolved_reason"]
		require.Equal(t, f.Source, f.Metadata["resolved_by"])
	}
	require.Equal(t, map[string]string{
		"ghas_code_scanning:o/r:1": "fixed on GitHub",
		"ghas_code_scanning:o/r:2": "dismissed on GitHub: won't fix",
		"ghas_secrets:o/r:3":       "resolved on GitHub: pattern deleted",
	}, notes)
}

// A failed hydrate resolves nothing in that batch; the collector re-reads the
// closure next sweep.
func TestReconcileProviderClosures_HydrateErrorResolvesNothing(t *testing.T) {
	svc := &fakeProviderReconciler{
		stored:   []finding.Finding{ghasStored("ghas_secrets:o/r:3", "ghas_secrets", "conn-a")},
		byIDsErr: errors.New("timeout"),
	}
	reconcileProviderClosures(context.Background(), svc, "conn-a", []collect.FindingClosure{
		{ID: "ghas_secrets:o/r:3", Source: "ghas_secrets", Reason: finding.ReasonFixed},
	}, nil)
	require.Empty(t, svc.resolved)
}
