package scan

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type profileAuditRow struct {
	action, targetType, targetID string
	details                      map[string]any
}

type fakeProfileAudit struct{ rows []profileAuditRow }

func (f *fakeProfileAudit) Record(_ context.Context, action, targetType, targetID string, details map[string]any) {
	f.rows = append(f.rows, profileAuditRow{action, targetType, targetID, details})
}

// crudProfileRepo stores one profile in memory for the CRUD paths.
type crudProfileRepo struct {
	ProfileRepo
	stored  ScanProfile
	deleted bool
}

func (r *crudProfileRepo) CreateProfile(_ context.Context, name, _ string, tags []string, enabled bool, targetQuery string, drift bool, schedule, scanner, strategy string) (ScanProfile, error) {
	r.stored = ScanProfile{ID: "p-1", Name: name, TemplateTags: tags, Enabled: enabled, TargetQuery: targetQuery,
		DriftEnabled: drift, Schedule: schedule, ScannerType: scanner, TemplateStrategy: TemplateStrategy(strategy)}
	return r.stored, nil
}

func (r *crudProfileRepo) GetProfile(context.Context, string) (ScanProfile, error) {
	return r.stored, nil
}

func (r *crudProfileRepo) UpdateProfile(_ context.Context, id, name, _ string, tags []string, enabled bool, targetQuery string, drift bool, schedule, scanner, strategy string) (ScanProfile, error) {
	r.stored = ScanProfile{ID: id, Name: name, TemplateTags: tags, Enabled: enabled, TargetQuery: targetQuery,
		DriftEnabled: drift, Schedule: schedule, ScannerType: scanner, TemplateStrategy: TemplateStrategy(strategy)}
	return r.stored, nil
}

func (r *crudProfileRepo) DeleteProfile(context.Context, string) error { r.deleted = true; return nil }

func TestScanProfileChanges_AreAudited(t *testing.T) {
	repo := &crudProfileRepo{}
	a := &fakeProfileAudit{}
	svc := NewProfileService(repo, nil, nil, nil, nil).WithAudit(a)
	ctx := context.Background()

	_, err := svc.CreateProfile(ctx, "weekly", "", []string{"cve"}, true, "", false, "", "nuclei", string(StrategyTags))
	require.NoError(t, err)
	_, err = svc.UpdateProfile(ctx, "p-1", "weekly", "", []string{"cve"}, false, "", false, "", "nuclei", string(StrategyTags))
	require.NoError(t, err)
	require.NoError(t, svc.DeleteProfile(ctx, "p-1"))

	require.Len(t, a.rows, 3)
	require.Equal(t, AuditActionProfileCreate, a.rows[0].action)
	require.Equal(t, AuditTargetScanProfile, a.rows[0].targetType)
	require.Equal(t, "p-1", a.rows[0].targetID)
	require.Equal(t, AuditActionProfileUpdate, a.rows[1].action)
	require.Equal(t, true, a.rows[1].details["before"].(map[string]any)["enabled"])
	require.Equal(t, false, a.rows[1].details["after"].(map[string]any)["enabled"], "disabling a profile is visible")
	require.Equal(t, AuditActionProfileDelete, a.rows[2].action)
	require.Equal(t, "weekly", a.rows[2].details["name"])
	require.True(t, repo.deleted)
}

func TestScanProfileRejectedChange_IsNotAudited(t *testing.T) {
	a := &fakeProfileAudit{}
	svc := NewProfileService(&crudProfileRepo{}, nil, nil, nil, nil).WithAudit(a)
	_, err := svc.CreateProfile(context.Background(), "p", "", nil, true, "", false, "not a cron", "nuclei", string(StrategyTags))
	require.Error(t, err)
	require.Empty(t, a.rows)
}
