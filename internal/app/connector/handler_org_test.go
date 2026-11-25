package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
)

func newOrgHandler(t *testing.T) (*Handler, *fakeSyncer, *fakeDiscoverer, Connector) {
	t.Helper()
	h, syncer := newTestHandler(t)
	disc := &fakeDiscoverer{accounts: []DiscoveredAccount{active("222222222222"), {ID: "333333333333", State: "SUSPENDED"}}}
	h.svc.WithOrgDiscoverer(disc)
	org, err := h.svc.Create(context.Background(), TypeAWSOrg, "acme", orgConfig(map[string]string{
		OrgKeyHubAuth: HubAuthAccessKey, "aws_access_key_id": "AKIAHUB", "aws_secret_access_key": "hub-secret",
		OrgKeyHubRoleARN: testHubRole,
	}), "")
	require.NoError(t, err)
	return h, syncer, disc, org
}

func asRole(r *http.Request, role auth.Role) *http.Request {
	return r.WithContext(auth.ContextWithUser(r.Context(), auth.User{ID: "u2", Email: "someone@b.example", Role: role}))
}

func TestCreateHandler_AWSOrg(t *testing.T) {
	h, _ := newTestHandler(t)
	body := `{"type":"aws_org","name":"acme","config":{"management_role_arn":"` + testMgmtRole + `","external_id":"graph-ext-0123456789abcdef"}}`
	rec := httptest.NewRecorder()
	h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/connectors", strings.NewReader(body)))
	require.Equal(t, http.StatusCreated, rec.Code)
	require.NotContains(t, rec.Body.String(), "graph-ext", "the ExternalId is config, never echoed")
}

func TestCreateHandler_AWSOrgInvalidConfig_400(t *testing.T) {
	h, _ := newTestHandler(t)
	body := `{"type":"aws_org","name":"acme","config":{"management_role_arn":"not-an-arn","external_id":"graph-ext-0123456789abcdef"}}`
	rec := httptest.NewRecorder()
	h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/connectors", strings.NewReader(body)))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestCreateHandler_HandMadeOrgChild_400(t *testing.T) {
	h, _ := newTestHandler(t)
	body := `{"type":"aws","name":"x","config":{"region":"eu-west-1","role_arn":"arn:aws:iam::2:role/x","org_connector_id":"o"}}`
	rec := httptest.NewRecorder()
	h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/connectors", strings.NewReader(body)))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOrgAccountsHandler(t *testing.T) {
	h, _, _, org := newOrgHandler(t)
	_, err := h.svc.ReconcileOrg(context.Background(), org.ID)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/connectors/"+org.ID+"/org-accounts", nil)
	req.SetPathValue("id", org.ID)
	rec := httptest.NewRecorder()
	h.OrgAccounts(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, rec.Body.String(), "AKIAHUB")
	var got []orgAccountResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Len(t, got, 2)
	byID := map[string]orgAccountResponse{}
	for _, a := range got {
		byID[a.AccountID] = a
	}
	require.Equal(t, "active", byID["222222222222"].Status)
	require.NotNil(t, byID["222222222222"].Child)
	require.True(t, byID["222222222222"].Child.Enabled)
	require.Equal(t, "suspended", byID["333333333333"].Status)
	require.Nil(t, byID["333333333333"].Child)
}

func TestOrgAccountsHandler_Errors(t *testing.T) {
	h, _ := newTestHandler(t)
	plain, err := h.svc.Create(context.Background(), TypeAWS, "prod", awsConfig, "")
	require.NoError(t, err)
	for id, want := range map[string]int{"ghost": http.StatusNotFound, plain.ID: http.StatusBadRequest} {
		req := httptest.NewRequest(http.MethodGet, "/api/connectors/"+id+"/org-accounts", nil)
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		h.OrgAccounts(rec, req)
		require.Equal(t, want, rec.Code, id)
	}
}

func TestTestConnectionHandler(t *testing.T) {
	h, _, _, org := newOrgHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/connectors/"+org.ID+"/test", nil)
	req.SetPathValue("id", org.ID)
	rec := httptest.NewRecorder()
	h.TestConnection(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var got orgTestResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.True(t, got.HubOK)
	require.Equal(t, 2, got.AccountCount)
	require.NotNil(t, got.Members, "members is an array, never null")
}

func TestTestConnectionHandler_NotAnOrg_400(t *testing.T) {
	h, _, _, _ := newOrgHandler(t)
	plain, err := h.svc.Create(context.Background(), TypeAWS, "prod", awsConfig, "")
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/connectors/"+plain.ID+"/test", nil)
	req.SetPathValue("id", plain.ID)
	rec := httptest.NewRecorder()
	h.TestConnection(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestTriggerSync_OrgEnqueuesDiscovery(t *testing.T) {
	h, syncer, _, org := newOrgHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/connectors/"+org.ID+"/sync", nil)
	req.SetPathValue("id", org.ID)
	rec := httptest.NewRecorder()
	h.TriggerSync(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code)
	require.Equal(t, 1, syncer.discoveries)
	require.Empty(t, syncer.enqueued, "an org connector has no collector to sync")
}

func TestOrgTemplateHandler(t *testing.T) {
	h, _ := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/aws-org/templates/graph-readonly-role.yaml", nil)
	req.SetPathValue("name", "graph-readonly-role.yaml")
	rec := httptest.NewRecorder()
	h.OrgTemplate(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "AWS::IAM::Role")

	for _, name := range []string{"nope.yaml", "embed.go", "..", ""} {
		req := httptest.NewRequest(http.MethodGet, "/api/aws-org/templates/x", nil)
		req.SetPathValue("name", name)
		rec := httptest.NewRecorder()
		h.OrgTemplate(rec, req)
		require.Equal(t, http.StatusNotFound, rec.Code, name)
	}
}

// The connection test makes live AWS calls with the org's credential; it is
// admin-only like every connector write, driven through RequireRole exactly as
// server.go wires it.
func TestTestConnection_NonAdmin_403(t *testing.T) {
	h, _, _, org := newOrgHandler(t)
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		path    string
		body    string
	}{
		{"test connection", h.TestConnection, "/api/connectors/" + org.ID + "/test", ""},
		{"create aws_org", h.Create, "/api/connectors", `{"type":"aws_org","name":"x","config":{"management_role_arn":"` + testMgmtRole + `","external_id":"abcdefgh"}}`},
		{"sync aws_org", h.TriggerSync, "/api/connectors/" + org.ID + "/sync", ""},
	} {
		for _, role := range []auth.Role{auth.RoleViewer, auth.RoleAnalyst} {
			t.Run(tc.name+"/"+string(role), func(t *testing.T) {
				req := asRole(httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body)), role)
				req.SetPathValue("id", org.ID)
				rec := httptest.NewRecorder()
				auth.RequireRole(auth.RoleAdmin, tc.handler)(rec, req)
				require.Equal(t, http.StatusForbidden, rec.Code)
			})
		}
	}
}
