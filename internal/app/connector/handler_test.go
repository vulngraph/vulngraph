package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeSyncer records which connector IDs were asked to sync.
type fakeSyncer struct {
	enqueued    []string
	discoveries int
}

func (f *fakeSyncer) EnqueueSync(_ context.Context, id string) error {
	f.enqueued = append(f.enqueued, id)
	return nil
}

func (f *fakeSyncer) EnqueueOrgDiscovery(context.Context) error {
	f.discoveries++
	return nil
}

func newTestHandler(t *testing.T) (*Handler, *fakeSyncer) {
	t.Helper()
	svc, _ := newTestService(t)
	syncer := &fakeSyncer{}
	return NewHandler(svc, syncer), syncer
}

func TestCreateHandler_OmitsConfigFromResponse(t *testing.T) {
	h, _ := newTestHandler(t)

	body := `{"type":"aws","name":"prod","config":{"role_arn":"arn:aws:iam::1:role/x","region":"eu-west-1"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/connectors", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.Create(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)
	require.NotContains(t, rec.Body.String(), "role/x", "response must never echo credentials")

	var got map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, "aws", got["type"])
	_, hasConfig := got["config"]
	require.False(t, hasConfig, "response must not contain a config field")
}

func TestCreateHandler_MissingConfig_400(t *testing.T) {
	h, _ := newTestHandler(t)

	body := `{"type":"aws","name":"prod","config":{"role_arn":"only"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/connectors", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.Create(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestDeleteHandler_NotFound_404(t *testing.T) {
	h, _ := newTestHandler(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/connectors/ghost", nil)
	req.SetPathValue("id", "ghost")
	rec := httptest.NewRecorder()
	h.Delete(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
}

// A mode change on an unknown connector is a 404, not a 204 for a write that
// touched nothing.
func TestSetModeHandler_NotFound_404(t *testing.T) {
	h, _ := newTestHandler(t)

	req := httptest.NewRequest(http.MethodPut, "/api/connectors/ghost/mode", strings.NewReader(`{"mode":"read_write"}`))
	req.SetPathValue("id", "ghost")
	rec := httptest.NewRecorder()
	h.SetMode(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestTriggerSync_EnqueuesForExistingConnector(t *testing.T) {
	h, syncer := newTestHandler(t)

	created, err := h.svc.Create(context.Background(), TypeAWS, "prod", awsConfig, "")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/connectors/"+created.ID+"/sync", nil)
	req.SetPathValue("id", created.ID)
	rec := httptest.NewRecorder()
	h.TriggerSync(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code)
	require.Equal(t, []string{created.ID}, syncer.enqueued)
}

func TestTriggerSync_UnknownConnector_404(t *testing.T) {
	h, syncer := newTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/connectors/ghost/sync", nil)
	req.SetPathValue("id", "ghost")
	rec := httptest.NewRecorder()
	h.TriggerSync(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
	require.Empty(t, syncer.enqueued, "must not enqueue a sync for a connector that does not exist")
}

func TestListHandler_ReturnsMetadataOnly(t *testing.T) {
	h, _ := newTestHandler(t)

	create := `{"type":"github","name":"org","config":{"app_id":"1","installation_id":"2","private_key_pem":"KEY"}}`
	creq := httptest.NewRequest(http.MethodPost, "/api/connectors", strings.NewReader(create))
	h.Create(httptest.NewRecorder(), creq)

	req := httptest.NewRequest(http.MethodGet, "/api/connectors", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, rec.Body.String(), "KEY", "list must never expose credentials")
	var got []map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Len(t, got, 1)
}

func TestPurgeHandler_ConfirmNameMismatch_400(t *testing.T) {
	h, _ := newTestHandler(t)
	c, err := h.svc.Create(context.Background(), TypeAWS, "aws-prod", awsConfig, "")
	require.NoError(t, err)
	h.svc.WithPurge(&fakeAssetPurger{idsByAccount: map[string][]string{}}, &fakeFindingResolver{})

	body := `{"confirm_name":"wrong-name"}`
	req := httptest.NewRequest(http.MethodPost, "/api/connectors/"+c.ID+"/purge", strings.NewReader(body))
	req.SetPathValue("id", c.ID)
	rec := httptest.NewRecorder()
	h.Purge(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPurgeHandler_NotFound_404(t *testing.T) {
	h, _ := newTestHandler(t)
	h.svc.WithPurge(&fakeAssetPurger{idsByAccount: map[string][]string{}}, &fakeFindingResolver{})

	body := `{"confirm_name":"whatever"}`
	req := httptest.NewRequest(http.MethodPost, "/api/connectors/ghost/purge", strings.NewReader(body))
	req.SetPathValue("id", "ghost")
	rec := httptest.NewRecorder()
	h.Purge(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestPurgeHandler_HappyPath(t *testing.T) {
	h, _ := newTestHandler(t)
	c, err := h.svc.Create(context.Background(), TypeAWS, "aws-prod", map[string]string{
		"role_arn": "arn:aws:iam::555555555555:role/x", "region": "eu-west-1",
	}, "")
	require.NoError(t, err)
	h.svc.WithPurge(&fakeAssetPurger{idsByAccount: map[string][]string{
		"aws/555555555555": {"asset-a", "asset-b"},
	}}, &fakeFindingResolver{})

	body := `{"confirm_name":"aws-prod"}`
	req := httptest.NewRequest(http.MethodPost, "/api/connectors/"+c.ID+"/purge", strings.NewReader(body))
	req.SetPathValue("id", c.ID)
	rec := httptest.NewRecorder()
	h.Purge(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var got purgeResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, 2, got.AssetsDeleted)
	require.Equal(t, 2, got.FindingsResolved)

	_, err = h.svc.Get(context.Background(), c.ID)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestPurgeHandler_NotWired_400(t *testing.T) {
	h, _ := newTestHandler(t)
	c, err := h.svc.Create(context.Background(), TypeAWS, "aws-prod", awsConfig, "")
	require.NoError(t, err)
	// WithPurge deliberately not called — must fail closed, not 500.

	body := `{"confirm_name":"aws-prod"}`
	req := httptest.NewRequest(http.MethodPost, "/api/connectors/"+c.ID+"/purge", strings.NewReader(body))
	req.SetPathValue("id", c.ID)
	rec := httptest.NewRecorder()
	h.Purge(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}
