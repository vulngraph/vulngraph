package webhook

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/connector"
)

type fakeConnectors struct {
	conn connector.Connector
	err  error
}

func (f fakeConnectors) Get(context.Context, string) (connector.Connector, error) {
	return f.conn, f.err
}

type fakeSyncer struct {
	enqueued []string
	err      error
}

func (f *fakeSyncer) EnqueueSync(_ context.Context, id string) error {
	if f.err != nil {
		return f.err
	}
	f.enqueued = append(f.enqueued, id)
	return nil
}

const secret = "hook-secret"

func ghConnector() connector.Connector {
	return connector.Connector{
		ID: "c1", Type: connector.TypeGitHub,
		Config: map[string]string{webhookSecretKey: secret},
	}
}

// deliverySeq lets each call to post default to a fresh, unique delivery ID
// so existing signature/dispatch tests don't collide with each other via the
// replay guard.
var deliverySeq int

// post builds a signed GitHub webhook request for connector c1, with a fresh
// X-GitHub-Delivery ID unless the caller wants to control it (see postWithDelivery).
func post(t *testing.T, h *Handler, event string, body string, sig string) *httptest.ResponseRecorder {
	t.Helper()
	deliverySeq++
	return postWithDelivery(t, h, event, body, sig, fmt.Sprintf("delivery-%d", deliverySeq))
}

// postWithDelivery is post with an explicit X-GitHub-Delivery value (or "" to
// omit the header entirely), for exercising the replay guard.
func postWithDelivery(t *testing.T, h *Handler, event string, body string, sig string, deliveryID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/github/c1", strings.NewReader(body))
	req.SetPathValue("id", "c1")
	if event != "" {
		req.Header.Set("X-GitHub-Event", event)
	}
	if sig != "" {
		req.Header.Set("X-Hub-Signature-256", sig)
	}
	if deliveryID != "" {
		req.Header.Set("X-GitHub-Delivery", deliveryID)
	}
	rec := httptest.NewRecorder()
	h.GitHub(rec, req)
	return rec
}

func TestGitHub_ValidPushEnqueuesSync(t *testing.T) {
	syncer := &fakeSyncer{}
	h := NewHandler(fakeConnectors{conn: ghConnector()}, syncer)
	body := `{"ref":"refs/heads/main"}`

	rec := post(t, h, "push", body, sign(secret, []byte(body)))

	require.Equal(t, http.StatusAccepted, rec.Code)
	require.Equal(t, []string{"c1"}, syncer.enqueued)
}

func TestGitHub_PingIsAcknowledgedWithoutSync(t *testing.T) {
	syncer := &fakeSyncer{}
	h := NewHandler(fakeConnectors{conn: ghConnector()}, syncer)
	body := `{"zen":"x"}`

	rec := post(t, h, "ping", body, sign(secret, []byte(body)))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Empty(t, syncer.enqueued, "ping must not trigger a sync")
}

func TestGitHub_BadSignatureRejected(t *testing.T) {
	syncer := &fakeSyncer{}
	h := NewHandler(fakeConnectors{conn: ghConnector()}, syncer)
	body := `{"ref":"refs/heads/main"}`

	rec := post(t, h, "push", body, sign("wrong-secret", []byte(body)))

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Empty(t, syncer.enqueued, "an unverified payload must never enqueue work")
}

func TestGitHub_NoSecretConfigured_Rejected(t *testing.T) {
	syncer := &fakeSyncer{}
	c := ghConnector()
	c.Config = map[string]string{} // event source not opted in
	h := NewHandler(fakeConnectors{conn: c}, syncer)
	body := `{"ref":"refs/heads/main"}`

	rec := post(t, h, "push", body, sign(secret, []byte(body)))

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Empty(t, syncer.enqueued)
}

func TestGitHub_MissingEventHeader_400(t *testing.T) {
	h := NewHandler(fakeConnectors{conn: ghConnector()}, &fakeSyncer{})
	body := `{}`

	rec := post(t, h, "", body, sign(secret, []byte(body)))

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// An unknown connector id answers exactly like a bad signature on a known
// one, so the endpoint is not an oracle for which connector ids exist.
func TestGitHub_UnknownConnector_SameAsBadSignature(t *testing.T) {
	syncer := &fakeSyncer{}
	unknown := post(t, NewHandler(fakeConnectors{err: connector.ErrNotFound}, syncer), "push", `{}`, sign(secret, []byte(`{}`)))
	badSig := post(t, NewHandler(fakeConnectors{conn: ghConnector()}, syncer), "push", `{}`, "sha256=whatever")

	require.Equal(t, http.StatusUnauthorized, unknown.Code)
	require.Equal(t, badSig.Code, unknown.Code)
	require.Equal(t, badSig.Body.String(), unknown.Body.String())
	require.Empty(t, syncer.enqueued)
}

func TestGitHub_ConnectorLoadError_500(t *testing.T) {
	h := NewHandler(fakeConnectors{err: errors.New("pg down")}, &fakeSyncer{})

	rec := post(t, h, "push", `{}`, "sha256=whatever")

	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestGitHub_EnqueueError_500(t *testing.T) {
	syncer := &fakeSyncer{err: errors.New("river down")}
	h := NewHandler(fakeConnectors{conn: ghConnector()}, syncer)
	body := `{"ref":"refs/heads/main"}`

	rec := post(t, h, "push", body, sign(secret, []byte(body)))

	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

// --- replay protection (defect 2) ---

func TestGitHub_SameDeliveryIDTwice_SecondRejected(t *testing.T) {
	syncer := &fakeSyncer{}
	h := NewHandler(fakeConnectors{conn: ghConnector()}, syncer)
	body := `{"ref":"refs/heads/main"}`
	sig := sign(secret, []byte(body))

	first := postWithDelivery(t, h, "push", body, sig, "dup-1")
	require.Equal(t, http.StatusAccepted, first.Code)
	require.Equal(t, []string{"c1"}, syncer.enqueued)

	second := postWithDelivery(t, h, "push", body, sig, "dup-1")
	require.Equal(t, http.StatusOK, second.Code, "replay must be acknowledged, not enqueued")
	require.Equal(t, []string{"c1"}, syncer.enqueued, "a replayed delivery must not enqueue a second sync")
}

// X-GitHub-Delivery is outside the HMAC: a replayer who rewrites it must not
// get a fresh sync, so the guard keys on the signed body.
func TestGitHub_ReplayWithRewrittenDeliveryID_Rejected(t *testing.T) {
	syncer := &fakeSyncer{}
	h := NewHandler(fakeConnectors{conn: ghConnector()}, syncer)
	body := `{"ref":"refs/heads/main"}`
	sig := sign(secret, []byte(body))

	first := postWithDelivery(t, h, "push", body, sig, "id-1")
	require.Equal(t, http.StatusAccepted, first.Code)

	second := postWithDelivery(t, h, "push", body, sig, "id-2-forged")
	require.Equal(t, http.StatusOK, second.Code, "replay must be acknowledged, not enqueued")
	require.Equal(t, []string{"c1"}, syncer.enqueued)
}

func TestGitHub_DistinctDeliveries_BothAccepted(t *testing.T) {
	syncer := &fakeSyncer{}
	h := NewHandler(fakeConnectors{conn: ghConnector()}, syncer)
	for i, body := range []string{`{"after":"aaa"}`, `{"after":"bbb"}`} {
		rec := postWithDelivery(t, h, "push", body, sign(secret, []byte(body)), fmt.Sprintf("id-%d", i))
		require.Equal(t, http.StatusAccepted, rec.Code)
	}
	require.Equal(t, []string{"c1", "c1"}, syncer.enqueued, "two distinct deliveries must both sync")
}

func TestGitHub_MissingDeliveryHeader_Rejected(t *testing.T) {
	syncer := &fakeSyncer{}
	h := NewHandler(fakeConnectors{conn: ghConnector()}, syncer)
	body := `{"ref":"refs/heads/main"}`

	rec := postWithDelivery(t, h, "push", body, sign(secret, []byte(body)), "")

	require.Equal(t, http.StatusBadRequest, rec.Code,
		"a request with no delivery ID would otherwise bypass the dedup check entirely — reject it")
	require.Empty(t, syncer.enqueued)
}

func TestGitHub_BadSignature_NeverPopulatesReplayGuard(t *testing.T) {
	// An unauthenticated request must never be able to populate or probe the
	// dedup set: verify signature FIRST, dedup second.
	syncer := &fakeSyncer{}
	h := NewHandler(fakeConnectors{conn: ghConnector()}, syncer)
	body := `{"ref":"refs/heads/main"}`

	forged := postWithDelivery(t, h, "push", body, sign("wrong-secret", []byte(body)), "shared-id")
	require.Equal(t, http.StatusUnauthorized, forged.Code)

	// The SAME body and delivery ID, now correctly signed, must still be
	// accepted — proving the rejected forgery above never touched the guard.
	genuine := postWithDelivery(t, h, "push", body, sign(secret, []byte(body)), "shared-id")
	require.Equal(t, http.StatusAccepted, genuine.Code)
	require.Equal(t, []string{"c1"}, syncer.enqueued)
}

func TestGitHub_ReplayAcrossDifferentConnectors_BothAccepted(t *testing.T) {
	// The guard is scoped per connector (path id), so the same payload landing
	// on two different connectors doesn't cause a false-positive rejection on
	// the second one.
	syncer := &fakeSyncer{}
	h := NewHandler(fakeConnectors{conn: ghConnector()}, syncer)
	body := `{"ref":"refs/heads/main"}`
	sig := sign(secret, []byte(body))

	rec := postWithDelivery(t, h, "push", body, sig, "shared-across-connectors")
	require.Equal(t, http.StatusAccepted, rec.Code)

	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/github/c2", strings.NewReader(body))
	req.SetPathValue("id", "c2")
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Delivery", "shared-across-connectors")
	rec2 := httptest.NewRecorder()
	h.GitHub(rec2, req)

	require.Equal(t, http.StatusAccepted, rec2.Code)
	require.Equal(t, []string{"c1", "c2"}, syncer.enqueued)
}
