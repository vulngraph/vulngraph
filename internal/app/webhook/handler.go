package webhook

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"

	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// maxBody caps the payload we read. GitHub webhook deliveries are well under
// this; the limit bounds memory for an unauthenticated endpoint.
const maxBody = 1 << 20 // 1 MiB

// webhookSecretKey is the connector config key holding the shared HMAC secret.
const webhookSecretKey = "webhook_secret"

// ConnectorLookup loads a connector with its decrypted config. connector.Service
// implements it.
type ConnectorLookup interface {
	Get(ctx context.Context, id string) (connector.Connector, error)
}

// Syncer enqueues an immediate sync for a connector. jobs.Enqueuer implements it
// (the same seam the connector handler uses), keeping River out of this package.
type Syncer interface {
	EnqueueSync(ctx context.Context, connectorID string) error
}

type Handler struct {
	connectors ConnectorLookup
	syncer     Syncer
	// replay dedups on a hash of the signed body so a captured, validly-signed
	// payload can't be replayed to force repeated syncs. See GitHub's doc
	// comment for the threat model this does and does not cover.
	replay *replayGuard
}

func NewHandler(connectors ConnectorLookup, syncer Syncer) *Handler {
	return &Handler{connectors: connectors, syncer: syncer, replay: newReplayGuard(replayGuardCapacity)}
}

// GitHub handles a GitHub webhook for one connector (id in the path). It verifies
// the X-Hub-Signature-256 HMAC against the connector's stored webhook_secret,
// then — for any verified event other than ping — enqueues an immediate sync
// of that connector.
// The sync job is unique-while-queued, so a burst of pushes coalesces into one
// sync rather than a thundering herd.
//
// Replay protection: verified requests are deduped on the SHA-256 of the
// signed body (h.replay), checked AFTER signature verification so an
// unauthenticated request can never populate or probe the dedup set. The
// X-GitHub-Delivery header is NOT part of the key: it is outside the HMAC, so
// a replayer could change it at will and every variant would look new. Every
// genuine delivery has a distinct body (push payloads carry the commit range
// and timestamps), and a manual "Redeliver" in GitHub resends the same body,
// which is exactly a replay. The delivery header is still required and logged,
// since GitHub always sends it.
//
// This is a per-process, bounded, in-memory set (replayGuard), not a
// persisted or shared one — deliberately, given the actual threat: the only
// effect of a successful replay is a redundant SyncConnectorArgs job, not a
// mutation. That job is itself
// unique-while-queued-or-running (jobs.SyncConnectorArgs), which ALREADY
// blocks a replay landing anywhere in the cluster while the original sync is
// still in flight, regardless of which pod's replay guard sees it. What this
// guard adds is catching a delayed replay — one arriving after the original
// sync has already finished — on whichever pod happens to receive it. With
// multiple graph-serve replicas running (the normal deployment shape) a
// delayed replay that lands on a DIFFERENT pod than the original is NOT caught: each pod's guard
// is independent, so that request still enqueues one more sync. Accepted
// rather than closed with a shared store (Postgres/Redis) because the
// residual cost is one redundant, side-effect-free sync job — the same cost
// class as the periodic reconciliation sweep finding the same change a few
// minutes early — which does not justify a shared store.
func (h *Handler) GitHub(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// An unknown connector id falls through with no secret, so it fails
	// verification with the same 401 as a bad signature: the endpoint does
	// not reveal which connector ids exist.
	c, err := h.connectors.Get(r.Context(), id)
	if errors.Is(err, connector.ErrNotFound) {
		c, err = connector.Connector{}, nil
	}
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Str("connector_id", id).Msg("webhook: load connector failed")
		errs.WriteHTTPError(w, errs.Internal("failed to load connector"))
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("failed to read request body"))
		return
	}

	// Authenticity is the signature. An unknown connector, a missing/wrong
	// secret and a forged payload are reported identically, so the endpoint
	// reveals nothing about any of them.
	if !verifyGitHubSignature(c.Config[webhookSecretKey], body, r.Header.Get("X-Hub-Signature-256")) {
		errs.WriteHTTPErrorCtx(r.Context(), w, "signature verification failed", http.StatusUnauthorized)
		return
	}

	deliveryID := r.Header.Get("X-GitHub-Delivery")
	if deliveryID == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("missing X-GitHub-Delivery header"))
		return
	}
	sum := sha256.Sum256(body)
	if h.replay.seenBefore(id + ":" + hex.EncodeToString(sum[:])) {
		log.FromContext(r.Context()).Warn().Str("connector_id", id).Str("delivery_id", deliveryID).
			Msg("webhook: replayed delivery rejected")
		// 2xx, not an error status: this is a valid, already-processed
		// delivery from GitHub's point of view, and a non-2xx here would
		// make GitHub's own retry logic redeliver it again.
		w.WriteHeader(http.StatusOK)
		return
	}

	switch r.Header.Get("X-GitHub-Event") {
	case "":
		errs.WriteHTTPError(w, errs.InvalidInput("missing X-GitHub-Event header"))
		return
	case "ping":
		// GitHub's setup handshake — verified, nothing to sync.
		w.WriteHeader(http.StatusOK)
		return
	}

	if err := h.syncer.EnqueueSync(r.Context(), id); err != nil {
		log.FromContext(r.Context()).Error().Err(err).Str("connector_id", id).Msg("webhook: enqueue sync failed")
		errs.WriteHTTPError(w, errs.Internal("failed to enqueue sync"))
		return
	}
	log.FromContext(r.Context()).Info().Str("connector_id", id).
		Str("event", r.Header.Get("X-GitHub-Event")).Msg("webhook: targeted sync enqueued")
	w.WriteHeader(http.StatusAccepted)
}
