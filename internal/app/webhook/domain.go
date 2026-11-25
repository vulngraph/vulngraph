// Package webhook receives provider change-events and turns them into targeted
// syncs — the event-driven freshness layer. A verified event enqueues
// an immediate sync of the affected connector, so a change surfaces in seconds
// instead of waiting for the periodic reconciliation sweep.
//
// These endpoints are NOT session-authenticated: the caller is the provider, not
// a logged-in operator. Authenticity is the provider's payload signature (HMAC),
// verified against the connector's stored webhook secret — an unsigned or
// mis-signed request is rejected before any work is enqueued.
package webhook

import "errors"

// ErrBadSignature is returned when a payload's signature does not match the
// connector's webhook secret (or the connector has no secret configured — the
// two are deliberately indistinguishable to the caller).
var ErrBadSignature = errors.New("webhook: signature verification failed")
