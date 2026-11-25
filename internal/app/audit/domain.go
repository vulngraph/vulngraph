// Package audit writes the admin-action rows of the shared insert-only
// audit_events trail (ClickHouse, 7-year TTL): sign-in, sign-out and refused
// sign-ins, API keys refused on session-only routes, connector, user, API
// key, alert-channel and remediation-policy changes, manual finding
// resolves, saved-query and scan-profile changes, and the scans a person
// starts. Each domain names its own actions and calls Service.Record through
// an interface it defines; the executor, suppress, govern and respond domains
// write their own rows to the same table.
// docs/security-hardening.md#audit-trail lists every action.
package audit

import "time"

// Event is one audit_events row.
type Event struct {
	TS         time.Time
	Actor      string // the acting user's email; ActorUnknown when none is on the context
	Action     string // "<domain>.<verb>", named by the domain that acted
	TargetType string
	TargetID   string
	// Details is JSON: the domain's before/after values plus actor_user_id
	// and, when present, api_key_id and client_ip. Never a secret.
	Details string
}

// ActorUnknown is the actor of a row written with no authenticated principal
// on the context and no fallback actor configured. It is written, never
// dropped: an unattributed admin action is what an auditor needs to see.
const ActorUnknown = "unknown"

// ActorCLI is the fallback actor of the `graph user` commands, which run
// with database access and no signed-in user.
const ActorCLI = "cli"
