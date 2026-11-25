package main

import "errors"

// bypassAuthAckEnv must be set alongside BYPASS_AUTH=true. One stray env var
// (a copied .env, a leftover dev value) must not be enough to serve every
// request as an admin.
const bypassAuthAckEnv = "BYPASS_AUTH_I_UNDERSTAND"

var errBypassAuthUnacknowledged = errors.New(
	"BYPASS_AUTH=true disables all authentication; refusing to start without " +
		bypassAuthAckEnv + "=yes (only behind a network-level auth gate such as ZTNA/oauth2-proxy)")

// bypassAuthEnabled reports whether auth bypass is requested, and refuses it
// unless the acknowledgement is also exactly "yes".
func bypassAuthEnabled(getenv func(string) string) (bool, error) {
	if getenv("BYPASS_AUTH") != "true" {
		return false, nil
	}
	if getenv(bypassAuthAckEnv) != "yes" {
		return false, errBypassAuthUnacknowledged
	}
	return true, nil
}
