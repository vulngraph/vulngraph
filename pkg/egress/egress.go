// Package egress holds the switches for outbound connections Vulngraph makes on its
// own, as opposed to the ones an operator configures (connectors, LLM, webhooks).
// docs/configuration.md#network-egress lists every destination and its switch.
//
// It is a separate package because three places read the same switches: the
// worker's dependency wiring, the scanner's copy of the periodic schedule, and
// the nuclei adapter.
package egress

import (
	"fmt"

	"github.com/vulngraph/vulngraph/pkg/envswitch"
)

// OfflineEnv is the umbrella switch. OFFLINE_MODE=true turns off every
// outbound feed that is on by default, as if each per-feed switch were set,
// and keeps every opt-in connection (Enabled) off whatever its switch says.
const OfflineEnv = "OFFLINE_MODE"

// Offline reports whether OFFLINE_MODE is on (envswitch.Parse spellings). An
// unrecognised value is an error and reads as on: the air-gap switch fails
// closed, so a caller that logs the error still makes no outbound call.
func Offline(getenv func(string) string) (bool, error) {
	on, err := envswitch.Parse(getenv, OfflineEnv)
	if err != nil {
		return true, fmt.Errorf("egress.Offline: %w", err)
	}
	return on, nil
}

// Disabled reports whether the feed behind key is off: key is on or
// OFFLINE_MODE is on. An unrecognised value in either is an error and reads as
// off, for the same reason as Offline.
func Disabled(getenv func(string) string, key string) (bool, error) {
	offline, err := Offline(getenv)
	if err != nil {
		return true, fmt.Errorf("egress.Disabled: %w", err)
	}
	off, err := envswitch.Parse(getenv, key)
	if err != nil {
		return true, fmt.Errorf("egress.Disabled: %w", err)
	}
	return off || offline, nil
}

// Enabled reports whether the opt-in connection behind key is on: key is on
// and OFFLINE_MODE is off. An unrecognised value in either is an error and
// reads as off, for the same reason as Offline.
func Enabled(getenv func(string) string, key string) (bool, error) {
	offline, err := Offline(getenv)
	if err != nil {
		return false, fmt.Errorf("egress.Enabled: %w", err)
	}
	on, err := envswitch.Parse(getenv, key)
	if err != nil {
		return false, fmt.Errorf("egress.Enabled: %w", err)
	}
	return on && !offline, nil
}
