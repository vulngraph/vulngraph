// Package envswitch parses on/off environment switches, so every switch
// accepts the same spellings and none reads an unrecognised value as either
// setting. The variables docs/configuration.md lists as "Flag" (BYPASS_AUTH,
// COOKIE_INSECURE and others) do not use it: they turn on only for the exact
// string "true".
package envswitch

import (
	"fmt"
	"strings"
)

// Parse reads key as an on/off switch. Unset or empty is off. The value is
// trimmed and matched case-insensitively: 1, true, yes and on are on; 0,
// false, no and off are off. Anything else is an error naming the key, so a
// typo stops the process at startup instead of being read either way.
func Parse(getenv func(string) string, key string) (bool, error) {
	v := strings.TrimSpace(getenv(key))
	switch strings.ToLower(v) {
	case "", "0", "false", "no", "off":
		return false, nil
	case "1", "true", "yes", "on":
		return true, nil
	}
	return false, fmt.Errorf("%s=%q: must be one of 1/true/yes/on or 0/false/no/off", key, v)
}
