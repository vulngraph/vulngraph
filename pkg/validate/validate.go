// Package validate provides shared input validation helpers for HTTP handlers.
// Centralising these checks keeps per-handler validation noise (many handlers
// each hand-rolling `if x == ""`) in one place where the error message is
// consistent and the rules are testable.
package validate

import (
	"errors"
	"fmt"
	"net/mail"
)

// ErrEmpty is returned by NonEmpty when the input is the empty string.
var ErrEmpty = errors.New("required field is empty")

// NonEmpty returns ErrEmpty (wrapped with the field name) when value is "".
// Use at the top of every handler for required string fields. The wrapping
// makes it cheap for callers to surface a useful message:
//
//	if err := validate.NonEmpty("policy_id", req.PolicyId); err != nil { … }
func NonEmpty(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s: %w", field, ErrEmpty)
	}
	return nil
}

// MaxLen returns an error when value exceeds max bytes. Use at API boundaries
// where the upstream limits are not enforced (e.g. JSON body fields with no
// schema-level length limit).
func MaxLen(field, value string, max int) error {
	if len(value) > max {
		return fmt.Errorf("%s: too long (%d bytes, max %d)", field, len(value), max)
	}
	return nil
}

// Email validates that value parses as an RFC-5322 address.
func Email(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s: %w", field, ErrEmpty)
	}
	if _, err := mail.ParseAddress(value); err != nil {
		return fmt.Errorf("%s: invalid email: %w", field, err)
	}
	return nil
}
