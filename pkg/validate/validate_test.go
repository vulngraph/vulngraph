package validate_test

import (
	"errors"
	"testing"

	"github.com/vulngraph/vulngraph/pkg/validate"
)

func TestNonEmpty(t *testing.T) {
	if err := validate.NonEmpty("policy_id", ""); !errors.Is(err, validate.ErrEmpty) {
		t.Errorf("NonEmpty empty: want ErrEmpty, got %v", err)
	}
	if err := validate.NonEmpty("policy_id", "  "); err != nil {
		t.Errorf("NonEmpty whitespace passes through (expected) but got error: %v", err)
	}
	if err := validate.NonEmpty("policy_id", "abc"); err != nil {
		t.Errorf("NonEmpty valid input returned error: %v", err)
	}
}

func TestMaxLen(t *testing.T) {
	if err := validate.MaxLen("body", "0123456789", 5); err == nil {
		t.Error("expected error for over-limit input")
	}
	if err := validate.MaxLen("body", "ok", 5); err != nil {
		t.Errorf("expected nil for under-limit, got %v", err)
	}
}

func TestEmail(t *testing.T) {
	if err := validate.Email("contact", ""); err == nil {
		t.Error("expected error for empty email")
	}
	if err := validate.Email("contact", "not-an-email"); err == nil {
		t.Error("expected error for malformed email")
	}
	if err := validate.Email("contact", "user@example.com"); err != nil {
		t.Errorf("expected nil for valid email, got %v", err)
	}
}
