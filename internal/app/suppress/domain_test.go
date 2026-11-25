package suppress

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateExpiry(t *testing.T) {
	for _, tc := range []struct {
		name    string
		expires time.Time
		want    error
	}{
		{"missing", time.Time{}, ErrMissingExpiry},
		{"in the past", testNow.Add(-time.Second), ErrExpiryInPast},
		{"exactly now", testNow, ErrExpiryInPast},
		{"one second ahead", testNow.Add(time.Second), nil},
		{"ninety days", testNow.Add(90 * 24 * time.Hour), nil},
		{"max expiry", testNow.Add(MaxExpiry), nil},
		{"max expiry plus a day of date-picker slack", testNow.Add(MaxExpiry + maxExpiryGrace), nil},
		{"past max plus slack", testNow.Add(MaxExpiry + maxExpiryGrace + time.Second), ErrExpiryTooFar},
		{"two years", testNow.Add(2 * MaxExpiry), ErrExpiryTooFar},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateExpiry(testNow, tc.expires)
			if tc.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestSuppression_Expired(t *testing.T) {
	for _, tc := range []struct {
		name    string
		expires time.Time
		want    bool
	}{
		{"future", testNow.Add(time.Minute), false},
		{"exactly now is expired (exclusive bound)", testNow, true},
		{"past", testNow.Add(-time.Minute), true},
		// A row with no expiry cannot exist (NOT NULL), but if a zero value ever
		// reached here it must read as expired, never as permanent.
		{"zero value", time.Time{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, Suppression{ExpiresAt: tc.expires}.Expired(testNow))
		})
	}
}
