package cronexpr

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		expr string
		ok   bool
	}{
		{"* * * * *", true},
		{"0 2 * * *", true},
		{"*/15 * * * *", true},
		{"0-30/10 9-17 * * 1-5", true},
		{"0 0 1,15 * *", true},
		{"0 0 * * 7", true},
		{"5/10 * * * *", true},
		{"  0   2 * * *  ", true},
		{"", false},
		{"0 2 * *", false},
		{"0 2 * * * *", false},
		{"@daily", false},
		{"60 * * * *", false},
		{"* 24 * * *", false},
		{"* * 0 * *", false},
		{"* * 32 * *", false},
		{"* * * 13 *", false},
		{"* * * * 8", false},
		{"*/0 * * * *", false},
		{"*/x * * * *", false},
		{"5-1 * * * *", false},
		{"1,,2 * * * *", false},
		{"-5 * * * *", false},
		{"a b c d e", false},
		{"0 2 * JAN *", false},
		{"0 0 31 2 *", false},
		{"0 0 30,31 2 *", false},
		{"0 0 31 4,6,9,11 *", false},
		{"0 0 29 2 *", true},
		{"0 0 31 2,3 *", true},
		{"0 0 31 2 1", true},
		{"0 0 */31 2 *", true},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			err := Validate(tt.expr)
			if tt.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrInvalid)
		})
	}
}

func TestDue(t *testing.T) {
	// Wednesday 2026-10-21 09:30 UTC.
	wed := time.Date(2026, 10, 21, 9, 30, 0, 0, time.UTC)
	sun := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		expr string
		at   time.Time
		want bool
	}{
		{"every minute", "* * * * *", wed, true},
		{"exact minute and hour", "30 9 * * *", wed, true},
		{"wrong minute", "31 9 * * *", wed, false},
		{"step hits", "*/15 * * * *", wed, true},
		{"step misses", "*/20 * * * *", wed, false},
		{"offset step", "0-59/10 * * * *", wed, true},
		{"number with step runs to the field max", "10/20 * * * *", wed, true},
		{"weekday range", "30 9 * * 1-5", wed, true},
		{"weekend range misses", "30 9 * * 0,6", wed, false},
		{"7 is sunday", "0 0 * * 7", sun, true},
		{"dom and dow both restricted: either matches", "30 9 1 * 3", wed, true},
		{"dom restricted, dow star: both must match", "30 9 1 * *", wed, false},
		{"month list", "30 9 * 1,10 *", wed, true},
		{"malformed never fires", "30 9 * *", wed, false},
		{"out-of-range part never fires", "30,99 9 * * *", wed, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Due(tt.expr, tt.at))
		})
	}
}
