// Package cronexpr parses and evaluates the standard 5-field cron expressions
// (minute hour day-of-month month day-of-week) that saved queries and scan
// profiles are scheduled with. Validate and Due share one grammar, so an
// expression that validates is one Due can actually fire.
package cronexpr

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ErrInvalid is wrapped by every Validate failure.
var ErrInvalid = errors.New("cronexpr: invalid cron expression")

type bounds struct {
	name   string
	lo, hi int
}

// fieldBounds are the accepted ranges per field. Day-of-week accepts 7 as a
// second spelling of Sunday.
var fieldBounds = [5]bounds{
	{"minute", 0, 59},
	{"hour", 0, 23},
	{"day-of-month", 1, 31},
	{"month", 1, 12},
	{"day-of-week", 0, 7},
}

// Validate reports why expr is not a 5-field cron expression Due understands:
// each field is "*" or a comma list of N, A-B, */S, N/S or A-B/S, with every
// number inside the field's range and every step positive.
func Validate(expr string) error {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return fmt.Errorf("%w: want 5 fields (minute hour day-of-month month day-of-week), got %d", ErrInvalid, len(fields))
	}
	for i, f := range fields {
		if err := validateField(f, fieldBounds[i]); err != nil {
			return err
		}
	}
	if !dateReachable(fields[2], fields[3], fields[4]) {
		return fmt.Errorf("%w: day-of-month %q never occurs in month %q", ErrInvalid, fields[2], fields[3])
	}
	return nil
}

// daysIn is the longest each month gets (February in a leap year).
var daysIn = [13]int{0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}

// dateReachable reports whether some month in the month field has a day the
// day-of-month field names ("0 0 31 2 *" never fires). A restricted
// day-of-week fires on its own under cron's OR rule, so it always is.
func dateReachable(dom, month, dow string) bool {
	if dom == "*" || dow != "*" {
		return true
	}
	for m := 1; m <= 12; m++ {
		if !field(month, m, 1, 12) {
			continue
		}
		for d := 1; d <= daysIn[m]; d++ {
			if field(dom, d, 1, 31) {
				return true
			}
		}
	}
	return false
}

func validateField(field string, b bounds) error {
	for _, part := range strings.Split(field, ",") {
		rng := part
		if i := strings.IndexByte(part, '/'); i >= 0 {
			rng = part[:i]
			if s, err := strconv.Atoi(part[i+1:]); err != nil || s <= 0 {
				return fmt.Errorf("%w: %s step %q must be a positive integer", ErrInvalid, b.name, part[i+1:])
			}
		}
		switch {
		case rng == "*":
		case strings.Contains(rng, "-"):
			lohi := strings.SplitN(rng, "-", 2)
			lo, err1 := strconv.Atoi(lohi[0])
			hi, err2 := strconv.Atoi(lohi[1])
			if err1 != nil || err2 != nil || lo < b.lo || hi > b.hi || lo > hi {
				return fmt.Errorf("%w: %s range %q must be A-B with %d <= A <= B <= %d", ErrInvalid, b.name, rng, b.lo, b.hi)
			}
		default:
			n, err := strconv.Atoi(rng)
			if err != nil || n < b.lo || n > b.hi {
				return fmt.Errorf("%w: %s value %q must be * or a number in %d-%d", ErrInvalid, b.name, rng, b.lo, b.hi)
			}
		}
	}
	return nil
}

// Due reports whether expr matches time t. Day-of-month and day-of-week use
// cron's OR semantics when both are restricted. A malformed expression never
// fires; Validate says why.
func Due(expr string, t time.Time) bool {
	if Validate(expr) != nil {
		return false
	}
	fields := strings.Fields(expr)
	minute := field(fields[0], t.Minute(), 0, 59)
	hour := field(fields[1], t.Hour(), 0, 23)
	month := field(fields[3], int(t.Month()), 1, 12)
	dom := fields[2]
	dowExpr := fields[4]
	domMatch := field(dom, t.Day(), 1, 31)
	// Go: Sunday=0..Saturday=6, matching cron's 0-6 (and 7=Sunday handled below).
	dowMatch := field(dowExpr, int(t.Weekday()), 0, 6) ||
		(int(t.Weekday()) == 0 && field(dowExpr, 7, 0, 7))

	// Cron OR semantics: if both DOM and DOW are restricted (neither "*"), the
	// command runs when EITHER matches. If one is "*", both must match.
	var dayMatch bool
	switch {
	case dom == "*" && dowExpr == "*":
		dayMatch = true
	case dom != "*" && dowExpr != "*":
		dayMatch = domMatch || dowMatch
	default:
		dayMatch = domMatch && dowMatch
	}
	return minute && hour && month && dayMatch
}

// field evaluates one already-validated cron field against val.
func field(f string, val, lo, hi int) bool {
	if f == "*" {
		return true
	}
	for _, part := range strings.Split(f, ",") {
		step := 1
		rng := part
		if i := strings.IndexByte(part, '/'); i >= 0 {
			rng = part[:i]
			step, _ = strconv.Atoi(part[i+1:])
		}
		start, end := lo, hi
		switch {
		case rng == "*":
		case strings.Contains(rng, "-"):
			lohi := strings.SplitN(rng, "-", 2)
			start, _ = strconv.Atoi(lohi[0])
			end, _ = strconv.Atoi(lohi[1])
		default:
			n, _ := strconv.Atoi(rng)
			if step == 1 {
				if n == val {
					return true
				}
				continue
			}
			start = n
		}
		for v := start; v <= end; v += step {
			if v == val {
				return true
			}
		}
	}
	return false
}
