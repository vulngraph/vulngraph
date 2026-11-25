package asset

import (
	"strings"
	"testing"
)

// An operator chasing a host has an address far more often than an instance id.
// The predicate matched only name+id, so searching an IP returned nothing for a
// host that is present and correctly inventoried, and it was unfindable.
func TestAssetSearchCondition_CoversEveryIdentifierAnOperatorHolds(t *testing.T) {
	cond, args := assetSearchCondition("10.0.0.42")

	for _, col := range []string{"name", "id", "private_ip", "public_ip", "domain", "endpoint"} {
		if !strings.Contains(cond, col+" ILIKE ?") {
			t.Errorf("search does not cover %s: %s", col, cond)
		}
	}
	if got, want := strings.Count(cond, "?"), len(args); got != want {
		t.Fatalf("placeholder/arg mismatch: %d placeholders, %d args", got, want)
	}
	for _, a := range args {
		if a != "%10.0.0.42%" {
			t.Fatalf("arg = %v, want the wrapped term", a)
		}
	}
}

// The search term must only ever reach the query as a bound arg — never
// interpolated — so a search string cannot alter the predicate.
func TestAssetSearchCondition_TermIsNeverInterpolated(t *testing.T) {
	cond, args := assetSearchCondition("'; DROP TABLE assets --")

	if strings.Contains(cond, "DROP") {
		t.Fatalf("search term leaked into the SQL: %s", cond)
	}
	for _, a := range args {
		if a != "%'; DROP TABLE assets --%" {
			t.Fatalf("arg = %v, want the term bound verbatim", a)
		}
	}
}
