package belief

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// mustFixClassDecl matches an enrich must-fix class constant declaration. The
// classes are read out of the enrich SOURCE as text rather than imported: no
// internal/app domain imports another today, and the point of this guard is to
// notice a class that was added over there without a decision being taken here.
var mustFixClassDecl = regexp.MustCompile(`(?m)^\s*MustFix[A-Za-z]*\s*=\s*"([a-z_]+)"`)

// inListValues pulls the quoted values out of the backlog cursor's
// `must_fix_class IN (...)` predicate.
var inListValues = regexp.MustCompile(`must_fix_class IN \(([^)]*)\)`)

// TestAdjudicationBacklogSQLMirrorsNeedsAdjudication holds the two halves of the
// attention gate equal: NeedsAdjudication decides by EXCLUDING the decisive
// classes, while selectAdjudicationBacklog has to ENUMERATE the rest in SQL. A
// class present in enrich but missing from that IN list is invisible to the sweep
// — the Go gate would happily adjudicate it, but no row carrying it is ever
// selected, so the population disappears with no error anywhere.
//
// This is exactly how must_fix_class=routine shipped: it replaced "" as the
// classifier's fall-through verdict, which is the majority of enriched findings
// and most of what this cursor exists to feed, and the IN list still enumerated
// only the empty string and elevated.
func TestAdjudicationBacklogSQLMirrorsNeedsAdjudication(t *testing.T) {
	src, err := os.ReadFile("../enrich/mustfix.go")
	require.NoError(t, err, "read the enrich must-fix classes")

	classes := []string{""} // "" is a real value: unenriched, or a gate withdrawal
	for _, m := range mustFixClassDecl.FindAllStringSubmatch(string(src), -1) {
		classes = append(classes, m[1])
	}
	require.Greater(t, len(classes), 3, "must-fix class constants must be discoverable")

	var wantInList []string
	for _, c := range classes {
		if NeedsAdjudication(SeverityInputs{Band: "high", MustFixClass: c}) {
			wantInList = append(wantInList, c)
		}
	}
	require.NotEmpty(t, wantInList, "some class must be adjudicatable")

	m := inListValues.FindStringSubmatch(selectAdjudicationBacklog)
	require.Len(t, m, 2, "the backlog cursor must filter on a must_fix_class IN list")
	var gotInList []string
	for _, v := range strings.Split(m[1], ",") {
		gotInList = append(gotInList, strings.Trim(strings.TrimSpace(v), "'"))
	}

	sort.Strings(wantInList)
	sort.Strings(gotInList)
	require.Equal(t, wantInList, gotInList,
		"every must-fix class NeedsAdjudication accepts must appear in the backlog cursor's IN list, and nothing else may")
}
