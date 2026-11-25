package graphstore

import (
	"fmt"
	"sort"
	"strings"
)

// signalRefreshCols names, per node label, the columns a signal-only refresh may
// update — and it is per-label rather than one global list on purpose.
//
// `score` is the reason. On Asset, IamRole and K8sWorkload it holds
// asset.RiskScore, which the BFS owns (bfsScoreLabels) and a signal refresh must
// never touch. On Package it holds sig.MaxScore — a finding severity, i.e. a
// signal. The same column name means two different things, which is exactly the
// trap bfsScoreLabels documents from the other direction, so writing one blanket
// column set would corrupt whichever side it got wrong.
//
// Deliberately excluded everywhere: `exposed` and `internet_hops`. Both are
// topology-derived, a refresh has no edges, and the rollup carries their zero
// values — writing them would assert "not exposed / not reachable" for every node.
// toxic_combo IS listed because it is refreshable, but only once recomputed from
// the stashed exposure set; see RefreshSignals.
//
// TestSignalRefreshColsMatchNodeLoader derives the expected coverage from
// nodeCSVCols and pins this map against it, so a new signal column or a new
// signal-carrying label cannot be added without either covering it here or
// failing the build.
var signalRefreshCols = map[string][]string{
	NodeAsset:       {"has_kev", "exploitable", "toxic_combo", "max_score", "privesc_count"},
	NodeIamRole:     {"has_kev", "exploitable", "toxic_combo", "max_score", "privesc_count"},
	NodeK8sWorkload: {"has_kev", "exploitable", "toxic_combo", "max_score", "privesc_count"},
	NodePackage:     {"score", "has_kev", "exploitable", "cve_id", "epss_score"},
}

// topologyOnlyNodeCols are signal-shaped node columns a signal-only refresh must
// never write, because they are derived from the edge set the refresh does not have.
// Named so the pin test can assert their absence rather than trusting review.
var topologyOnlyNodeCols = []string{"exposed", "internet_hops"}

// signalRefreshLabels returns the labels to refresh, in a stable order so the
// per-label UNWIND statements run deterministically (map iteration is randomised,
// and a nondeterministic write order makes a partial failure hard to reason about).
func signalRefreshLabels() []string {
	labels := make([]string, 0, len(signalRefreshCols))
	for l := range signalRefreshCols {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	return labels
}

// signalRefreshQuery builds the UNWIND ... SET statement for one label from
// signalRefreshCols, so the statement cannot drift from the declaration.
func signalRefreshQuery(label string) string {
	cols := signalRefreshCols[label]
	sets := make([]string, 0, len(cols))
	for _, c := range cols {
		sets = append(sets, fmt.Sprintf("n.%s = r.%s", c, c))
	}
	return fmt.Sprintf("UNWIND $rows AS r MATCH (n:%s {id: r.id}) SET %s",
		label, strings.Join(sets, ", "))
}
