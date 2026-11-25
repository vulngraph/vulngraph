package finding

import "strings"

// routingHaving builds the finding_enrichment-side HAVING for List's owner and
// environment filters (see selectFindingKeysArgMax). It reads the same argMax
// over enriched_at as hydration, so a page never returns a finding whose
// hydrated owner contradicts the filter that selected it. Returns "" when
// neither filter is set; otherwise " HAVING …" ready to append after GROUP BY.
func routingHaving(f Filter) (string, []any) {
	var (
		conds []string
		args  []any
	)
	switch {
	case f.Owner == OwnerUnowned:
		conds = append(conds, "argMax(owner_source, enriched_at) = 'none'")
	case f.Owner != "":
		conds = append(conds, "argMax(owner_team, enriched_at) = ?")
		args = append(args, f.Owner)
	}
	if f.Environment != "" {
		conds = append(conds, "argMax(environment, enriched_at) = ?")
		args = append(args, f.Environment)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " HAVING " + strings.Join(conds, " AND "), args
}
