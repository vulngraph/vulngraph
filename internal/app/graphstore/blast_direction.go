package graphstore

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// blastWalkDir is the direction a blast-radius walk follows an edge type: the
// attacker's direction, shared with the ClickHouse fallback via
// graphschema.AttackDirection (see there for the classification rationale).
func blastWalkDir(edgeType string) graphschema.Direction {
	return graphschema.AttackDirection(edgeType)
}

// relWalk reports whether a blast walk follows a Ladybug rel table outbound
// (src→dst) and/or inbound (dst→src). A rel table carrying several edge types
// is followed in every direction any of them is.
func relWalk(relTable string) (out, in bool) {
	named := false
	for _, e := range graphschema.EdgeTypes {
		if e.Rel != relTable && !slices.Contains(e.Reroutes, relTable) {
			continue
		}
		named = true
		switch blastWalkDir(e.Type) {
		case graphschema.DirReverse:
			in = true
		case graphschema.DirBoth:
			out, in = true, true
		default:
			out = true
		}
	}
	if !named {
		out = true // a rel table no registry type names: keep the historical outbound walk
	}
	return out, in
}

// blastHopQueries are the one-hop Ladybug queries a blast walk runs per frontier:
// for every node label, one query over the loaded rel tables it is followed
// OUT of and one over those it is followed IN to. Typed rel lists (never an
// untyped -[]->) are what lets direction be chosen per rel table. Each query
// projects m.id only; edge types are resolved afterwards (blastRadiusEdges).
var blastHopQueries = buildBlastHopQueries()

func buildBlastHopQueries() []string {
	outRels := map[string][]string{} // source label → rels walked src→dst
	inRels := map[string][]string{}  // destination label → rels walked dst→src
	for rel, spec := range ladybugRelSpec {
		out, in := relWalk(rel)
		if out {
			outRels[spec.from] = append(outRels[spec.from], rel)
		}
		if in {
			inRels[spec.to] = append(inRels[spec.to], rel)
		}
	}
	var qs []string
	for _, side := range []struct {
		rels    map[string][]string
		pattern string
	}{
		{outRels, "MATCH (n:%s)-[r:%s]->(m) WHERE n.id IN $ids RETURN DISTINCT m.id AS mid LIMIT 5000"},
		{inRels, "MATCH (n:%s)<-[r:%s]-(m) WHERE n.id IN $ids RETURN DISTINCT m.id AS mid LIMIT 5000"},
	} {
		labels := make([]string, 0, len(side.rels))
		for l := range side.rels {
			labels = append(labels, l)
		}
		sort.Strings(labels)
		for _, l := range labels {
			rels := side.rels[l]
			sort.Strings(rels)
			qs = append(qs, fmt.Sprintf(side.pattern, quoteLabel(l), strings.Join(rels, "|")))
		}
	}
	return qs
}
