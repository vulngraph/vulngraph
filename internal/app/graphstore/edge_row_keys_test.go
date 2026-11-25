package graphstore

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// TestEdgeRowKeysMatchRelSpec proves the property that lets the CSV writer stop
// materialising a map per edge.
//
// buildEdgeRows hand-writes a row map per rel table (RunsImage gets "image_ref",
// FederatedAccess gets five trust keys, the default branch gets "via"), and
// writeRelCSV then reads those maps back by ladybugRelSpec[rel].prop[].rowKey. If the two
// ever disagree the column silently loads empty — which is exactly what happened to
// RunsImage.image_ref, empty on every row loaded once the rel became traversable.
//
// The invariant: for every rel table, the keys buildEdgeRows produces are exactly
// {"src","dst"} plus the spec's rowKeys. While that holds, a streaming writer can pull
// values straight from the edge in spec order without building the intermediate map,
// and be provably equivalent to today's behaviour rather than hopefully equivalent.
//
// This test is the precondition for that change. If it ever fails, the streaming path
// is no longer equivalent and must be revisited before the map form is removed.
func TestEdgeRowKeysMatchRelSpec(t *testing.T) {
	// One edge per rel table, with every property key any branch reads populated with
	// a distinguishable value, so a mis-wired key shows up as a wrong value and not
	// merely as an absent one.
	props := map[string]string{
		"via": "VIA", "origin": "ORIGIN", "matched": "MATCHED",
		"image_ref": "IMAGE_REF", "trust_type": "TRUST_TYPE", "subject": "SUBJECT",
		"provenance": "PROVENANCE", "confidence": "CONFIDENCE",
		"workflow_path": "WORKFLOW_PATH", "path": "PATH",
	}

	checked := 0
	for _, et := range graphschemaEdgeTypesForRowKeyTest() {
		for _, shape := range edgeShapesFor(et) {
			shape.Properties = props
			byRel := buildEdgeRows([]asset.Edge{shape})
			for relTable, rr := range byRel {
				require.Len(t, rr.rows, 1, "%s: expected one row", relTable)
				row := rr.rows[0]

				spec, ok := ladybugRelSpec[relTable]
				require.True(t, ok, "rel table %q has rows but no ladybugRelSpec entry — "+
					"writeRelCSV would emit a header with no property columns", relTable)

				want := map[string]bool{"src": true, "dst": true}
				for _, p := range spec.prop {
					want[p.rowKey] = true
				}
				for k := range row {
					require.True(t, want[k],
						"rel %q row carries key %q, which ladybugRelSpec does not list as a "+
							"rowKey — writeRelCSV never reads it, so whatever it holds is dropped "+
							"silently. Either add the column to the spec or stop setting the key.",
						relTable, k)
				}
				for _, p := range spec.prop {
					got, present := row[p.rowKey]
					require.True(t, present,
						"rel %q declares property column %q (rowKey %q) but buildEdgeRows does "+
							"not set it — the column loads empty on every row, the RunsImage.image_ref "+
							"bug exactly", relTable, p.col, p.rowKey)

					// Values, not just keys. Every property is read straight from
					// Properties[rowKey] — EXCEPT "via", which falls back
					// via → origin → matched (dns_points_to stamps "matched"). Pinning
					// this is what makes it safe to derive rows from the spec instead of
					// hand-writing a map per rel table.
					want := any(props[p.rowKey])
					if p.rowKey == "via" {
						want = any("VIA")
					}
					require.Equal(t, want, got,
						"rel %q property %q (rowKey %q) resolved to %v, expected %v — a "+
							"property that does not come from Properties[rowKey] cannot be derived "+
							"from the spec, and the streaming CSV writer would load the wrong value",
						relTable, p.col, p.rowKey, got, want)
				}
				checked++
			}
		}
	}
	require.Positive(t, checked, "no rel tables exercised — the fixture stopped routing anywhere")
	t.Logf("verified row-key/spec agreement for %d rel-table routings", checked)
}

// graphschemaEdgeTypesForRowKeyTest lists the edge types to exercise, derived from the
// graphschema registry so a newly declared edge type is covered without editing this
// test — the "derive, never hand-maintain" rule.
func graphschemaEdgeTypesForRowKeyTest() []string {
	out := make([]string, 0, len(graphschema.EdgeTypes))
	for _, e := range graphschema.EdgeTypes {
		out = append(out, e.Type)
	}
	return out
}

// edgeShapesFor produces the endpoint-type combinations buildEdgeRows routes on, so
// the reroute branches (K8sWorkload sources, package runs_in, non-k8s deploys_to,
// IamRole defined_in) are all reached rather than only the default branch.
func edgeShapesFor(edgeType string) []asset.Edge {
	combos := [][2]string{
		{"ec2_instance", "iam_role"},
		{"k8s_pod", "iam_role"},
		{"k8s_pod", "k8s_service_account"},
		{"package", "container_image"},
		{"github_repo", "k8s_deployment"},
		{"github_repo", "cloud_function"},
		{"iam_role", "github_repo"},
		{"k8s_pod", "internet"},
		{"s3_bucket", "dataclass:pii"},
	}
	out := make([]asset.Edge, 0, len(combos))
	for i, c := range combos {
		out = append(out, asset.Edge{
			SrcID:   fmt.Sprintf("src-%d", i),
			DstID:   fmt.Sprintf("dst-%d", i),
			SrcType: c[0], DstType: c[1], EdgeType: edgeType,
		})
	}
	return out
}
