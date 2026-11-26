package graphquery

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReferencesLabels(t *testing.T) {
	for _, tc := range []struct {
		q    string
		want bool
	}{
		{"MATCH (p:Package) RETURN p", true},
		{"MATCH (p:\n \x60Package\x60) RETURN p", true},
		{"MATCH (a)-[:RunsImage|RunsPackage]->(p) RETURN p", true},
		{"MATCH (a)-[:HasRole|\x60DependsOn\x60]->(p) RETURN p", true},
		{"MATCH (a:Asset) WHERE a.name=':Package' RETURN a", false},
		{"MATCH (a:Asset) RETURN a // :Package\n", false},
		{"MATCH (a:Asset) RETURN a.Package", false},
		{"MATCH (a:Asset) RETURN a", false},
	} {
		t.Run(tc.q, func(t *testing.T) {
			require.True(t, IsReadOnly(tc.q))
			require.Equal(t, tc.want, ReferencesLabels(tc.q, "Package", "RunsPackage", "DependsOn"))
		})
	}
}
