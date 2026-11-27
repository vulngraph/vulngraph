package graphstore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vulngraph/vulngraph/internal/app/explore"
)

func TestNodeType(t *testing.T) {
	assert.Equal(t, "iam_role", nodeType(NodeIamRole, map[string]any{"type": "iam_role"}))
	assert.Equal(t, "github_repo", nodeType(NodeRepo, map[string]any{}))
	assert.Equal(t, "", nodeType(NodeAsset, map[string]any{}))
}

func TestDedupeEdges(t *testing.T) {
	a := explore.Edge{SrcID: "a", DstID: "b", EdgeType: "ExecutesAs"}
	b := explore.Edge{SrcID: "a", DstID: "b", EdgeType: "CanAssume"}
	assert.Equal(t, []explore.Edge{a, b}, dedupeEdges([]explore.Edge{a, a, b, a}))
	assert.Empty(t, dedupeEdges(nil))
}
