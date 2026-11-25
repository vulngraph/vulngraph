package reason

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// promptRelToken matches rel tokens in the prompt's example Cypher:
// [r:Name], [:Name], [r1:A|B|C].
var promptRelToken = regexp.MustCompile(`\[\s*\w*\s*:\s*([A-Za-z_|]+)\s*\]`)

// TestCypherPromptRelsAreLoaded pins the NL→Cypher prompt to the loaded rel
// set: the schema block is generated from the registry, and every rel the
// EXAMPLES traverse must be loaded — an example teaching the model an unloaded
// rel produces queries that silently return zero rows.
func TestCypherPromptRelsAreLoaded(t *testing.T) {
	loaded := map[string]bool{}
	for _, r := range graphschema.LoadedRels() {
		loaded[r.Name] = true
	}
	matches := promptRelToken.FindAllStringSubmatch(cypherSystemPrompt, -1)
	require.NotEmpty(t, matches, "no rel tokens found in cypherSystemPrompt — extraction regex rotted")
	for _, m := range matches {
		for rel := range strings.SplitSeq(m[1], "|") {
			assert.True(t, loaded[rel],
				"cypherSystemPrompt example traverses %q which is not loaded into Ladybug — silent zero rows", rel)
		}
	}
	// The generated schema block must list every loaded rel.
	for rel := range loaded {
		assert.Contains(t, cypherSystemPrompt, "\n  "+rel+" ", "loaded rel %q missing from the prompt schema block", rel)
	}
}

// TestGraphPromptAdvertisesOnlyExpandRels pins the NL→spec prompt to the
// structured expand set — it once advertised RunsIn (never populated) and
// DeploysTo (not in the expand view), teaching the model specs that returned
// nothing on either engine.
func TestGraphPromptAdvertisesOnlyExpandRels(t *testing.T) {
	expand := map[string]bool{}
	for _, r := range graphschema.ExpandRels() {
		expand[r.Name] = true
	}
	// Every quoted edge_types value in the examples must be an expand rel.
	matches := edgeTypesList.FindAllStringSubmatch(graphSystemPrompt, -1)
	require.NotEmpty(t, matches)
	for _, m := range matches {
		for _, rel := range edgeTypeNames(m[1]) {
			assert.True(t, expand[rel],
				"graphSystemPrompt example uses edge_type %q which is not in the expand view", rel)
		}
	}
	assert.NotContains(t, graphSystemPrompt, "RunsIn", "RunsIn is never populated — must not be advertised")
}

// edgeTypesList matches an edge_types array in a GraphQuerySpec example.
var edgeTypesList = regexp.MustCompile(`"edge_types":\[([^\]]*)\]`)

func edgeTypeNames(list string) []string {
	var names []string
	for raw := range strings.SplitSeq(list, ",") {
		if name := strings.Trim(strings.TrimSpace(raw), `"`); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// TestPromptWorkloadRoleHopsIncludeHasRole: an EC2 instance reaches its role
// only through HasRole, so an example that follows ExecutesAs alone teaches the
// model a query that leaves every instance profile out.
func TestPromptWorkloadRoleHopsIncludeHasRole(t *testing.T) {
	for _, m := range promptRelToken.FindAllStringSubmatch(cypherSystemPrompt, -1) {
		rels := strings.Split(m[1], "|")
		if slices.Contains(rels, "ExecutesAs") {
			assert.Contains(t, rels, "HasRole", "cypherSystemPrompt hop %q follows ExecutesAs without HasRole", m[0])
		}
	}
	matches := edgeTypesList.FindAllStringSubmatch(graphSystemPrompt, -1)
	require.NotEmpty(t, matches)
	for _, m := range matches {
		rels := edgeTypeNames(m[1])
		if slices.Contains(rels, "ExecutesAs") {
			assert.Contains(t, rels, "HasRole", "graphSystemPrompt example %q follows ExecutesAs without HasRole", m[0])
		}
	}
}

// TestCypherPromptQueryShapeGuidance pins the rules the NL→Cypher prompt
// teaches about query shape. Variable-length paths, untyped patterns, label()
// and UNION with IN lists all run correctly on the engine
// (graphstore/engine_shapes_test.go), so the prompt must not forbid them as
// crashes; it must state the depth cap the engine enforces, and keep the
// INT32 boolean, reserved-keyword and read-only rules.
func TestCypherPromptQueryShapeGuidance(t *testing.T) {
	for _, stale := range []string{"crash", "SIGABRT", "SIGSEGV", "length_error", "NEVER use variable-length", "NEVER use the label()", "NEVER use UNION"} {
		assert.NotContains(t, cypherSystemPrompt, stale)
	}
	for _, rule := range []string{
		"explicit upper bound of at most 6",
		"-[:CanAssume*1..3]->",
		"a bare [*] stops at 6 hops",
		"Prefer explicit rel types",
		"are INT32 — use = 1 not = true",
		"RESERVED keyword — ALWAYS write it backtick-escaped",
		"Never use CREATE, MERGE, SET, DELETE, DROP, COPY, ALTER, CALL, or any write operation",
	} {
		assert.Contains(t, cypherSystemPrompt, rule)
	}
}

// promptLabelToken matches node-label tokens in prompt Cypher: (x:Label,
// (:Label, (x:`Group`.
var promptLabelToken = regexp.MustCompile("\\(\\s*\\w*\\s*:\\s*`?([A-Z][A-Za-z]*)`?")

// assertPromptSchemaIsLoaded fails t when prompt traverses a rel that is not
// loaded into Ladybug or names a node label no loaded rel reaches.
func assertPromptSchemaIsLoaded(t *testing.T, prompt string) {
	t.Helper()
	loaded := map[string]bool{}
	for _, r := range graphschema.LoadedRels() {
		loaded[r.Name] = true
	}
	labels := map[string]bool{}
	for _, l := range QueryableNodeLabels() {
		labels[l] = true
	}
	for _, m := range promptRelToken.FindAllStringSubmatch(prompt, -1) {
		for rel := range strings.SplitSeq(m[1], "|") {
			assert.True(t, loaded[strings.TrimRight(rel, "*0123456789.")], "prompt traverses %q which is not loaded", rel)
		}
	}
	for _, m := range promptLabelToken.FindAllStringSubmatch(prompt, -1) {
		assert.True(t, labels[m[1]], "prompt names node label %q which no loaded rel reaches", m[1])
	}
}

func TestCypherPromptLabelsExist(t *testing.T) {
	assertPromptSchemaIsLoaded(t, cypherSystemPrompt)
	for _, gone := range []string{"EC2Instance", "SecurityGroup"} {
		assert.NotContains(t, cypherSystemPrompt, gone, "%s has no node table", gone)
	}
}

// Every queryable label is worded, and every worded label is queryable — a
// doc for a label nothing loaded reaches would be advertised by nobody, and a
// queryable label without one would render as a bare name.
func TestNodeLabelDocsMatchQueryableLabels(t *testing.T) {
	queryable := map[string]bool{}
	for _, l := range QueryableNodeLabels() {
		queryable[l] = true
		assert.NotEmpty(t, nodeLabelDocs[l], "queryable label %q has no prompt doc", l)
	}
	for l := range nodeLabelDocs {
		assert.True(t, queryable[l], "nodeLabelDocs words %q, which no loaded rel reaches", l)
	}
	for _, unfed := range []string{graphschema.NodeSubnet, graphschema.NodeDNSZone, graphschema.NodeIamPolicy} {
		assert.False(t, queryable[unfed], "%s is reached by no loaded rel", unfed)
	}
	block := NodeLabelBlock()
	for l := range queryable {
		assert.Contains(t, block, "- "+l+": ")
	}
}
