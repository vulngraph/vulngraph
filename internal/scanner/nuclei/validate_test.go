package nuclei

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// Phase 2 must actually parse the template: an unknown matcher type passes the
// structural check and is caught only when nuclei loads the template.
func TestValidate_InvalidMatcherType(t *testing.T) {
	bad := `id: test-bad
info:
  name: Test Template
  author: graph
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: invalid_matcher_type
        words: ["test"]`
	result := Validate(t.Context(), bad)
	require.False(t, result.Valid, "nuclei rejects an unknown matcher type at load")
	require.Contains(t, result.Errors[0].Message, "nuclei SDK")
}

func TestValidate_SDKRejectsWhatStructureAccepts(t *testing.T) {
	head := "info:\n  name: T\n  author: graph\n  severity: medium\n"
	cases := map[string]string{
		"malformed http block": "id: bad-http\n" + head + "http:\n  - method: 42\n    path: notalist\n    matchers: 7",
		"invalid dsl":          "id: bad-dsl\n" + head + "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}\"\n    matchers:\n      - type: dsl\n        dsl:\n          - \"status_code == (\"",
		"id with spaces":       "id: \"bad id\"\n" + head + "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}\"",
	}
	for name, tpl := range cases {
		t.Run(name, func(t *testing.T) {
			result := Validate(t.Context(), tpl)
			require.False(t, result.Valid)
			require.Contains(t, result.Errors[0].Message, "nuclei SDK")
		})
	}
}

func TestValidate_MissingAuthor(t *testing.T) {
	noAuthor := `id: test
info:
  name: Test
  severity: medium
http:
  - method: GET
    path: ["{{BaseURL}}"]`
	result := Validate(t.Context(), noAuthor)
	require.False(t, result.Valid, "nuclei refuses to load a template with no author")
	require.Contains(t, result.Errors[0].Message, "info.author")
}

func TestValidate_GoodTemplate(t *testing.T) {
	good := `id: valid-check
info:
  name: Valid Check
  author: graph
  severity: high
  tags: exposure
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words: ["admin"]`
	result := Validate(t.Context(), good)
	require.True(t, result.Valid, "valid template should pass: %v", result.Errors)
	require.NotNil(t, result.Info)
	require.Equal(t, "valid-check", result.Info.ID)
	require.Equal(t, "high", result.Info.Severity)
	require.Contains(t, result.Info.Protocols, "http")
}

func TestValidate_MissingID(t *testing.T) {
	noID := `info:
  name: Test
  severity: medium
http:
  - method: GET
    path: ["{{BaseURL}}"]`
	result := Validate(t.Context(), noID)
	require.False(t, result.Valid)
	require.NotEmpty(t, result.Errors)
	require.Contains(t, result.Errors[0].Message, "id")
}

func TestValidate_MissingName(t *testing.T) {
	noName := `id: test
info:
  severity: medium
http:
  - method: GET
    path: ["{{BaseURL}}"]`
	result := Validate(t.Context(), noName)
	require.False(t, result.Valid)
}

func TestValidate_InvalidSeverity(t *testing.T) {
	badSev := `id: test
info:
  name: Test
  severity: super-critical
http:
  - method: GET
    path: ["{{BaseURL}}"]`
	result := Validate(t.Context(), badSev)
	require.False(t, result.Valid, "should reject unknown severity")
	require.NotEmpty(t, result.Errors)
}

func TestValidate_NoProtocol(t *testing.T) {
	noProto := `id: test
info:
  name: Test
  severity: medium`
	result := Validate(t.Context(), noProto)
	require.False(t, result.Valid, "should reject template with no protocol block")
}

func TestValidate_YAMLParseError(t *testing.T) {
	bad := `id: test
info:
  name: [this is not valid yaml
  severity: medium`
	result := Validate(t.Context(), bad)
	require.False(t, result.Valid)
	require.NotEmpty(t, result.Errors)
}

func TestValidate_AllKnownMatcherTypes(t *testing.T) {
	for _, mt := range []string{"word", "regex", "status", "binary", "xpath", "dsl", "size"} {
		template := `id: test-` + mt + `
info:
  name: Test ` + mt + `
  author: graph
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: ` + mt
		result := Validate(t.Context(), template)
		require.True(t, result.Valid, "matcher type %q: %v", mt, result.Errors)
	}
}

func TestValidate_DNSTemplate(t *testing.T) {
	dns := `id: dns-check
info:
  name: DNS Check
  author: graph
  severity: info
  tags: dns
dns:
  - name: "{{FQDN}}"
    type: A
    matchers:
      - type: word
        words: ["127.0.0.1"]`
	result := Validate(t.Context(), dns)
	require.True(t, result.Valid, "%v", result.Errors)
	require.Equal(t, "dns-check", result.Info.ID)
	require.Contains(t, result.Info.Protocols, "dns")
}

// A tag on nuclei's default ignore list must not make a well-formed template
// invalid: the loader would drop it by tag, not because it failed to parse.
// Nuclei lowercases a template's tags but its index filter compares include
// tags case-sensitively, so a mixed-case tag must still be let through.
func TestValidate_IgnoreListTagsStillValid(t *testing.T) {
	for i, tag := range []string{"dos", "fuzz", "intrusive", "DOS", "Fuzz", " Intrusive "} {
		tpl := `id: tagged-` + strconv.Itoa(i) + `
info:
  name: Tagged
  author: graph
  severity: medium
  tags: "` + tag + `"
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: status
        status: [200]`
		result := Validate(t.Context(), tpl)
		require.True(t, result.Valid, "tag %q: %v", tag, result.Errors)
	}
}

// File and code templates never run here, so Validate says so by name instead
// of reporting a load failure.
func TestValidate_FileAndCodeUnsupported(t *testing.T) {
	head := "info:\n  name: T\n  author: graph\n  severity: medium\n"
	cases := map[string]string{
		"file": "id: file-check\n" + head + "file:\n  - extensions:\n      - all\n    matchers:\n      - type: word\n        words: [\"secret\"]",
		"code": "id: code-check\n" + head + "code:\n  - engine:\n      - sh\n    source: echo hi",
	}
	for name, tpl := range cases {
		t.Run(name, func(t *testing.T) {
			result := Validate(t.Context(), tpl)
			require.False(t, result.Valid)
			require.Contains(t, result.Errors[0].Message, "not supported")
		})
	}
}

// Validate and TestTemplate share templateIncludeTags, so both lift the
// ignore-list exclusion for a mixed-case tag.
func TestTemplateIncludeTagsNormalises(t *testing.T) {
	var doc templateDoc
	doc.Info.Tags = "DOS, Fuzz"
	require.Equal(t, []string{"dos", "fuzz"}, templateIncludeTags(doc))
	doc.Info.Tags = []any{" Dos "}
	require.Equal(t, []string{"dos"}, templateIncludeTags(doc))
	require.Empty(t, templateIncludeTags(templateDoc{}))
}
