package reason

import "github.com/vulngraph/vulngraph/pkg/promptfence"

// fenceOpen/fenceClose/fenceEscape are re-exported package-level aliases so
// this file's own tests (fence_test.go, which pin the exact marker text and
// escaping behavior against the in-package buildPrompt/buildAdjudicationPrompt
// output) don't need to import pkg/promptfence directly.
const (
	fenceOpen  = promptfence.Open
	fenceClose = promptfence.Close
)

var fenceEscape = promptfence.Escape

// fence wraps untrusted text in the delimiters after neutralising any delimiter
// the text itself carries. Use it for every interpolation of scan-derived text
// into a prompt in this package; TestBuildPrompt_EveryStringFieldIsFenced checks
// the fields it seeds, and TestFence_* pins that a resource name containing the
// end marker cannot break out. Delegates to pkg/promptfence.Fence so
// there is exactly one escaper implementation: internal/app/respond cannot
// import this package (reason.go imports respond, so the reverse would be a
// cycle), and needs the same escaper for its own untrusted interpolations
// (internal/app/respond/refine_handler.go) — pkg/promptfence is the shared
// leaf both sides can import.
func fence(s string) string {
	return promptfence.Fence(s)
}

// Fence is the exported form of the same delimiter, for callers outside this
// package that interpolate untrusted text into a prompt — e.g. chat's
// frontend-supplied page-context block and tool results
// (internal/app/chat/service.go), which carry the same threat: whatever the
// user is currently viewing, or whatever a tool call returns, can itself be
// attacker-influenceable text (a finding title, a resource name) chosen by
// someone who never touches the chat UI. Equivalent to promptfence.Fence;
// kept here so existing callers importing internal/reason don't need to
// switch imports.
func Fence(s string) string {
	return fence(s)
}
