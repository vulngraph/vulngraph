// Package promptfence provides the untrusted-content fence every LLM prompt
// in this codebase uses to delimit attacker-influenceable text.
//
// It lives here, a leaf package with no internal/ imports, specifically so
// domains that cannot import each other directly can still share one escaper
// implementation. internal/reason imports internal/app/respond (reason.go),
// so respond cannot import reason without creating a cycle — respond's own
// untrusted interpolations (internal/app/respond/refine_handler.go) import
// this package instead. internal/reason's own fence() delegates here too, so
// there is exactly one escaper implementation, not two that could drift.
package promptfence

import (
	"regexp"
	"strings"
)

// Everything a scanner, registry, repository or cloud API echoed back to us —
// finding titles, descriptions, peer titles, the assembled grounded context —
// is attacker-influenceable text: someone who can name an S3 bucket, tag an
// instance, publish a container image, or serve a page nuclei matches can
// choose exactly what lands inside these delimiters.
//
// The system prompts instruct the model to treat everything between the markers
// as data, never as instructions. That instruction is only worth anything if the
// markers themselves cannot be forged: a finding title containing the literal
// end-marker would close the fence early and the remainder of the title would be
// read as prompt text at the trusted level.
const (
	Open  = "<<<UNTRUSTED>>>"
	Close = "<<<END UNTRUSTED>>>"
)

// Escape neutralises the delimiters inside untrusted text by appending
// "_ESCAPED" to every occurrence of the word "untrusted" in any casing
// (Unicode simple case folding, so "UNTRUſTED" counts too). A model does not
// read "<<<end untrusted>>>", "<<< END UNTRUSTED >>>" or a variant padded with
// a no-break or zero-width space or closed with a fullwidth ">" as different
// from the real close marker, so the escape cannot depend on what surrounds
// the word: every occurrence is broken.
//
// What Escape guarantees: both markers contain the word, and after Escape
// every occurrence of it, in any casing, is followed by "_ESCAPED", so no
// output contains either marker, or a variant of one that differs only in
// casing or in what surrounds the word. It matches the word itself, so it does
// not catch a form a model may still read as the word: a homoglyph (Cyrillic
// "е" for "e") or a zero-width or other format character inside it. The fence
// is a defence-in-depth delimiter, not a prompt-injection boundary: a model can
// still follow instructions in fenced text, and ADR 042's other controls
// (grounding, the policy gate, human approval) are the boundary.
//
// The word cannot overlap itself, and an occurrence already followed by
// "_ESCAPED" (in any casing) is left as it is, so a second pass leaves
// escaped text unchanged. Escaping the "<<<" run instead would NOT be safe:
// "<<<<" replaced non-overlapping re-forms a marker prefix out of the
// leftover "<".
//
// The original casing is kept, so prose that merely uses the word ("trusted
// and untrusted networks") still reads clearly, as "untrusted_ESCAPED".
//
// Exported (not just Fence) so internal/reason's own fence_test.go — which
// pins the exact marker text and escaping behavior against buildPrompt's
// output — can alias it locally without a second implementation to drift.
func Escape(s string) string {
	return untrustedWord.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasSuffix(strings.ToLower(m), escapedSuffix) {
			return m
		}
		return m + "_ESCAPED"
	})
}

const escapedSuffix = "_escaped"

var untrustedWord = regexp.MustCompile(`(?i)untrusted(?:_escaped)?`)

// Fence wraps untrusted text in the delimiters after neutralising any
// delimiter the text itself carries. Use it (or internal/reason's fence(),
// which delegates here) for every interpolation of scan-derived or otherwise
// attacker-influenceable text into a prompt. Call sites are reviewed, not
// mechanically enforced; TestFence_* pins only the escaping (a resource name
// containing the end marker cannot break out).
func Fence(s string) string {
	return Open + Escape(s) + Close
}
