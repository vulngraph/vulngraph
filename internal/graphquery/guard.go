// Package graphquery holds the shared read-only Cypher guard used everywhere an
// untrusted graph query enters the system: the /api/graph/cypher HTTP endpoint,
// the explore NL→Cypher path, the MCP graph_query tool, LLM-generated Cypher,
// and saved queries. It is a leaf package (no internal imports) so all of those
// callers can depend on it without import cycles.
//
// The guard has two layers: an allowlist of opening clauses (readStarters) and a
// keyword denylist for the rest of the query (forbiddenRe). graphstore backs it
// with the engine's own prepared-statement read-only check (IsReadOnly on the
// prepared statement) before executing. The opening-clause allowlist is what
// stops statements no write-keyword denylist names. LadybugDB's grammar accepts
// more than MATCH/RETURN: LOAD FROM '<path|url>' (server-side
// file/HTTP read), INSTALL … FROM '<url>' + LOAD EXTENSION (remote code load in
// the worker pod), ATTACH (outbound DB connection), and EXPORT/IMPORT DATABASE
// (full-graph exfil). None of those contain a classic write keyword, so a
// denylist of CREATE/SET/DELETE/… lets them through. Because every one of those
// statements is a top-level clause, requiring the query to BEGIN with a known
// reading clause rejects them all at the first token — before any string
// literal or property value can influence the decision.
package graphquery

import (
	"regexp"
	"strings"
)

// readStarters are the only clause keywords a safe query may begin with. Every
// write/DDL/IO statement starts with a different keyword and is rejected here.
var readStarters = map[string]bool{
	"MATCH":    true,
	"OPTIONAL": true, // OPTIONAL MATCH
	"WITH":     true,
	"UNWIND":   true,
	"RETURN":   true,
}

// forbiddenRe catches write/DDL/IO keywords that can also appear MID-query
// (e.g. MATCH … SET, or a chained CALL). Applied after comments and string
// literals are stripped, so a resource literally named "SET" cannot trip it.
//
// The leading boundary is "not a letter or underscore", not \b: RE2's \b counts
// digits as word characters, but the engine lexes `1=1SET` as the integer 1
// followed by SET, so \b let `WHERE 1=1SET n.x=0` through as a read. Rejecting a
// keyword after a digit also catches identifiers like `v2set` — the safe
// direction. The trailing \b is sound: a keyword followed by a letter, digit or
// underscore lexes as one identifier in the engine too.
var forbiddenRe = regexp.MustCompile(`(?i)(?:^|[^A-Za-z_])(CREATE|MERGE|SET|DELETE|REMOVE|DROP|COPY|ALTER|LOAD|INSTALL|ATTACH|DETACH|EXPORT|IMPORT|USE|CALL|MACRO|CHECKPOINT|BEGIN|COMMIT|ROLLBACK)\b`)

// IsReadOnly reports whether q is a single read-only Cypher statement safe to
// run against the graph. It is deliberately strict: unknown or malformed input
// returns false.
func IsReadOnly(q string) bool {
	s, ok := sanitize(q)
	if !ok || s == "" {
		return false
	}
	// Single statement only: an embedded ';' with anything after it could smuggle
	// a second (write/IO) statement. A trailing ';' is fine.
	if i := strings.IndexByte(s, ';'); i >= 0 && strings.TrimSpace(s[i+1:]) != "" {
		return false
	}
	if !readStarters[strings.ToUpper(firstToken(s))] {
		return false
	}
	return !forbiddenRe.MatchString(s)
}

// Forbidden returns the first forbidden keyword in q, for actionable error
// messages ("keyword SET is not permitted"). It returns "" when q is rejected
// for a structural reason (bad start token, multiple statements) rather than a
// keyword — callers must treat any IsReadOnly==false as a rejection regardless.
func Forbidden(q string) string {
	s, _ := sanitize(q)
	if m := forbiddenRe.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// firstToken returns the leading run of ASCII letters (Cypher keywords are
// ASCII), which is enough to classify the opening clause.
func firstToken(s string) string {
	i := 0
	for i < len(s) && isLetter(s[i]) {
		i++
	}
	return s[:i]
}

func isLetter(b byte) bool { return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') }
