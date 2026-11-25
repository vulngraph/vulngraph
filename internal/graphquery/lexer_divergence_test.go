package graphquery

import "testing"

func sanitized(q string) string {
	s, ok := sanitize(q)
	if !ok {
		return "<rejected>"
	}
	return s
}

// Every query here was (or would be) lexed differently by the guard and by
// Ladybug's Cypher.g4 lexer, so the guard saw a comment/literal where the engine
// saw code. The first two executed writes against real liblbug before the fix.
func TestIsReadOnly_LexerDivergenceCannotHideAWrite(t *testing.T) {
	bypasses := []struct{ name, query string }{
		{"block comment closed late by the grammar", `MATCH (n) /* **/ ' */ DETACH DELETE n //'`},
		{"second statement behind a late-closing comment", `RETURN 1 /* **/ ' */; CREATE (x:Evil) //'`},
		{"triple star before slash", `MATCH (n) /* ***/ " */ DETACH DELETE n //"`},
		{"late close with backtick", "MATCH (n) /* **/ ` */ SET n.x = 1 //`"},
		{"plain block comment", `MATCH (n) /* c */ RETURN n`},
		{"unterminated block comment", `MATCH (n) RETURN n /* DETACH DELETE n`},
		{"line comment ended by lone CR", "MATCH (n) RETURN n // x\rDETACH DELETE n"},
		{"lone CR hides second statement", "RETURN 1 // x\r; CREATE (m:Evil)"},
		{"unterminated string", `MATCH (n) RETURN n '; DETACH DELETE n`},
		{"unterminated backtick", "MATCH (n) RETURN n `; DETACH DELETE n"},
		{"invalid escape in string", `MATCH (n) WHERE n.x = 'a\q' RETURN n`},
		{"short unicode escape", `MATCH (n) WHERE n.x = '\u12' RETURN n`},
		{"trailing backslash", `MATCH (n) WHERE n.x = 'a\`},
	}
	for _, tt := range bypasses {
		t.Run(tt.name, func(t *testing.T) {
			if IsReadOnly(tt.query) {
				t.Fatalf("IsReadOnly accepted: %q\nsanitized=%q", tt.query, sanitized(tt.query))
			}
		})
	}
}

func TestIsReadOnly_LexerSafeReadsStillPass(t *testing.T) {
	ok := []string{
		"MATCH (n) // trailing comment\nRETURN n",
		"MATCH (n) // CRLF comment\r\nRETURN n",
		"MATCH (n) RETURN n // comment at EOF",
		`MATCH (n) WHERE n.url = 'https://x/*' RETURN n`,
		`MATCH (n) WHERE n.x = 'tab\there é \U0001F600 \\ \" \''  RETURN n`,
		"MATCH (n) WHERE n.x = \"a // not a comment\" RETURN n",
	}
	for _, q := range ok {
		t.Run(q, func(t *testing.T) {
			if !IsReadOnly(q) {
				t.Fatalf("IsReadOnly rejected a legitimate read: %q\nsanitized=%q", q, sanitized(q))
			}
		})
	}
}

// RE2's \b treats digits as word characters, so `1SET` had no boundary before
// SET; the engine lexes it as the integer 1 then SET, and the write ran. Every
// forbidden keyword glued to a preceding digit must still be rejected, and
// Forbidden must name the keyword, not the digit.
func TestIsReadOnly_KeywordGluedToDigitIsRejected(t *testing.T) {
	bypasses := []struct{ query, keyword string }{
		{"MATCH (n:Asset) WHERE 1=1SET n.risk_score=0 RETURN n", "SET"},
		{"MATCH ()-[r]->() WHERE 1=1DELETE r", "DELETE"},
		{"MATCH (n) WHERE 1=1DETACH DELETE n", "DETACH"},
		{"MATCH (n) WITH n LIMIT 1CREATE (:Asset {id:'x'})", "CREATE"},
		{"WITH 1 AS x LIMIT 1LOAD FROM '/path' RETURN *", "LOAD"},
		{"MATCH (n) WITH n LIMIT 1CALL show_tables() RETURN *", "CALL"},
		{"MATCH (n) WITH n LIMIT 1MERGE (:Asset {id:'x'})", "MERGE"},
		{"MATCH (n) WHERE 1=1REMOVE n.x", "REMOVE"},
		{"MATCH (n) WITH n LIMIT 1DROP TABLE Asset", "DROP"},
		{"MATCH (n) WITH n LIMIT 1COPY Asset FROM '/x.csv'", "COPY"},
		{"MATCH (n) WITH n LIMIT 1INSTALL httpfs", "INSTALL"},
		{"MATCH (n) WITH n LIMIT 1ATTACH 'x' AS y", "ATTACH"},
		{"MATCH (n) WITH n LIMIT 1EXPORT DATABASE '/tmp/d'", "EXPORT"},
		{"MATCH (n) WHERE n.x = 1.5SET n.y = 1", "SET"},
		{"MATCH (n) WHERE 1=1set n.x=0 RETURN n", "set"},
	}
	for _, tt := range bypasses {
		t.Run(tt.query, func(t *testing.T) {
			if IsReadOnly(tt.query) {
				t.Fatalf("IsReadOnly accepted: %q", tt.query)
			}
			if kw := Forbidden(tt.query); kw != tt.keyword {
				t.Fatalf("Forbidden(%q) = %q, want %q", tt.query, kw, tt.keyword)
			}
		})
	}
}

// The tightened boundary must not reject keywords that are only a suffix or
// prefix of an identifier the engine lexes as one token.
func TestIsReadOnly_KeywordInsideIdentifierStillPasses(t *testing.T) {
	ok := []string{
		"MATCH (n) WHERE n.offset > 1 RETURN n",
		"MATCH (n) WHERE n.asset_id = 'x' RETURN n.reset_at",
		"MATCH (n) RETURN n.created_at, n.user, n.callback_url",
		"MATCH (n) WHERE n._set = 1 RETURN n",
		"MATCH (n) RETURN n.set1",
	}
	for _, q := range ok {
		t.Run(q, func(t *testing.T) {
			if !IsReadOnly(q) {
				t.Fatalf("IsReadOnly rejected a legitimate read: %q", q)
			}
		})
	}
}
