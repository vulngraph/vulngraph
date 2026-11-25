# ADR 036 — Read-only Cypher trust model and a single validator

**Status:** accepted

## Context

Cypher against the Ladybug graph is exposed to three classes of caller, two of them
only partially trusted:

- **Authenticated operators**, directly, via `POST /api/graph/cypher` and saved
  queries (detection-as-code, ADR 027).
- **The LLM**, indirectly: `/api/chat` `run_cypher`, the MCP `run_cypher` /
  `graph_query` tools, and explore's NL→Cypher translation (`internal/reason`)
  all let a model emit Cypher that we then execute. Because the model reasons
  over attacker-influenceable data (resource names, tags, finding text), a
  prompt-injection payload can attempt to steer the emitted query.

The engine (upstream LadybugDB, ADR 095) has a grammar **larger than MATCH/RETURN**:
`LOAD FROM '<path|url>'` (server-side file / HTTP read), `INSTALL … FROM '<url>'`
+ `LOAD EXTENSION` (remote extension load → code execution in the worker pod),
`ATTACH` (outbound DB connection), `EXPORT/IMPORT DATABASE`, `USE`, `COPY`. None
of these contain a classic write keyword (`CREATE`/`SET`/`DELETE`/…).

The prior guard was a **keyword denylist** (`CREATE|MERGE|SET|DELETE|REMOVE|DROP|
COPY|ALTER|CALL … WRITE`), and it had been **copy-pasted into four packages**
(graphstore, explore, mcp, savedquery) that had already drifted apart (mcp's copy
had dropped the `CALL … WRITE` clause). A denylist of that shape passes every
statement in the list above — giving an authenticated user, or an injected model
output, SSRF / arbitrary file read / remote code load on the worker pod.

## Decision

1. **Allowlist, not denylist.** A query is read-only only if, after comments and
   string/backtick literals are stripped, it (a) is a single statement, (b) begins
   with `MATCH`, `OPTIONAL`, `WITH`, `UNWIND`, or `RETURN`, and (c) contains no
   write/DDL/IO keyword (`CREATE|MERGE|SET|DELETE|REMOVE|DROP|COPY|ALTER|LOAD|
   INSTALL|ATTACH|DETACH|EXPORT|IMPORT|USE|CALL|MACRO|CHECKPOINT|BEGIN|COMMIT|
   ROLLBACK`). Requiring a reading-clause *start* rejects every dangerous
   statement at the first token; stripping literals first means a resource named
   `'SET'` or `'load balancer'` cannot cause a false positive.

2. **One validator, one package.** The logic lives only in `internal/graphquery`
   (`IsReadOnly`, `Forbidden`) — a leaf package with no internal imports, so
   graphstore, explore, mcp and savedquery all depend on it without import cycles.
   The four divergent copies are deleted. New Cypher entry points MUST call
   `graphquery.IsReadOnly`; they must not re-implement it.

3. **Validate at the innermost chokepoint.** `graphstore.Service.RunCypherBudget`
   validates before touching the engine, so the serve pod's in-process Ladybug
   replica is covered as well as the worker RPC handler. Transport-level checks
   (HTTP handler, MCP tool) are defense-in-depth, not the only line.

This is a syntactic guard, not a parser. It is intentionally strict (unknown or
malformed input is rejected). It does not bound result size — that is the separate
node/edge budget — nor does it defend the LLM against injection; it bounds the
blast radius of a successful injection to read-only traversal.

## Consequences

- The file-read / extension-load / exfil surface described above is closed for
  every Cypher entry point in one place; `internal/graphquery/guard_test.go` locks
  the behaviour, including the engine's IO statements and comment/semicolon smuggling.
- A future legitimate need for `CALL { … }` read subqueries would require widening
  the allowlist deliberately (and testing it), rather than silently inheriting it.
- Prompt injection is explicitly *out of scope* for this ADR — the residual risk
  that a model acts on attacker-influenced text is tracked separately (see the
  agentic-pipeline ADRs and [ADR 042](042-prompt-injection-posture.md)).
