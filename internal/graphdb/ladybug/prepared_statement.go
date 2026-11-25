package ladybug

// #include "lbug.h"
// #include <stdlib.h>
import "C"

// PreparedStatement represents a prepared statement in Ladybug, which can be
// used to execute a query with parameters.
// PreparedStatement is returned by the `Prepare` method of Connection.
type PreparedStatement struct {
	cPreparedStatement C.lbug_prepared_statement
	connection         *Connection
	isClosed           bool
}

// Close closes the PreparedStatement. Calling this method is optional.
// The PreparedStatement will be closed automatically when it is garbage collected.
func (stmt *PreparedStatement) Close() {
	if stmt.isClosed {
		return
	}
	C.lbug_prepared_statement_destroy(&stmt.cPreparedStatement)
	stmt.isClosed = true
}

// IsReadOnly reports whether the engine planned the statement as read-only,
// i.e. executing it cannot modify the database. It is the engine's own verdict
// from its parser and binder, so it cannot diverge from how the query runs.
// It covers database writes only: LOAD FROM, EXPORT DATABASE and CALL are
// read-only to the engine, so it complements a statement allowlist rather than
// replacing one.
func (stmt *PreparedStatement) IsReadOnly() bool {
	return bool(C.lbug_prepared_statement_is_read_only(&stmt.cPreparedStatement))
}
