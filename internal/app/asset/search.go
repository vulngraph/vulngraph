package asset

import "strings"

// assetSearchFields are the columns a free-text asset search matches. Every one
// is something an operator can plausibly be holding when they go looking for a
// host: a name from a dashboard, an id from an ARN, an address from a log line,
// an alert, or a packet capture. Deliberately more than just name+id, so an
// operator holding only an IP address can still find the asset.
var assetSearchFields = []string{"name", "id", "private_ip", "public_ip", "domain", "endpoint"}

// assetSearchCondition builds the free-text search predicate and its args. Pure,
// so the field coverage is table-testable without a database.
func assetSearchCondition(search string) (string, []any) {
	parts := make([]string, len(assetSearchFields))
	args := make([]any, len(assetSearchFields))
	like := "%" + search + "%"
	for i, col := range assetSearchFields {
		parts[i] = col + " ILIKE ?"
		args[i] = like
	}
	return "(" + strings.Join(parts, " OR ") + ")", args
}
