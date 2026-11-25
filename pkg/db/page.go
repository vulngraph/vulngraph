// Package db provides reusable, zero-dependency helpers for database access
// patterns across Vulngraph. All handlers and RPC implementations must use
// these types instead of rolling their own pagination or placeholder logic.
package db

// ListParams is the canonical pagination + search input for all list queries.
// Handlers parse it from JSON request query params and pass it down to
// repository layer functions.
type ListParams struct {
	Limit  int
	Offset int
	Search string
}

// Clamp applies safe defaults and bounds to a ListParams.
// maxLimit of 0 defaults to 1000.
//
//	params.Clamp(500)
func (p *ListParams) Clamp(maxLimit int) {
	if maxLimit <= 0 {
		maxLimit = 1000
	}
	if p.Limit <= 0 {
		p.Limit = 50
	}
	if p.Limit > maxLimit {
		p.Limit = maxLimit
	}
}

// Page[T] is the canonical paginated result for all list responses.
// Handlers shape Page[T] into the JSON response for list endpoints.
//
//	page := db.NewPage(assets, total, params.Limit, params.Offset)
type Page[T any] struct {
	Items   []T
	Total   int
	Limit   int
	Offset  int
	HasMore bool
}

// NewPage constructs a Page from a result slice and the original query params.
// total must be the full count of matching rows across all pages — used by
// the frontend to calculate page count.
//
// items is never nil in the returned Page (empty slice when no results).
func NewPage[T any](items []T, total, limit, offset int) Page[T] {
	if items == nil {
		items = []T{}
	}
	return Page[T]{
		Items:   items,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
		HasMore: offset+len(items) < total,
	}
}
