package db

import "fmt"

// CHStringBatches bounds both item count and encoded SQL size. clickhouse-go
// substitutes '?' arguments into the query, and several reads repeat the IN
// list twice. A 32 KiB raw-string budget leaves room for escaping, both copies,
// separators and query text below ClickHouse's 256 KiB default.
func CHStringBatches(ids []string) ([][]string, error) {
	const maxItems, maxBytes = 500, 32 << 10
	seen := make(map[string]bool, len(ids))
	var batches [][]string
	var batch []string
	bytes := 0
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		if len(id) > maxBytes {
			return nil, fmt.Errorf("identifier exceeds bounded query size")
		}
		if len(batch) == maxItems || bytes+len(id) > maxBytes {
			batches = append(batches, batch)
			batch = nil
			bytes = 0
		}
		batch = append(batch, id)
		bytes += len(id)
	}
	if len(batch) > 0 {
		batches = append(batches, batch)
	}
	return batches, nil
}
