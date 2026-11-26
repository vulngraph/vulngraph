package db

// Native binary inserts have a fixed round-trip cost. Bound both rows and
// estimated payload so small records amortize that cost without collecting
// thousands of unusually wide records into a single driver block.
const (
	CHWriteMaxRows  = 2000
	CHWriteMaxBytes = 4 << 20
)

// CHWriteBatchEnd returns an exclusive end index. One oversized row is sent on
// its own: callers must always make progress without silently dropping it.
func CHWriteBatchEnd[T any](rows []T, start int, size func(T) int) int {
	end := min(start+CHWriteMaxRows, len(rows))
	bytes := 0
	for i := start; i < end; i++ {
		n := size(rows[i])
		if i > start && n > CHWriteMaxBytes-bytes {
			return i
		}
		bytes += n
	}
	return end
}

// CHMapBytes conservatively budgets maps including JSON escaping. Native Map
// columns need less, but using the same estimate keeps both forms bounded.
func CHMapBytes(m map[string]string) int {
	size := 2
	for k, v := range m {
		size += 32 + 6*(len(k)+len(v))
	}
	return size
}
