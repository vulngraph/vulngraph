//go:build darwin

package ladybug

/*
#include <malloc/malloc.h>

static size_t heap_in_use(void) {
	malloc_statistics_t s;
	malloc_zone_statistics(NULL, &s);
	return s.size_in_use;
}
*/
import "C"

// heapInUse reports the bytes the C allocator currently has handed out, so the
// binding's tests can detect native allocations that are never freed.
func heapInUse() uint64 { return uint64(C.heap_in_use()) }
