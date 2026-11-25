//go:build linux

package ladybug

/*
#include <malloc.h>

static size_t heap_in_use(void) {
	struct mallinfo2 m = mallinfo2();
	return m.uordblks + m.hblkhd;
}
*/
import "C"

// heapInUse reports the bytes the C allocator currently has handed out, so the
// binding's tests can detect native allocations that are never freed. It lives
// in a non-test file only because cgo cannot be used in _test.go files; the
// binding builds for linux and darwin only (the platforms LadybugDB ships).
func heapInUse() uint64 { return uint64(C.heap_in_use()) }
