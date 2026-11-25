//go:build linux

package ladybug

/*
#include <malloc.h>
*/
import "C"

// TrimMemory asks glibc to release freed-but-retained heap segments back to
// the OS (malloc_trim(0)). Every Ladybug rebuild opens a brand-new native
// Database side-by-side with the live one and destroys the old one on swap
// (SyncFromSources, internal/app/graphstore/service_sync.go) — glibc's arena
// allocator only unmaps a non-main arena's heap when its top chunk is free,
// which the native engine's allocation pattern rarely satisfies, so freed
// C++ memory sits resident and each rebuild ratchets RSS higher: this shows
// up as a per-arena plateau rather than an unbounded leak, but
// MALLOC_ARENA_MAX=2 alone does not release it. Calling this right after
// Database.Close() forces glibc to give that memory back instead of holding
// it for a future allocation that may never come in this arena again.
//
// malloc_trim is a glibc extension; this file is Linux-only (the prod
// deployment target) via the build tag. See memtrim_other.go for the no-op
// used on darwin/other platforms during local development.
func TrimMemory() {
	C.malloc_trim(0)
}
