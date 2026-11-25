//go:build !linux

package ladybug

// TrimMemory is a no-op outside Linux. malloc_trim is a glibc extension; the
// production deployment target is Linux (see memtrim_linux.go for the real
// implementation and why it's needed), and darwin's allocator has no
// equivalent knob worth wiring up for local development.
func TrimMemory() {}
