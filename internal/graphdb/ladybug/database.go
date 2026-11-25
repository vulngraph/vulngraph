// Package ladybug provides a Go interface to the Ladybug graph engine.
// The package is a wrapper around the C API of the Ladybug graph engine.
package ladybug

// #include "lbug.h"
// #include <stdlib.h>
import "C"
import (
	"fmt"
	"os"
	"runtime"
	"unsafe"
)

// SystemConfig represents the configuration of the Ladybug graph engine database system.
// BufferPoolSize is the size of the buffer pool in bytes.
// MaxNumThreads is the maximum number of threads that can be used by the database system.
// EnableCompression is a boolean flag to enable or disable compression.
// ReadOnly is a boolean flag to open the database in read-only mode.
// MaxDbSize is the maximum size of the database in bytes.
type SystemConfig struct {
	BufferPoolSize    uint64
	MaxNumThreads     uint64
	EnableCompression bool
	ReadOnly          bool
	MaxDbSize         uint64
}

// DefaultSystemConfig returns the default system configuration.
// The default system configuration is as follows:
// BufferPoolSize: 80% of the total system memory.
// MaxNumThreads: Number of CPU cores.
// EnableCompression: true.
// ReadOnly: false.
// MaxDbSize: 0 (unlimited).
func DefaultSystemConfig() SystemConfig {
	cSystemConfig := C.lbug_default_system_config()
	return SystemConfig{
		BufferPoolSize:    uint64(cSystemConfig.buffer_pool_size),
		MaxNumThreads:     uint64(cSystemConfig.max_num_threads),
		EnableCompression: bool(cSystemConfig.enable_compression),
		ReadOnly:          bool(cSystemConfig.read_only),
		MaxDbSize:         uint64(cSystemConfig.max_db_size),
	}
}

// toC converts the SystemConfig Go struct to the C struct.
func (config SystemConfig) toC() C.lbug_system_config {
	cSystemConfig := C.lbug_default_system_config()
	cSystemConfig.buffer_pool_size = C.uint64_t(config.BufferPoolSize)
	cSystemConfig.max_num_threads = C.uint64_t(config.MaxNumThreads)
	cSystemConfig.enable_compression = C.bool(config.EnableCompression)
	cSystemConfig.read_only = C.bool(config.ReadOnly)
	cSystemConfig.max_db_size = C.uint64_t(config.MaxDbSize)
	return cSystemConfig
}

// Database represents a Ladybug graph engine database instance.
type Database struct {
	cDatabase C.lbug_database
	isClosed  bool
}

// OpenDatabase opens a Ladybug graph engine database at the given path with the given system configuration.
func OpenDatabase(path string, systemConfig SystemConfig) (*Database, error) {
	db := &Database{}
	runtime.SetFinalizer(db, func(db *Database) {
		db.Close()
	})
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	cSystemConfig := systemConfig.toC()
	status := C.lbug_database_init(cPath, cSystemConfig, &db.cDatabase)
	if status != C.LbugSuccess {
		// Collect filesystem context to disambiguate permission vs other failures.
		detail := pathDiag(path)
		return db, fmt.Errorf("failed to open database with status %d: %s", status, detail)
	}
	return db, nil
}

// OpenInMemoryDatabase opens a Ladybug graph engine database in in-memory mode with the given system configuration.
func OpenInMemoryDatabase(systemConfig SystemConfig) (*Database, error) {
	return OpenDatabase(":memory:", systemConfig)
}

// pathDiag returns a brief string with stat info for path, used to surface
// permission failures when ladybug_database_init returns a non-success status.
func pathDiag(path string) string {
	if path == ":memory:" {
		return "in-memory"
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Sprintf("stat(%s) failed: %v", path, err)
	}
	// Also probe write access directly.
	testFile := path + "/.ladybug_write_probe"
	f, werr := os.OpenFile(testFile, os.O_CREATE|os.O_WRONLY, 0600)
	if f != nil {
		_ = f.Close()
		_ = os.Remove(testFile)
	}
	return fmt.Sprintf("path=%s mode=%v writable=%v", path, info.Mode(), werr == nil)
}

// Close closes the database. Calling this method is optional.
// The database will be closed automatically when it is garbage collected.
//
// Every Close is followed by TrimMemory: glibc only unmaps a non-main arena's
// heap when its top chunk is free, which ladybug_database_destroy's allocation
// pattern rarely satisfies, so freed native memory stays resident and ratchets
// RSS up across repeated open/close cycles (measured directly). This has to
// live here rather than in a caller — OpenDatabase's
// GC finalizer and driver.go's connector.Close() both call this method
// directly, bypassing any wrapper a caller might trim through.
func (db *Database) Close() {
	if db.isClosed {
		return
	}
	C.lbug_database_destroy(&db.cDatabase)
	db.isClosed = true
	TrimMemory()
}
