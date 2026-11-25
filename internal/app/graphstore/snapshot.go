package graphstore

// snapshot.go — fast graph startup via a serialised topology cache on the PVC.
//
// Ladybug's native OpenDatabase(path) requires mmap(MAP_SHARED), which some
// container runtimes' default seccomp profiles block. This file provides an alternative: after
// each full topology rebuild, write the asset+edge data to a gob+gzip file on
// the PVC via regular os.Open/os.Create (no mmap, so unaffected by the seccomp
// block). On startup, load from the snapshot instead of ClickHouse if the
// schema version matches.
//
// The snapshot does NOT replace ClickHouse as the source of truth — it is a
// disposable cache. Delete it and the next correlate sweep rebuilds from CH.

import (
	"compress/gzip"
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// GraphSnapshot is the on-disk representation of a topology snapshot.
// Only topology (assets + edges) is stored — signals are re-queried from CH
// on load because they change frequently and are cheap to read.
type GraphSnapshot struct {
	SchemaVersion string
	// TopoDigest is the Topo half of the load digest the writing sync computed
	// over exactly these assets/edges. Persisting it lets a worker restart seed
	// the no-op-rebuild gate from disk instead of starting cold every time.
	// LoadFromSnapshot re-verifies it against a fresh recompute before seeding
	// the gate, so a digest-algorithm change between binaries can only fail open
	// into a rebuild. Zero means "no baseline" (old snapshot, or the writer's
	// digest failed).
	TopoDigest uint64
	BuiltAt    time.Time
	Assets     []asset.Asset
	Edges      []asset.Edge
	// ReachComplete records whether the writing build fetched every
	// attacker-movement edge type and all assets untruncated; a replay must degrade
	// internet_hops to ReachUnknown exactly like the original build did.
	ReachComplete bool
	// EdgeFetchComplete is the writing build's asset.EdgeSyncResult.FetchComplete.
	// Not implied by publication: a cold pod can publish a partial fetch.
	EdgeFetchComplete bool
	// AssetFetchComplete is the writing build's !asset.AssetSyncResult.Truncated, for
	// the same reason.
	AssetFetchComplete bool
}

// snapshotMaxAge is the oldest snapshot LoadFromSnapshot will warm-start from.
// Older than this, a cold ClickHouse rebuild is preferred over serving a stale
// topology that LastBuiltAt would (correctly) report as days old.
const snapshotMaxAge = 24 * time.Hour

// WriteSnapshot serialises snap to path as gob+gzip. Writes to a temp file in
// the same directory then renames atomically so a partial write never corrupts.
func WriteSnapshot(path string, snap GraphSnapshot) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("WriteSnapshot: mkdir: %w", err)
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("WriteSnapshot: create: %w", err)
	}
	gz := gzip.NewWriter(f)
	if err := gob.NewEncoder(gz).Encode(snap); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("WriteSnapshot: encode: %w", err)
	}
	if err := gz.Close(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("WriteSnapshot: gzip close: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("WriteSnapshot: close: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("WriteSnapshot: rename: %w", err)
	}
	return nil
}

// ReadSnapshot deserialises a snapshot from path. Returns ErrSnapshotMissing
// when the file doesn't exist (not an error — just means cold start from CH).
// Returns ErrSnapshotStale when the schema version doesn't match.
func ReadSnapshot(path, schemaVersion string) (GraphSnapshot, error) {
	snap, err := decodeSnapshotFile(path)
	if err != nil {
		return GraphSnapshot{}, err
	}
	if snap.SchemaVersion != schemaVersion {
		return GraphSnapshot{}, ErrSnapshotStale
	}
	return snap, nil
}

// ReadSnapshotShapeAnyVersion decodes the on-disk snapshot's asset/edge counts
// WITHOUT checking SchemaVersion, for exactly one purpose: arming the fidelity
// gate's Layer-2 baseline (fidelity.go, case 1) across a version bump. It must
// never seed the served GRAPH — that still goes through ReadSnapshot, whose
// version check stands: there is no in-place Ladybug migration.
//
// A SchemaVersion bump gates Ladybug's DDL or loading set, not the ClickHouse row
// counts Layer 2 compares, so the previous build's shape is usually still a
// valid comparison point straight through the bump; using it costs at most one
// late-published sweep under acceptOnRepeat, never a false publish.
//
// Returns (_, false) on anything that stops it being a trustworthy shape: no
// file, or a decode error (a gob-incompatible struct change between
// binaries).
func ReadSnapshotShapeAnyVersion(path string) (fidelityShape, bool) {
	snap, err := decodeSnapshotFile(path)
	if err != nil {
		return fidelityShape{}, false
	}
	return shapeOf(snap.Assets, snap.Edges), true
}

// decodeSnapshotFile does the gzip+gob decode shared by ReadSnapshot (which then
// checks SchemaVersion) and ReadSnapshotShapeAnyVersion (which deliberately does not).
func decodeSnapshotFile(path string) (GraphSnapshot, error) {
	if path == "" {
		return GraphSnapshot{}, ErrSnapshotMissing
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return GraphSnapshot{}, ErrSnapshotMissing
		}
		return GraphSnapshot{}, fmt.Errorf("decodeSnapshotFile: open: %w", err)
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return GraphSnapshot{}, fmt.Errorf("decodeSnapshotFile: gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	var snap GraphSnapshot
	if err := gob.NewDecoder(gz).Decode(&snap); err != nil {
		return GraphSnapshot{}, fmt.Errorf("decodeSnapshotFile: decode: %w", err)
	}
	return snap, nil
}
