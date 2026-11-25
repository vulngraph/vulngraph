package graphstore

// fidelity_persist.go — durable memory for a PENDING fidelity-gate refusal
// (hardening, case 4).
//
// fidelityState lives only in process memory. A worker crash between "refused"
// and "confirmed on repeat" would wipe both the refused shape and the decline
// streak, restarting minRepeatAge's clock from zero — turning a would-be
// one-sweep-late publish into a wedge that never clears if crashes recur
// faster than the repeat window.
//
// The fix persists the small refusal record — counts and a timestamp, not the
// graph — next to the topology snapshot on the same PVC, so LoadFromSnapshot
// can restore it on the next boot. Deliberately NOT gated by SchemaVersion:
// unlike the graph itself, a refusal record has no DDL or loading-set
// dependency.
//
// This must NOT be confused with the graph baseline: seedBaseline/publishedShape
// and this file's rearm are independent halves of fidelityState, restored in
// different places for different reasons — see fidelity.go's seedBaseline doc.

import (
	"encoding/gob"
	"os"
	"path/filepath"
)

// refusalRecordPath derives the durable-refusal sidecar path from the topology
// snapshot path. Empty when snapshots are disabled (LADYBUG_SNAPSHOT_PATH unset) —
// nothing survives a pod restart in that mode anyway, so there is nothing worth
// persisting.
func refusalRecordPath(snapshotPath string) string {
	if snapshotPath == "" {
		return ""
	}
	return snapshotPath + ".fidelity_refusal"
}

// writeRefusalRecord serialises rec to path as gob, atomically (temp file + rename)
// — the same discipline WriteSnapshot uses, so a crash mid-write can never leave a
// corrupt record for the next boot to trip over. A no-op when path is empty.
func writeRefusalRecord(path string, rec refusalRecord) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := gob.NewEncoder(f).Encode(rec); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// readRefusalRecord loads a persisted refusal. Returns (_, false) when there is
// none — no file (nothing was pending), or a decode error (a binary/format change
// between the writing and reading binaries). Either way this fails OPEN into
// "nothing pending" rather than serving a record that might not mean what it used
// to: the cost of losing a real pending refusal here is the same bounded cost the
// gate already accepts everywhere else (one sweep, refused again, repeat clock
// restarts), never a false publish.
func readRefusalRecord(path string) (refusalRecord, bool) {
	if path == "" {
		return refusalRecord{}, false
	}
	f, err := os.Open(path)
	if err != nil {
		return refusalRecord{}, false
	}
	defer func() { _ = f.Close() }()
	var rec refusalRecord
	if err := gob.NewDecoder(f).Decode(&rec); err != nil {
		return refusalRecord{}, false
	}
	return rec, true
}

// clearRefusalRecord removes the durable refusal. Called whenever the gate actually
// publishes (a fresh decision, not the baseline-only seedBaseline), so a resolved
// refusal can never be replayed into a LATER, unrelated crash's rearm. A no-op when
// path is empty or the file does not exist.
func clearRefusalRecord(path string) {
	if path == "" {
		return
	}
	_ = os.Remove(path)
}
