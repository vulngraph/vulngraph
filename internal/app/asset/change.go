package asset

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"time"
)

// FieldChange is one field-level difference between two versions of an asset —
// the unit of the per-field change log that powers the drift timeline.
type FieldChange struct {
	AssetID     string
	Field       string // "public_ip", "name", "tag:<k>", "meta:<k>"
	OldValue    string
	NewValue    string
	ConnectorID string
	ChangedAt   time.Time
}

// DiffFields returns the field-level changes between an old and new version of
// the same asset. Core fields are compared directly; tags and metadata are
// compared key-by-key (added, removed, or changed keys all produce a change).
// IDs are assumed equal — callers diff the same asset across two syncs.
func DiffFields(old, next Asset) []FieldChange {
	var out []FieldChange
	add := func(field, ov, nv string) {
		if ov != nv {
			out = append(out, FieldChange{
				AssetID: next.ID, Field: field,
				OldValue: capChangeValue(ov), NewValue: capChangeValue(nv),
			})
		}
	}

	add("name", old.Name, next.Name)
	add("region", old.Region, next.Region)
	add("endpoint", old.Endpoint, next.Endpoint)
	add("public_ip", old.PublicIP, next.PublicIP)
	add("private_ip", old.PrivateIP, next.PrivateIP)
	add("domain", old.Domain, next.Domain)

	for k, ov := range diffMaps(old.Tags, next.Tags) {
		add("tag:"+k, ov[0], ov[1])
	}
	for k, ov := range diffMaps(old.Metadata, next.Metadata) {
		add("meta:"+k, ov[0], ov[1])
	}

	// Stable order so a multi-field change always logs the same way.
	sort.Slice(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return out
}

// changeValueCap bounds a stored old/new value in the change log.
//
// The change log is a responder-facing timeline — one reader, selectChangeLog,
// behind the asset detail page, which renders the newest 100 rows — and it
// never feeds scoring or correlation. It does not need whole values: a field
// like meta:permissions can carry a large expanded-permission blob that
// differs on every observation, and nothing renders that as a timeline entry
// anyway. 1 KiB keeps values readable for a human scanning what changed,
// which is the whole job of this table.
const changeValueCap = 1024

// capChangeValue truncates an oversized change-log value, appending its true length
// and a digest of the full value.
//
// The digest is what keeps the log honest under truncation: two different oversized
// values must remain distinguishable to someone reading old_value against new_value,
// or a capped row would imply "nothing changed" when plenty did.
//
// DiffFields compares the UNCAPPED values and caps only on the way into storage. That
// is not because capping first would break detection — the digest happens to keep
// capped values distinct too — but because change detection should not depend on the
// collision-resistance of a truncated hash, and there is no reason to hash a value
// that did not change.
func capChangeValue(v string) string {
	if len(v) <= changeValueCap {
		return v
	}
	sum := sha256.Sum256([]byte(v))
	return fmt.Sprintf("%s…[%dB sha256:%x]", v[:changeValueCap], len(v), sum[:4])
}

// diffMaps returns the union of keys whose values differ between two maps,
// mapped to [oldValue, newValue]. A missing key reads as "".
func diffMaps(old, next map[string]string) map[string][2]string {
	changed := map[string][2]string{}
	for k, nv := range next {
		if ov, ok := old[k]; !ok || ov != nv {
			changed[k] = [2]string{old[k], nv}
		}
	}
	for k, ov := range old {
		if _, ok := next[k]; !ok {
			changed[k] = [2]string{ov, ""}
		}
	}
	return changed
}
