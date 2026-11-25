package asset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"sort"
	"strings"
	"time"
)

// hashVersion prefixes the content hash input so future field additions can
// bump the version (invalidating all stored fingerprints) without a migration.
const hashVersion = "asset:v1"

// ContentHash computes a stable 8-byte (16 hex char) SHA-256 over an asset's
// semantic fields. Excludes operational timestamps (DiscoveredAt, LastSeen) and
// score outputs (RiskScore IS included since CIEM scores it based on IAM policy
// analysis — it reflects the asset's security posture, not enrichment state).
//
// The canonical form: fields are newline-separated; map keys are sorted before
// serialisation so map insertion order never affects the hash.
func ContentHash(a Asset) string {
	var b strings.Builder
	b.WriteString(hashVersion)
	b.WriteByte('\n')
	b.WriteString(a.ID)
	b.WriteByte('\n')
	b.WriteString(a.Name)
	b.WriteByte('\n')
	b.WriteString(a.Type)
	b.WriteByte('\n')
	b.WriteString(string(a.Provider))
	b.WriteByte('\n')
	b.WriteString(a.Region)
	b.WriteByte('\n')
	b.WriteString(a.AccountID)
	b.WriteByte('\n')
	b.WriteString(a.Endpoint)
	b.WriteByte('\n')
	b.WriteString(a.PublicIP)
	b.WriteByte('\n')
	b.WriteString(a.PrivateIP)
	b.WriteByte('\n')
	b.WriteString(a.Domain)
	b.WriteByte('\n')
	writeMap(&b, a.Tags)
	writeMap(&b, hashMetadata(a.Metadata))
	fmt.Fprintf(&b, "score=%d\n", a.RiskScore)

	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8]) // 64-bit — collision probability negligible at ~100k-asset scale
}

// Organization observations are refreshed even on unchanged sweeps. Their
// collection time controls evidence freshness, not semantic change detection.
// CIEM evaluates freshness before the sync fingerprint; its resulting tier and
// coverage remain hashed. Keep the original timestamp in the stored metadata.
func hashMetadata(metadata map[string]string) map[string]string {
	var normalized map[string]string
	for _, key := range []string{"organization_policies", "organization_membership"} {
		raw := metadata[key]
		if raw == "" {
			continue
		}
		var object map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &object) != nil || object == nil {
			continue
		}
		var observed time.Time
		if json.Unmarshal(object["observed_at"], &observed) != nil || observed.IsZero() {
			continue
		}
		object["observed_at"] = json.RawMessage(`"observed"`)
		encoded, err := json.Marshal(object)
		if err != nil {
			continue
		}
		if normalized == nil {
			normalized = maps.Clone(metadata)
		}
		normalized[key] = string(encoded)
	}
	if normalized != nil {
		return normalized
	}
	return metadata
}

// ConnectorFingerprint computes a combined fingerprint over all assets a
// connector returned. If this matches the stored connector.SyncFingerprint, no
// asset changed since the last sweep — skip ingest + enrich entirely.
func ConnectorFingerprint(assets []Asset) string {
	if len(assets) == 0 {
		return ""
	}
	// Sort by id so the fingerprint is insertion-order independent.
	pairs := make([]string, len(assets))
	for i, a := range assets {
		pairs[i] = a.ID + ":" + ContentHash(a)
	}
	sort.Strings(pairs)
	sum := sha256.Sum256([]byte(strings.Join(pairs, "\n")))
	return hex.EncodeToString(sum[:8])
}

// writeMap appends sorted key=value lines from m to b.
func writeMap(b *strings.Builder, m map[string]string) {
	if len(m) == 0 {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
		b.WriteByte('\n')
	}
}
