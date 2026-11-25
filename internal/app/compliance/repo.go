package compliance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/db"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// inventorySamples returns one representative live asset per distinct
// (provider, type, evidence) among the given types (%[1]s). evidence is the
// asset's metadata projected onto the evidence keys (%[2]s) and reduced to
// what evaluability reads (compliance.EvidenceSpec): a key's presence always,
// its value only where a check or ciem.Graded reads it — a value key
// (privilege_tier), a probe-set key on an asset missing another key of that
// set, and for an AWS security group's ingress/egress whether the rule list
// decodes. Any other value becomes ”, so assets differing only in a policy
// document or a rule list collapse into one sample; the whole reduced
// projection is the group key, so every member of a group answers
// evaluability identically and the result cannot change with read order.
//
// sgRulesDecodable is deliberately stricter than encoding/json: it collapses a
// rule list to '[]' only when every rule is an object of exactly the
// sgIngressRule fields with their JSON types, and leaves anything else raw for
// the Go decoder to judge. A raw value costs one extra sample; a wrongly
// collapsed one would read an unreadable rule list as observed.
//
// argMax per id, not FINAL: the read is filtered (type IN), and a filtered
// FINAL is the CLAUDE.md anti-pattern. The inner aggregates are aliased to
// fresh names and RE-PROJECTED as type/last_seen/metadata immediately before
// the WHERE, so InventoryReadCond's column references resolve against the
// latest version of each asset (the shadowing hazard documented at
// asset.EphemeralLivenessCond), and no aggregate is aliased to its own
// argument's name (ClickHouse's ILLEGAL_AGGREGATION). type is filtered again
// after argMax: an asset whose latest type is outside the set is not sampled.
//
// Placeholders bind in text order: value keys, probe providers, probe types,
// probe key sets, then the type set twice.
//
// Not a const: it concatenates asset.InventoryReadCond, a package-level var.
var inventorySamples = `SELECT provider, type,
		arrayMap(kv -> kv.1, evidence) AS evidence_keys,
		arrayMap(kv -> kv.2, evidence) AS evidence_values
	FROM (
		SELECT provider, type,
			arrayMap(kv -> (kv.1, multiIf(
				kv.1 = 'permissions', if(kv.2 = '', '', 'observed'),
				has(CAST(? AS Array(String)), kv.1), kv.2,
				arrayExists((pp, pt, pk) -> pp = provider AND (pt = '' OR pt = type) AND has(pk, kv.1) AND NOT hasAll(present, pk),
					CAST(? AS Array(String)), CAST(? AS Array(String)), CAST(? AS Array(Array(String)))), kv.2,
				provider = 'aws' AND type = 'security_group' AND kv.1 IN ('ingress', 'egress'), if(` + sgRulesDecodable + `, '[]', kv.2),
				'')), raw) AS evidence
		FROM (
			SELECT provider, type, raw, arrayMap(kv -> kv.1, raw) AS present
			FROM (
				SELECT provider, type,
					arraySort(arrayFilter(kv -> has([%[2]s], kv.1), JSONExtractKeysAndValues(metadata, 'String'))) AS raw
				FROM (
					SELECT asset_provider AS provider, asset_type AS type, latest_seen AS last_seen, asset_md AS metadata FROM (
						SELECT id,
							argMax(provider, synced_at) AS asset_provider,
							argMax(type, synced_at) AS asset_type,
							argMax(metadata, synced_at) AS asset_md,
							max(last_seen) AS latest_seen
						FROM assets
						WHERE type IN (%[1]s)
						GROUP BY id
					)
				)
				WHERE type IN (%[1]s) AND ` + asset.InventoryReadCond + `
			)
		)
	)
	GROUP BY provider, type, evidence`

// sgRulesDecodable holds when kv.2 is a rule list checks.decodeSGRules
// provably accepts: empty, or a JSON array of objects whose keys are distinct
// sgIngressRule fields (exact spelling — encoding/json also matches other
// casings, which this leaves raw), protocol a string, ports int32 integers,
// cidrs an array of strings; null is allowed wherever encoding/json skips it.
const sgRulesDecodable = `(kv.2 = '' OR (isValidJSON(kv.2) AND JSONType(kv.2) = 'Array' AND arrayAll(e ->
				JSONType(e) = 'Object'
				AND arrayAll(k -> k IN ('protocol', 'from_port', 'to_port', 'cidrs'), JSONExtractKeys(e))
				AND length(JSONExtractKeys(e)) = length(arrayDistinct(JSONExtractKeys(e)))
				AND JSONType(e, 'protocol') IN ('Null', 'String')
				AND (JSONType(e, 'from_port') = 'Null' OR (JSONType(e, 'from_port') = 'Int64' AND JSONExtractInt(e, 'from_port') BETWEEN -2147483648 AND 2147483647))
				AND (JSONType(e, 'to_port') = 'Null' OR (JSONType(e, 'to_port') = 'Int64' AND JSONExtractInt(e, 'to_port') BETWEEN -2147483648 AND 2147483647))
				AND (JSONType(e, 'cidrs') = 'Null' OR (JSONType(e, 'cidrs') = 'Array' AND arrayAll(c -> JSONType(c) IN ('Null', 'String'), JSONExtractArrayRaw(e, 'cidrs')))),
			JSONExtractArrayRaw(kv.2))))`

// inventoryTimeout bounds the sample read; it scans the gated assets table.
const inventoryTimeout = 30 * time.Second

// CHInventory reads inventory samples from ClickHouse.
type CHInventory struct{ ch *db.CH }

// NewCHInventory wires the inventory reader.
func NewCHInventory(ch *db.CH) *CHInventory { return &CHInventory{ch: ch} }

// Samples implements Inventory. spec.Keys must be non-empty: with no evidence
// keys nothing is known to make an asset evaluable.
func (r *CHInventory) Samples(ctx context.Context, spec EvidenceSpec) ([]asset.Asset, error) {
	if len(spec.Types) == 0 {
		return nil, nil
	}
	if len(spec.Keys) == 0 {
		return nil, errors.New("Samples: no evidence keys")
	}
	qCtx, cancel := context.WithTimeout(ctx, inventoryTimeout)
	defer cancel()
	typePH, typeArgs := dbutil.CHIn(spec.Types)
	keyPH, keyArgs := dbutil.CHIn(spec.Keys)
	probeProviders := make([]string, len(spec.Probes))
	probeTypes := make([]string, len(spec.Probes))
	probeKeys := make([][]string, len(spec.Probes))
	for i, p := range spec.Probes {
		probeProviders[i], probeTypes[i], probeKeys[i] = p.Provider, p.Type, p.Keys
	}
	valueKeys := append([]string{}, spec.ValueKeys...) // never nil: binds as []
	args := []any{valueKeys, probeProviders, probeTypes, probeKeys}
	args = append(append(append(args, keyArgs...), typeArgs...), typeArgs...)
	var out []asset.Asset
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var provider, typ string
			var ks, vs []string
			if err := rows.Scan(&provider, &typ, &ks, &vs); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			if len(ks) != len(vs) {
				return fmt.Errorf("scan (%s/%s): %d evidence keys, %d values", provider, typ, len(ks), len(vs))
			}
			a := asset.Asset{Provider: asset.Provider(provider), Type: typ, Metadata: make(map[string]string, len(ks))}
			for i, k := range ks {
				a.Metadata[k] = vs[i]
			}
			out = append(out, a)
		}
		return rows.Err()
	}, fmt.Sprintf(inventorySamples, typePH, keyPH), args...)
	if err != nil {
		return nil, fmt.Errorf("Samples: %w", err)
	}
	return out, nil
}
