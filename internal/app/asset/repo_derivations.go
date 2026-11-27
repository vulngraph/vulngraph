package asset

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/vulngraph/vulngraph/internal/db"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

const beginDerivedUpdate = `SELECT now64(9)`
const insertFindingRisk = `INSERT INTO asset_finding_risk (generation,digest,id,risk_score)`
const commitFindingRisk = `INSERT INTO asset_finding_risk (generation,digest,id,risk_score,pinned)`
const publishFindingRisk = `INSERT INTO asset_risk_publications (generation,digest)`
const pinFindingRisk = `INSERT INTO asset_finding_risk (generation,digest,id,risk_score,pinned)
 SELECT generation,digest,id,max(risk_score),toUInt8(1) FROM asset_finding_risk
 WHERE generation=parseDateTime64BestEffort(?,9) AND digest=? AND id!='' GROUP BY generation,digest,id`
const pinnedFindingRiskCount = `SELECT count() FROM (
 SELECT id FROM asset_finding_risk WHERE generation=parseDateTime64BestEffort(?,9) AND digest=? AND id!='' GROUP BY id HAVING max(pinned)=1)`
const retainedRiskGenerations = `SELECT DISTINCT generation,digest FROM asset_finding_risk WHERE id='' AND pinned=1 ORDER BY generation DESC,digest DESC LIMIT 2`
const retireRiskPublications = `INSERT INTO asset_risk_publications (generation,digest,updated_at,retired,retired_at)
 SELECT generation,digest,now64(9),toUInt8(1),now64(9) FROM asset_finding_risk
 WHERE id='' AND pinned=1 AND (generation,digest)<(parseDateTime64BestEffort(?,9),?)
 AND (generation,digest) NOT IN (SELECT generation,digest FROM asset_risk_publications
 GROUP BY generation,digest HAVING argMax(retired,updated_at)=1) GROUP BY generation,digest`
const pruneFindingRisk = `DELETE FROM asset_finding_risk
 WHERE (generation,digest) IN (
  SELECT generation,digest FROM asset_risk_publications GROUP BY generation,digest
  HAVING argMax(retired,updated_at)=1 AND argMax(retired_at,updated_at)<now64(9)-INTERVAL 1 HOUR
 ) OR (generation<now64(9)-INTERVAL 1 DAY AND (generation,digest) NOT IN
  (SELECT DISTINCT generation,digest FROM asset_finding_risk WHERE id='' AND pinned=1))
 SETTINGS lightweight_deletes_sync=1`
const pruneRiskPublications = `DELETE FROM asset_risk_publications
 WHERE (generation,digest) IN (
  SELECT generation,digest FROM asset_risk_publications GROUP BY generation,digest
  HAVING argMax(retired,updated_at)=1 AND argMax(retired_at,updated_at)<now64(9)-INTERVAL 1 HOUR
 ) SETTINGS lightweight_deletes_sync=1`
const insertAnnotations = `INSERT INTO asset_annotations (source,id,observed_at,input_key,patch)`

func (r *CHRepo) BeginDerivedUpdate(ctx context.Context) (time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var version time.Time
	err := r.ch.Select(ctx, func(rows driver.Rows) error {
		if !rows.Next() {
			return fmt.Errorf("missing derivation version")
		}
		return rows.Scan(&version)
	}, beginDerivedUpdate)
	if err != nil {
		return time.Time{}, fmt.Errorf("BeginDerivedUpdate: %w", err)
	}
	return version, nil
}

func (r *CHRepo) PublishFindingRisk(ctx context.Context, version time.Time, scores map[string]uint8) error {
	if version.IsZero() {
		return fmt.Errorf("PublishFindingRisk: missing source version")
	}
	if _, invalid := scores[""]; invalid {
		return fmt.Errorf("PublishFindingRisk: empty resource identity is reserved for commit markers")
	}
	now, err := r.BeginDerivedUpdate(ctx)
	if err != nil {
		return err
	}
	if version.After(now) || version.Before(now.Add(-time.Hour)) {
		return fmt.Errorf("PublishFindingRisk: expired or future source version; recompute the snapshot")
	}
	ctx, cancel := db.WithWriteBudget(ctx, assetWriteBudget)
	defer cancel()
	if err := r.pruneFindingRisk(ctx); err != nil {
		return err
	}
	type scoreRow struct {
		ID    string
		Score uint8
	}
	rows := make([]scoreRow, 0, len(scores))
	for id, score := range scores {
		rows = append(rows, scoreRow{id, score})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	hash := sha256.New()
	for _, row := range rows {
		if _, err := fmt.Fprintf(hash, "%d:%s:%d\n", len(row.ID), row.ID, row.Score); err != nil {
			return fmt.Errorf("PublishFindingRisk: digest: %w", err)
		}
	}
	digest := fmt.Sprintf("%x", hash.Sum(nil))
	for start := 0; start < len(rows); {
		end := dbutil.CHWriteBatchEnd(rows, start, func(row scoreRow) int { return len(row.ID) + 96 })
		if err := r.ch.Batch(ctx, insertFindingRisk, func(b driver.Batch) error {
			for _, row := range rows[start:end] {
				if err := b.Append(version, digest, row.ID, row.Score); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("PublishFindingRisk: rows: %w", err)
		}
		start = end
	}
	if err := r.ch.Exec(ctx, pinFindingRisk, version.UTC().Format(time.RFC3339Nano), digest); err != nil {
		return fmt.Errorf("PublishFindingRisk: pin complete rows: %w", err)
	}
	var pinned uint64
	if err := r.ch.Select(ctx, func(rows driver.Rows) error {
		if !rows.Next() {
			return fmt.Errorf("missing pinned row count")
		}
		return rows.Scan(&pinned)
	}, pinnedFindingRiskCount, version.UTC().Format(time.RFC3339Nano), digest); err != nil {
		return fmt.Errorf("PublishFindingRisk: verify complete data: %w", err)
	}
	if pinned != uint64(len(scores)) {
		return fmt.Errorf("PublishFindingRisk: pinned %d rows, expected %d", pinned, len(scores))
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("PublishFindingRisk: before publication: %w", err)
	}
	// A query-wide shared snapshot of this one table contains either the
	// previous marker or this marker and its already-pinned complete rows.
	// A marker in another table can be newer than the data snapshot.
	if err := r.ch.Batch(ctx, commitFindingRisk, func(b driver.Batch) error {
		return b.Append(version, digest, "", uint8(0), uint8(1))
	}); err != nil {
		return fmt.Errorf("PublishFindingRisk: commit marker: %w", err)
	}
	if err := r.ch.Batch(ctx, publishFindingRisk, func(b driver.Batch) error { return b.Append(version, digest) }); err != nil {
		return fmt.Errorf("PublishFindingRisk: cleanup ledger: %w", err)
	}
	return r.pruneFindingRisk(ctx)
}

func (r *CHRepo) WriteAnnotations(ctx context.Context, version time.Time, annotations []Annotation) error {
	if len(annotations) == 0 {
		return nil
	}
	if version.IsZero() {
		return fmt.Errorf("WriteAnnotations: missing source version")
	}
	patches := make([]string, len(annotations))
	for i, a := range annotations {
		if a.Source != ManifestDriftSource || len(a.Metadata) != 1 {
			return fmt.Errorf("WriteAnnotations: unsupported producer or keys")
		}
		value, ok := a.Metadata["drift"]
		if !ok {
			return fmt.Errorf("WriteAnnotations: producer does not own metadata key")
		}
		var patch any
		if value != "" {
			patch = value
		}
		b, err := json.Marshal(map[string]any{"drift": patch})
		if err != nil {
			return fmt.Errorf("WriteAnnotations: encode: %w", err)
		}
		patches[i] = string(b)
	}
	ctx, cancel := db.WithWriteBudget(ctx, assetWriteBudget)
	defer cancel()
	for start := 0; start < len(annotations); {
		end := dbutil.CHWriteBatchEnd(annotations, start, func(a Annotation) int {
			n := len(a.ID) + len(a.InputKey) + len(a.Source) + 32
			for k, v := range a.Metadata {
				n += 6*(len(k)+len(v)) + 8
			}
			return n
		})
		if err := r.ch.Batch(ctx, insertAnnotations, func(b driver.Batch) error {
			for i := start; i < end; i++ {
				a := annotations[i]
				if err := b.Append(a.Source, a.ID, version, a.InputKey, patches[i]); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("WriteAnnotations: %w", err)
		}
		start = end
	}
	return nil
}

// Keep the two newest complete generations and at most a day of abandoned
// staging, plus a one-hour grace for readers of recently replaced generations
// (the affected asset/correlation readers have at most five-minute timeouts).
// The active generation is never eligible for TTL removal. Cleanup
// compares ordered keys, so a late publisher cannot discard a newer snapshot.
func (r *CHRepo) pruneFindingRisk(ctx context.Context) error {
	type key struct {
		at     time.Time
		digest string
	}
	var keep []key
	if err := r.ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var k key
			if err := rows.Scan(&k.at, &k.digest); err != nil {
				return err
			}
			keep = append(keep, k)
		}
		return rows.Err()
	}, retainedRiskGenerations); err != nil {
		return fmt.Errorf("prune finding risk: generations: %w", err)
	}
	floor := key{at: time.Unix(0, 0)}
	if len(keep) > 0 {
		floor = keep[len(keep)-1]
	}
	if err := r.ch.Exec(ctx, retireRiskPublications, floor.at.UTC().Format(time.RFC3339Nano), floor.digest); err != nil {
		return fmt.Errorf("prune finding risk: markers: %w", err)
	}
	if err := r.ch.Exec(ctx, pruneFindingRisk); err != nil {
		return fmt.Errorf("prune finding risk: data: %w", err)
	}
	// Delete every marker version after the data. TTL can remove a newer
	// retired version before an older active version merges away; retaining
	// that older row would make abandoned data look published indefinitely.
	if err := r.ch.Exec(ctx, pruneRiskPublications); err != nil {
		return fmt.Errorf("prune finding risk: publication versions: %w", err)
	}
	return nil
}
