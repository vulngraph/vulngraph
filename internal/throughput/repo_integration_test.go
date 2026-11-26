//go:build integration

package throughput

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/vulngraph/vulngraph/internal/db"
)

func (p profile) coreNodes() uint64 { return p.Workloads + p.Images + 3*p.Groups }
func (p profile) hotPackages() uint64 {
	return min(p.Packages/10, p.Memberships/p.Images/4)
}

const seedAssets = `INSERT INTO assets
 (id,name,type,provider,metadata,risk_score,discovered_at,last_seen,synced_at)
 SELECT concat(?,toString(number),?),concat('bench-',toString(number)),?,
 'kubernetes','{}',if(? AND number%10=0,80,0),toDateTime(?),toDateTime(?),toDateTime(?)
 FROM numbers(?)`

const seedCoreEdges = `INSERT INTO graph_edges
 (src_id,src_type,dst_id,dst_type,edge_type,properties,synced_at)
 SELECT concat('pod-',toString(number)),'k8s_pod',concat('image-',toString(number%?)),
 'container_image','runs_image','{}',toDateTime(?) FROM numbers(?)
 UNION ALL SELECT concat('service-',toString(intDiv(number,10))),'k8s_service',
 concat('pod-',toString(number)),'k8s_pod','targets','{}',toDateTime(?) FROM numbers(?)
 UNION ALL SELECT concat('pod-',toString(number)),'k8s_pod',
 concat('role-',toString(intDiv(number,10))),'iam_role','executes_as','{}',toDateTime(?) FROM numbers(?)
 UNION ALL SELECT concat('ingress-',toString(number)),'k8s_ingress',
 concat('service-',toString(number)),'k8s_service','routes_to','{}',toDateTime(?) FROM numbers(?)
 UNION ALL SELECT concat('ingress-',toString(number*2)),'k8s_ingress',
 'internet','internet','exposed_to_internet','{}',toDateTime(?) FROM numbers(?)
 UNION ALL SELECT concat('role-',toString(number)),'iam_role',
 concat('role-',toString((number+1)%?)),'iam_role','can_assume','{}',toDateTime(?) FROM numbers(?)`

// Every image has a shared hot set; the remaining memberships rotate through
// the long tail. Slots stay distinct within an image, including partial rounds.
const seedMemberships = `INSERT INTO graph_edges
 (src_id,src_type,dst_id,dst_type,edge_type,properties,synced_at)
 SELECT concat('image-',toString(image)),'container_image',
 concat('pkg:generic/bench-',toString(if(slot<?,slot,?+(image*37+slot-?)%(?-?))),'@1.0.0'),
 'package','runs_package','{}',toDateTime(?)
 FROM (SELECT number%? AS image,intDiv(number,?) AS slot FROM numbers(?))`

const seedFindings = `INSERT INTO findings
 (id,source,type,severity,title,resource_type,resource_id,check_id,detected_at,synced_at)
 SELECT concat('bench-finding-',?,toString(number)),?,'vulnerability','high','Synthetic finding',?,
 concat(?,toString(number*10),?),concat('CVE-2026-',toString(10000+number)),toDateTime(?),toDateTime(?)
 FROM numbers(?)`

const seedEnrichment = `INSERT INTO finding_enrichment (id,score,score_band,known_exploited,enriched_at)
 SELECT id,80,'high',toUInt8(cityHash64(id)%10=0),toDateTime64(?,3) FROM findings`

const seedOldVersions = `INSERT INTO graph_edges
 SELECT * REPLACE (synced_at-INTERVAL 1 SECOND AS synced_at)
 FROM graph_edges WHERE cityHash64(src_id)%100=0`

const changeTopology = `INSERT INTO assets
 SELECT * REPLACE (concat(name,'-updated') AS name,toDateTime(?) AS synced_at)
 FROM assets WHERE type='k8s_pod' AND toUInt64OrNull(substring(id,5))%100=0`

// Deliberately count raw fixture rows, including versions, outside measurements.
const fixtureCounts = `SELECT
 (SELECT uniqExact(id) FROM assets),
 (SELECT uniqExact(tuple(src_id,edge_type,dst_id)) FROM graph_edges),
 (SELECT count() FROM assets), (SELECT count() FROM graph_edges)`

type rowCounts struct {
	Assets        uint64 `json:"logical_assets"`
	Edges         uint64 `json:"logical_edges"`
	AssetVersions uint64 `json:"physical_asset_rows"`
	EdgeVersions  uint64 `json:"physical_edge_rows"`
}

func seed(ctx context.Context, ch *db.CH, p profile, stamp int64) error {
	for _, a := range []struct {
		typ, prefix, suffix string
		count               uint64
	}{
		{"k8s_pod", "pod-", "", p.Workloads},
		{"container_image", "image-", "", p.Images},
		{"k8s_service", "service-", "", p.Groups},
		{"k8s_ingress", "ingress-", "", p.Groups},
		{"iam_role", "role-", "", p.Groups},
		{"package", "pkg:generic/bench-", "@1.0.0", p.Packages},
	} {
		if err := ch.Exec(ctx, seedAssets, a.prefix, a.suffix, a.typ, a.typ == "package", stamp, stamp, stamp, a.count); err != nil {
			return fmt.Errorf("seed %s: %w", a.typ, err)
		}
	}
	if err := ch.Exec(ctx, seedCoreEdges, p.Images, stamp, p.Workloads, stamp, p.Workloads,
		stamp, p.Workloads, stamp, p.Groups, stamp, p.Groups/2, p.Groups, stamp, p.Groups); err != nil {
		return fmt.Errorf("seed core edges: %w", err)
	}
	hot := p.hotPackages()
	if err := ch.Exec(ctx, seedMemberships, hot, hot, hot, p.Packages, hot, stamp, p.Images, p.Images, p.Memberships); err != nil {
		return fmt.Errorf("seed memberships: %w", err)
	}
	for _, f := range []struct {
		source, typ, prefix, suffix string
		count                       uint64
	}{
		{"cspm", "k8s_pod", "pod-", "", p.Workloads / 10},
		{"supply_chain", "package", "pkg:generic/bench-", "@1.0.0", p.Packages / 10},
	} {
		if err := ch.Exec(ctx, seedFindings, f.source, f.source, f.typ, f.prefix, f.suffix, stamp, stamp, f.count); err != nil {
			return fmt.Errorf("seed findings: %w", err)
		}
	}
	if err := ch.Exec(ctx, seedEnrichment, stamp); err != nil {
		return fmt.Errorf("seed enrichment: %w", err)
	}
	if err := ch.Exec(ctx, seedOldVersions); err != nil {
		return fmt.Errorf("seed versions: %w", err)
	}
	return nil
}

func counts(ctx context.Context, ch *db.CH) (rowCounts, error) {
	var c rowCounts
	err := ch.Select(ctx, func(rows driver.Rows) error {
		if !rows.Next() {
			return fmt.Errorf("fixture count returned no row")
		}
		return rows.Scan(&c.Assets, &c.Edges, &c.AssetVersions, &c.EdgeVersions)
	}, fixtureCounts)
	return c, err
}

const queryCosts = `SELECT query_id,normalized_query_hash,query,query_duration_ms,read_rows,read_bytes,
 result_rows,memory_usage,exception_code,exception
 FROM system.query_log WHERE type IN ('QueryFinish','ExceptionBeforeStart','ExceptionWhileProcessing')
 AND log_comment=? ORDER BY event_time_microseconds,query_id`

type queryCost struct {
	ID            string `json:"query_id"`
	Hash          uint64 `json:"normalized_query_hash"`
	SQL           string `json:"sql"`
	Milliseconds  uint64 `json:"duration_ms"`
	ReadRows      uint64 `json:"read_rows"`
	ReadBytes     uint64 `json:"read_bytes"`
	ResultRows    uint64 `json:"result_rows"`
	Memory        uint64 `json:"memory_bytes"`
	ExceptionCode int32  `json:"exception_code"`
	Exception     string `json:"exception,omitempty"`
}

func costs(ctx context.Context, ch *db.CH, comment string) ([]queryCost, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := ch.Exec(ctx, "SYSTEM FLUSH LOGS"); err != nil {
		return nil, fmt.Errorf("flush query log: %w", err)
	}
	var out []queryCost
	err := ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var q queryCost
			if err := rows.Scan(&q.ID, &q.Hash, &q.SQL, &q.Milliseconds, &q.ReadRows, &q.ReadBytes, &q.ResultRows, &q.Memory, &q.ExceptionCode, &q.Exception); err != nil {
				return err
			}
			out = append(out, q)
		}
		return rows.Err()
	}, queryCosts, comment)
	return out, err
}
