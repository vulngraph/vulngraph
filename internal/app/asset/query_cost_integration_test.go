//go:build integration

package asset

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/graphschema"
	"github.com/vulngraph/vulngraph/internal/perfassurance"
)

const baselineInventorySelect = `SELECT id, name, type, provider, region, account_id, endpoint,
 public_ip, private_ip, domain, tags, metadata, risk_score, discovered_at, first_discovered_at, last_seen
 FROM assets FINAL`

// Retained experiment: smaller query buffers reduced query memory but worsened
// mixed-load read tails without a consistent whole-server memory reduction.
const (
	inventoryQueryThreads   = 2
	inventoryQueryBlockRows = 512
)

func inventoryBufferExperiment(ctx context.Context, ch *db.CH) context.Context {
	return ch.WithQuerySettings(ctx, map[string]any{"max_threads": inventoryQueryThreads, "max_block_size": inventoryQueryBlockRows})
}

// Retain the pre-change SQL as a matched baseline, independently of listQuery.
func baselineInventoryQuery(f Filter) (string, []any, error) {
	conds := []string{inventoryReadCond}
	var args []any
	for _, pair := range [][2]string{{"provider", f.Provider}, {"type", f.Type}, {"region", f.Region}, {"account_id", f.AccountID}} {
		if pair[1] != "" {
			conds = append(conds, pair[0]+" = ?")
			args = append(args, pair[1])
		}
	}
	if f.Search != "" {
		c, a := assetSearchCondition(f.Search)
		conds = append(conds, c)
		args = append(args, a...)
	}
	if f.Exposed {
		conds = append(conds, "id IN (SELECT DISTINCT src_id FROM graph_edges WHERE edge_type = 'exposed_to_internet' AND "+graphschema.EdgeFreshnessCond+")")
	}
	if f.MinScore > 0 {
		conds = append(conds, "risk_score >= ?")
		args = append(args, f.MinScore)
	}
	q := baselineInventorySelect + " WHERE " + strings.Join(conds, " AND ")
	if f.Cursor != "" {
		stamp, id, err := decodeCursor(f.Cursor)
		if err != nil {
			return "", nil, err
		}
		q += " AND (last_seen, id) < (?, ?)"
		args = append(args, stamp, id)
	}
	limit := f.Limit
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	return q + " ORDER BY last_seen DESC, id DESC LIMIT ?", append(args, limit), nil
}

const seedInventoryQueryFixture = `INSERT INTO assets
 (id,name,type,provider,region,account_id,tags,metadata,risk_score,discovered_at,first_discovered_at,last_seen,synced_at)
 SELECT concat('query-',hex(MD5(toString(number)))), concat('host-',toString(number)),
 if(number%7=0,'k8s_pod','ec2_instance'),if(number%3=0,'gcp','aws'),if(number%5=0,'west','east'),
 toString(number%10), map(),toJSONString(map('payload',repeat(hex(SHA256(toString(number))),256))),
 toUInt8(number%100), now()-INTERVAL 1 DAY,now()-INTERVAL 1 DAY,
 if(number%14=0,now()-INTERVAL 8 DAY,now()-toIntervalSecond(number%1000)),now64(9)
 FROM numbers(?) SETTINGS max_block_size=512`

func readInventoryFixture(ctx context.Context, ch *db.CH, q string, args ...any) ([]Asset, error) {
	var out []Asset
	err := ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			a, err := scanAsset(rows)
			if err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	}, q, args...)
	return out, err
}

func TestInventoryQueryCosts(t *testing.T) {
	if os.Getenv("PERF_QUERY_ISOLATED") != "1" {
		t.Skip("run scripts/benchmark-queries.sh")
	}
	n, err := strconv.Atoi(os.Getenv("PERF_QUERY_ROWS"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, 1000)
	ctx := t.Context()
	ch, err := perfassurance.OpenQueryStore(ctx, os.Getenv("PERF_CLICKHOUSE_URL"))
	require.NoError(t, err)
	defer ch.Close()
	queryLog := perfassurance.QueryLogAccess{
		Flush: func(ctx context.Context) error { return ch.Exec(ctx, "SYSTEM FLUSH LOGS") },
		Select: `SELECT query, query_duration_ms, read_rows, read_bytes, memory_usage, exception, Settings['max_threads'], Settings['max_block_size'], ProfileEvents
 FROM system.query_log WHERE log_comment=? AND type IN ('QueryFinish','ExceptionWhileProcessing','ExceptionBeforeStart') ORDER BY event_time_microseconds, query_id`,
	}
	r := perfassurance.QueryReport{Rows: n, Plans: map[string][]string{}}
	versions := 1
	if v := os.Getenv("PERF_QUERY_VERSIONS"); v != "" {
		versions, err = strconv.Atoi(v)
		require.NoError(t, err)
		require.GreaterOrEqual(t, versions, 1)
		require.LessOrEqual(t, versions, 20)
	}
	budget := perfassurance.QueryBudget{Queries: 1, ReadRows: uint64(n * versions * 5), ReadBytes: uint64(n * versions * 20000), MemoryBytes: 32<<20 + uint64(n)*512}
	defer func() {
		r.Passed = !t.Failed()
		require.NoError(t, perfassurance.SaveQueryReport(os.Getenv("PERF_QUERY_DIR"), "inventory", r))
	}()
	require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
		if !rows.Next() {
			return fmt.Errorf("missing server thread default")
		}
		return rows.Scan(&r.DefaultMaxThreads)
	}, "SELECT toUInt64(getSetting('max_threads'))"))
	require.NoError(t, ch.Exec(ctx, "SYSTEM STOP MERGES assets"))
	require.NoError(t, ch.Exec(ctx, seedInventoryQueryFixture, n))
	for v := 1; v < versions; v++ {
		require.NoError(t, ch.Exec(ctx, `INSERT INTO assets SELECT * REPLACE(t.synced_at+INTERVAL 1 SECOND AS synced_at) FROM assets AS t WHERE t.synced_at=(SELECT max(v.synced_at) FROM assets AS v)`))
	}
	var physical, logical uint64
	require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
		if !rows.Next() {
			return fmt.Errorf("missing fixture counts")
		}
		return rows.Scan(&physical, &logical)
	}, "SELECT count(),uniqExact(id) FROM assets"))
	require.Equal(t, uint64(n*versions), physical)
	require.Equal(t, uint64(n), logical)
	require.NoError(t, ch.Exec(ctx, `INSERT INTO graph_edges (src_id,src_type,dst_id,dst_type,edge_type,properties,synced_at)
 SELECT id,type,'internet','internet','exposed_to_internet','{}',now64(9) FROM assets WHERE risk_score>=75`))

	filters := []struct {
		name string
		f    Filter
	}{{"all", Filter{}}, {"provider", Filter{Provider: "aws"}}, {"type", Filter{Type: "ec2_instance"}}, {"region", Filter{Region: "west"}}, {"account", Filter{AccountID: "2"}}, {"search", Filter{Search: "host-99"}}, {"exposed", Filter{Exposed: true}}, {"min_score", Filter{MinScore: 90}}}
	for _, tc := range filters {
		f := tc.f
		expected := independentInventoryKeys(n, f)
		for page := 0; page < 2; page++ {
			q, args, err := baselineInventoryQuery(f)
			require.NoError(t, err)
			want, err := readInventoryFixture(ctx, ch, q, args...)
			require.NoError(t, err)
			begin := min(page*100, len(expected))
			end := min(begin+100, len(expected))
			require.Len(t, want, end-begin)
			for i, a := range want {
				key := expected[begin+i]
				require.Equal(t, key.id, a.ID)
				require.Equal(t, "host-"+strconv.Itoa(key.n), a.Name)
				require.Equal(t, strings.Repeat(fmt.Sprintf("%X", sha256.Sum256([]byte(strconv.Itoa(key.n)))), 256), a.Metadata["payload"])
				require.Equal(t, uint8(key.n%100), a.RiskScore)
			}
			label := fmt.Sprintf("inventory-%s-page%d", tc.name, page)
			r.Plans[label], err = perfassurance.Explain(ctx, ch, q, args...)
			require.NoError(t, err)
			candidateQ, candidateArgs, err := listQuery(f)
			if os.Getenv("PERF_QUERY_EXPERIMENT") == "keys" {
				candidateQ, candidateArgs, err = candidateInventoryQuery(f)
			}
			require.NoError(t, err)
			r.Plans[label+"-candidate"], err = perfassurance.Explain(ctx, ch, candidateQ, candidateArgs...)
			require.NoError(t, err)
			for repeat := 0; repeat < 3; repeat++ {
				for _, candidate := range []bool{false, true} {
					mode := "baseline"
					if candidate {
						mode = "candidate"
					}
					sample, err := perfassurance.Measure(ctx, ch, queryLog, fmt.Sprintf("%s-%s-%d", label, mode, repeat), func(ctx context.Context) error {
						var got []Asset
						var err error
						if candidate {
							if os.Getenv("PERF_QUERY_EXPERIMENT") == "keys" {
								candidateQ, candidateArgs, e := candidateInventoryQuery(f)
								if e != nil {
									return e
								}
								got, err = readInventoryFixture(ctx, ch, candidateQ, candidateArgs...)
							} else {
								if os.Getenv("PERF_QUERY_EXPERIMENT") == "buffers" {
									ctx = inventoryBufferExperiment(ctx, ch)
								}
								got, err = NewCHRepo(ch).List(ctx, f)
							}
						} else {
							got, err = readInventoryFixture(ctx, ch, q, args...)
						}
						if err != nil {
							return err
						}
						if !reflect.DeepEqual(want, got) {
							return fmt.Errorf("exact result parity failed for %s", label)
						}
						return nil
					})
					if budgetErr := budget.Check(sample); budgetErr != nil {
						sample.BudgetError = budgetErr.Error()
					}
					r.Samples = append(r.Samples, sample)
					require.NoError(t, err)
					if candidate {
						require.NoError(t, budget.Check(sample))
						if os.Getenv("PERF_QUERY_EXPERIMENT") == "buffers" {
							for _, q := range sample.Queries {
								// Query-log Settings omits values equal to the server
								// default, including explicit two-thread settings on CI.
								if q.MaxThreads == "" {
									require.Equal(t, uint64(inventoryQueryThreads), r.DefaultMaxThreads)
								} else {
									require.Equal(t, strconv.Itoa(inventoryQueryThreads), q.MaxThreads)
								}
								require.Equal(t, strconv.Itoa(inventoryQueryBlockRows), q.MaxBlockSize)
							}
						}
					}
				}
			}
			if len(want) == 0 {
				break
			}
			f.Cursor = EncodeCursor(want[len(want)-1])
		}
	}
	expectedSummary := Summary{ByProvider: map[string]int{}, ByType: map[string]int{}}
	for _, key := range independentInventoryKeys(n, Filter{}) {
		expectedSummary.Total++
		provider := "aws"
		if key.n%3 == 0 {
			provider = "gcp"
		}
		typ := "ec2_instance"
		if key.n%7 == 0 {
			typ = "k8s_pod"
		}
		expectedSummary.ByProvider[provider]++
		expectedSummary.ByType[typ]++
	}
	r.Plans["inventory-summary"], err = perfassurance.Explain(ctx, ch, assetSummary)
	require.NoError(t, err)
	for repeat := 0; repeat < 3; repeat++ {
		sample, err := perfassurance.Measure(ctx, ch, queryLog, fmt.Sprintf("inventory-summary-%d", repeat), func(ctx context.Context) error {
			got, err := NewCHRepo(ch).Summary(ctx)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(expectedSummary, got) {
				return fmt.Errorf("independent inventory summary mismatch")
			}
			return nil
		})
		r.Samples = append(r.Samples, sample)
		require.NoError(t, err)
		require.NoError(t, budget.Check(sample))
	}

	if n == 1000 && versions == 1 {
		mutant, err := perfassurance.Measure(ctx, ch, queryLog, "inventory-wide-state-mutation", func(ctx context.Context) error {
			return ch.Select(ctx, func(rows driver.Rows) error {
				for rows.Next() {
					var n uint64
					if err := rows.Scan(&n); err != nil {
						return err
					}
				}
				return rows.Err()
			}, `SELECT toUInt64(length(groupArray(concat(metadata,metadata,metadata,metadata,metadata,metadata,metadata,metadata)))) FROM assets`)
		})
		require.NoError(t, err)
		mutant.ExpectedBudgetViolation = "query memory"
		r.Samples = append(r.Samples, mutant)
		require.ErrorContains(t, budget.Check(mutant), "query memory", "the real wide-state regression must trip the cost guard")
	}
}

// Experimental shape: keep FINAL's (type,id) identity and latest-row semantics,
// select narrow keys, then aggregate only their full rows in the same statement.
const candidateInventoryHydration = `SELECT id, current.1, type, current.2, current.3,
 current.4, current.5, current.6, current.7, current.8, current.9, current.10,
 current.11, current.12, current.13, current.14 AS last_seen
 FROM (SELECT id,type,argMax(tuple(name,provider,region,account_id,endpoint,public_ip,private_ip,domain,
 tags,metadata,risk_score,discovered_at,first_discovered_at,last_seen),synced_at) AS current
 FROM assets WHERE (type,id) IN (%s) GROUP BY type,id)
 ORDER BY last_seen DESC,id DESC`

func candidateInventoryQuery(f Filter) (string, []any, error) {
	q, args, err := baselineInventoryQuery(f)
	if err != nil {
		return "", nil, err
	}
	keys := strings.Replace(q, baselineInventorySelect, "SELECT type,id FROM assets FINAL", 1)
	return fmt.Sprintf(candidateInventoryHydration, keys), args, nil
}

type inventoryFixtureKey struct {
	id string
	n  int
}

func independentInventoryKeys(n int, f Filter) []inventoryFixtureKey {
	var keys []inventoryFixtureKey
	for i := 0; i < n; i++ {
		typ := "ec2_instance"
		if i%7 == 0 {
			typ = "k8s_pod"
		}
		if i%14 == 0 {
			continue
		}
		provider := "aws"
		if i%3 == 0 {
			provider = "gcp"
		}
		region := "east"
		if i%5 == 0 {
			region = "west"
		}
		id := fmt.Sprintf("query-%X", md5.Sum([]byte(strconv.Itoa(i))))
		if f.Provider != "" && f.Provider != provider || f.Type != "" && f.Type != typ || f.Region != "" && f.Region != region || f.AccountID != "" && f.AccountID != strconv.Itoa(i%10) || f.Exposed && i%100 < 75 || i%100 < int(f.MinScore) {
			continue
		}
		if f.Search != "" && !strings.Contains("host-"+strconv.Itoa(i), f.Search) && !strings.Contains(id, f.Search) {
			continue
		}
		keys = append(keys, inventoryFixtureKey{id, i})
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.n%1000 != b.n%1000 {
			return a.n%1000 < b.n%1000
		}
		return a.id > b.id
	})
	return keys
}
