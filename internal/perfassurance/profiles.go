package perfassurance

import (
	"encoding/json"
	"fmt"
)

// validateProfile rejects an empty or weakened resource/correctness declaration.
// Measurements still need to prove these limits were actually enforced.
func validateProfile(name string, raw json.RawMessage) []string {
	var p struct {
		Assets   int `json:"assets"`
		Findings int `json:"findings"`
		HTTPRate int `json:"http_requests_per_second"`
		JobRate  int `json:"enrichment_jobs_per_second"`
		Host     struct {
			CPUs       int `json:"vcpus"`
			Memory     int `json:"memory_gib"`
			Storage    int `json:"storage_gib"`
			IOPS       int `json:"storage_iops"`
			Throughput int `json:"storage_mib_per_second"`
		} `json:"host"`
		Limits map[string]struct {
			CPUs   int `json:"cpus"`
			Memory int `json:"memory_gib"`
		} `json:"limits"`
		Budgets struct {
			P95        int  `json:"interactive_p95_ms"`
			P99        int  `json:"interactive_p99_ms"`
			Freshness  int  `json:"admitted_change_freshness_seconds"`
			Recovery   int  `json:"full_recovery_seconds"`
			Soak       int  `json:"minimum_elapsed_soak_hours"`
			Errors     *int `json:"unexpected_errors"`
			Mismatches *int `json:"correctness_mismatches"`
			Lost       *int `json:"lost_or_unexplained_jobs"`
		} `json:"budgets"`
	}
	fail := func(reason string) []string { return []string{fmt.Sprintf("profile %s: %s", name, reason)} }
	if err := json.Unmarshal(raw, &p); err != nil {
		return fail("invalid JSON")
	}
	if p.Assets <= 0 || p.Findings <= 0 || p.HTTPRate <= 0 || p.JobRate <= 0 {
		return fail("missing dataset or arrival rate")
	}
	if p.Host.CPUs <= 0 || p.Host.Memory <= 0 || p.Host.Storage <= 0 || p.Host.IOPS <= 0 || p.Host.Throughput <= 0 {
		return fail("missing host/storage limits")
	}
	var cpus, memory int
	for _, component := range []string{"application", "clickhouse", "postgres", "scanner"} {
		v := p.Limits[component]
		if v.CPUs <= 0 || v.Memory <= 0 {
			return fail("missing component limits: " + component)
		}
		cpus += v.CPUs
		memory += v.Memory
	}
	if cpus > p.Host.CPUs || memory > p.Host.Memory {
		return fail("component limits exceed declared host")
	}
	b := p.Budgets
	if b.P95 <= 0 || b.P99 < b.P95 || b.Freshness <= 0 || b.Recovery <= 0 || b.Soak < 24 {
		return fail("missing latency/freshness/recovery/24h soak budgets")
	}
	for _, v := range []*int{b.Errors, b.Mismatches, b.Lost} {
		if v == nil || *v != 0 {
			return fail("correctness/error/lost-work budgets must explicitly be zero")
		}
	}
	return nil
}
