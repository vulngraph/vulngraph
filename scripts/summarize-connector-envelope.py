#!/usr/bin/env python3
"""Summarize retained envelope evidence without adding independent peaks."""

import bisect
import collections
import datetime
import hashlib
import json
import pathlib
import sys


def records(path):
    with path.open() as stream:
        return [json.loads(line) for line in stream if line.strip()]


def timestamp(value):
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def integer_file(record, name):
    value = record["files"][name]
    return int(value[0] if isinstance(value, list) else value)


def cpu_seconds(record):
    value = record["files"]["/sys/fs/cgroup/cpu.stat"]
    lines = value if isinstance(value, list) else value.splitlines()
    counters = dict(line.split() for line in lines)
    return int(counters["usage_usec"]) / 1_000_000


def main():
    root = pathlib.Path(sys.argv[1])
    trace = records(root / "worker-timeline.jsonl")
    worker = [row for row in trace if row["event"] == "sample"]
    databases = {}
    for name in ("clickhouse", "postgres"):
        rows = records(root / (name + "-resources.jsonl"))
        databases[name] = (rows, [timestamp(row["received_at"]) for row in rows])
    aligned = []
    for row in worker:
        at = timestamp(row["at"])
        times = [at]
        swap = {}
        if "/sys/fs/cgroup/memory.swap.current" in row["files"]:
            swap["worker"] = integer_file(row, "/sys/fs/cgroup/memory.swap.current")
        sample = {"at": row["at"], "active": row["active"], "worker": integer_file(row, "/sys/fs/cgroup/memory.current"),
                  "worker_go_heap": row["go_heap_alloc_bytes"], "cpu_seconds": {"worker": cpu_seconds(row)}}
        for name, (rows, stamps) in databases.items():
            position = bisect.bisect_left(stamps, at)
            candidates = [i for i in (position - 1, position) if 0 <= i < len(rows)]
            if not candidates:
                raise ValueError("missing database resource samples")
            match = min(candidates, key=lambda i: abs(stamps[i] - at))
            times.append(stamps[match])
            sample[name] = integer_file(rows[match], "/sys/fs/cgroup/memory.current")
            sample["cpu_seconds"][name] = cpu_seconds(rows[match])
            if "/sys/fs/cgroup/memory.swap.current" in rows[match]["files"]:
                swap[name] = integer_file(rows[match], "/sys/fs/cgroup/memory.swap.current")
        sample["span_seconds"] = max(times) - min(times)
        if sample["span_seconds"] <= 0.4:
            sample["sum_cgroup_bytes"] = sum(sample[name] for name in ("worker", "clickhouse", "postgres"))
            sample["swap_bytes"] = swap
            if len(swap) == 3:
                sample["sum_swap_bytes"] = sum(swap.values())
                sample["sum_resident_and_swap_bytes"] = sample["sum_cgroup_bytes"] + sample["sum_swap_bytes"]
            aligned.append(sample)
    pipeline = ("sync", "collect", "retained_result", "correlation_full", "correlation_partial", "enrich", "graph")
    native_windows = [(timestamp(row["at"]) - row["seconds"], timestamp(row["at"]))
                      for row in trace if row["event"] == "graph_phase_end" and row["phase"] in ("copy", "bfs")]
    native_samples = [row for row in aligned if any(start <= timestamp(row["at"]) <= end for start, end in native_windows)]
    def all_four(row):
        return all(row["active"].get(kind, 0) for kind in ("sync", "enrich", "correlation_full", "graph"))
    def peak(rows):
        return max(rows, key=lambda row: row["sum_cgroup_bytes"], default=None)
    groups = collections.defaultdict(lambda: {"queries": 0, "errors": 0, "read_rows": 0, "read_bytes": 0,
                                            "written_rows": 0, "written_bytes": 0, "peak_query_memory_bytes": 0,
                                            "query_cpu_microseconds": 0})
    cost_path = root / "application-query-costs.jsonl"
    if cost_path.exists():
        for row in records(cost_path):
            query = row["normalized_query"].lower()
            if row.get("log_comment") == "envelope-output-oracle":
                category = "output_oracle"
            elif query.startswith("insert into asset_finding_risk"):
                category = "risk_pin_copy" if "select" in query else ("risk_commit_marker" if "pinned" in query else "risk_stage")
            elif query.startswith("insert into asset_risk_publications"):
                category = "risk_retirement_markers" if "select" in query else "risk_publish"
            elif query.startswith("delete from asset"):
                category = "derived_cleanup" if "asset_finding_risk" in query or "asset_risk_publications" in query else "inventory_retirement"
            elif "asset_finding_risk" in query or "asset_risk_publications" in query:
                category = "derived_verification_and_selection"
            else:
                category = "other_application_queries"
            item = groups[category]
            item["queries"] += 1
            item["errors"] += int(row["exception_code"]) != 0
            for field in ("read_rows", "read_bytes", "written_rows", "written_bytes"):
                item[field] += int(row[field])
            item["peak_query_memory_bytes"] = max(item["peak_query_memory_bytes"], int(row["memory_usage"]))
            events = row["ProfileEvents"]
            item["query_cpu_microseconds"] += sum(int(events.get(name, 0)) for name in ("UserTimeMicroseconds", "SystemTimeMicroseconds"))
    table_samples = records(root / "database-timeline.jsonl") if (root / "database-timeline.jsonl").exists() else []
    db_peaks = {"active_parts": 0, "pending_mutations": 0, "mutation_parts_to_do": 0, "active_merges": 0, "sampler_errors": 0}
    for sample in table_samples:
        db_peaks["sampler_errors"] += "error" in sample
        for field, kind, column in (("active_parts", "parts", "entries"), ("pending_mutations", "mutations", "entries"),
                                    ("mutation_parts_to_do", "mutations", "rows"), ("active_merges", "merges", "entries")):
            total = sum(int(row[column]) for row in sample.get("rows", []) if row["kind"] == kind)
            db_peaks[field] = max(db_peaks[field], total)
    result = {
        "source_patch_sha256": hashlib.sha256((root / "source.patch").read_bytes()).hexdigest(),
        "worker_samples": len(worker), "aligned_samples": len(aligned),
        "maximum_alignment_span_seconds": max((row["span_seconds"] for row in aligned), default=None),
        "coincident_peak": peak(aligned),
        "coincident_resident_and_swap_peak": max((row for row in aligned if "sum_resident_and_swap_bytes" in row), key=lambda row: row["sum_resident_and_swap_bytes"], default=None),
        "active_pipeline_peak": peak([row for row in aligned if any(row["active"].get(kind, 0) for kind in pipeline)]),
        "phase_peaks": {kind: peak([row for row in aligned if row["active"].get(kind, 0)]) for kind in pipeline + ("oracle",)},
        "all_four_overlap_samples": sum(all_four(row) for row in aligned),
        "all_four_overlap_peak": peak([row for row in aligned if all_four(row)]),
        "native_build_peak": peak(native_samples),
        "all_four_native_build_samples": sum(all_four(row) for row in native_samples),
        "query_cost_groups": dict(groups), "database_sampled_peaks": db_peaks,
        "aligned_cpu_window_seconds": timestamp(aligned[-1]["at"]) - timestamp(aligned[0]["at"]) if aligned else None,
        "aligned_cpu_core_seconds": {name: aligned[-1]["cpu_seconds"][name] - aligned[0]["cpu_seconds"][name]
                                     for name in ("worker", "clickhouse", "postgres")} if aligned else None,
        "limitations": ["resident cgroup totals exclude swap; aligned resident+swap is reported only when all sources sampled it",
                        "sampled cgroup totals include caches and benchmark observer overhead; not separate native allocator bytes",
                        "nearest samples align within 400ms; peaks between samples can be missed",
                        "query costs include validation reads unless explicitly tagged output_oracle",
                        "database query CPU excludes background merges; process CPU/IO counters remain in resource timelines",
                        "synthetic local one-worker result, not fleet or SDK sizing evidence"],
    }
    (root / "aligned-costs.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("aligned_samples", "active_pipeline_peak", "database_sampled_peaks")}))


if __name__ == "__main__":
    main()
