#!/usr/bin/env python3
"""Collect comparable benchmark cohorts; never treat a failed run as a baseline."""

import argparse
import json
import math
import os
import platform
from pathlib import Path
import statistics
import subprocess
import sys


def read(path):
    return json.loads(Path(path).read_text())


def linux_cpu(cpuinfo, fallback):
    models, arm_ids = set(), set()
    arm_keys = ["CPU implementer", "CPU architecture", "CPU variant", "CPU part", "CPU revision"]
    for block in cpuinfo.strip().split("\n\n"):
        fields = dict(line.split(":", 1) for line in block.splitlines() if ":" in line)
        fields = {key.strip(): value.strip() for key, value in fields.items()}
        if fields.get("model name"):
            models.add(fields["model name"])
        # Linux ARM often has no model name; the architecture alone would make
        # different processors appear to be comparable benchmark hardware.
        if fields.get("CPU implementer") and fields.get("CPU part"):
            arm_ids.add(", ".join(f"{key}={fields[key]}" for key in arm_keys if key in fields))
    return " | ".join(sorted(arm_ids or models)) or fallback


def environment(postgres, clickhouse):
    cpu = platform.processor()
    if sys.platform == "darwin":
        cpu = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
    elif Path("/proc/cpuinfo").exists():
        cpu = linux_cpu(Path("/proc/cpuinfo").read_text(), cpu)
    stores = {}
    for name, container in [("postgres", postgres), ("clickhouse", clickhouse)]:
        # Select only resource limits and image identity; never export credentials.
        raw = subprocess.check_output([
            "docker", "inspect", "--format",
            '{{.Image}} {{.HostConfig.Memory}} {{.HostConfig.NanoCpus}}', container,
        ], text=True).split()
        stores[name] = {"image": raw[0], "memory_bytes": int(raw[1]), "nanocpus": int(raw[2])}
    return {
        "format_version": 1,
        "run_id": postgres,
        "working_tree_clean": not subprocess.check_output(["git", "status", "--porcelain"], text=True).strip(),
        "stable_machine_id": os.getenv("PERF_BASELINE_MACHINE", ""),
        "os": platform.system(), "architecture": platform.machine(),
        "cpu": cpu, "logical_cpus": os.cpu_count(), "stores": stores,
    }


def measurements(root):
    root = Path(root)
    graph = read(root / "storage/report.json")
    sync = read(root / "sync.json")
    soak = read(root / "soak.json")
    env = read(root / "storage/environment.json")
    env.pop("run_id")
    if not env["working_tree_clean"]:
        raise ValueError(f"{root}: dirty source tree; commit validated changes before creating a baseline")
    for label, report in [("graph", graph), ("sync", sync), ("soak", soak)]:
        if report.get("passed") is not True:
            raise ValueError(f"{root}: {label} did not pass")
    if len(soak["waves"]) < 3 or not soak["graph_rebuilt_after_restart"] or soak["retried_jobs"] < 2:
        raise ValueError(f"{root}: incomplete recovery measurement")
    if soak["final_unmeasured_findings"] or soak["verified_enrichments"] <= 0 or soak["blast_query_failures"]:
        raise ValueError(f"{root}: incomplete enrichment verification")
    if any(v["errors"] or v["count"] == 0 for v in soak["reads"].values()) or len(soak["reads"]) != 3:
        raise ValueError(f"{root}: missing or failed concurrent reads")
    if len(sync["measurements"]) != 40 or len(graph["measurements"]) != 6:
        raise ValueError(f"{root}: incomplete scenario matrix")
    connector_names = {"aws", "gcp", "azure", "kubernetes", "github", "okta", "google_workspace", "demo"}
    sync_scenarios = {"initial", "unchanged", "change_1pct", "unchanged_after", "partial"}
    if {(m["connector"], m["scenario"]) for m in sync["measurements"]} != {(c, s) for c in connector_names for s in sync_scenarios}:
        raise ValueError(f"{root}: duplicated or missing sync scenario")
    if {m["scenario"] for m in graph["measurements"]} != {"initial_build", "unchanged_1", "unchanged_2", "finding_update", "topology_update_1pct", "unchanged_after_update"}:
        raise ValueError(f"{root}: duplicated or missing graph scenario")
    collection_env = (root / "environment.txt").read_text().splitlines()
    if len(collection_env) != 2 or collection_env[1] != graph["commit"] or not collection_env[0].startswith("request_delay_ms="):
        raise ValueError(f"{root}: collection source is dirty, missing or differs from storage source")
    cohort = {
        "environment": env, "profile": graph["profile"],
        "versions": [graph["fixture_version"], sync["fixture_version"], soak["fixture_version"]],
        "go_version": graph["go_version"], "gomaxprocs": graph["gomaxprocs"],
        "ladybug_buffer_mb": graph["ladybug_buffer_mb"],
        "sync_counts": sorted((m["connector"], m["scenario"], m["verified_assets"], m["verified_edges"]) for m in sync["measurements"]),
        "soak_counts": [soak["verified_assets"], soak["verified_edges"], soak["verified_enrichments"]],
        "request_delay_ms": int(collection_env[0].split("=", 1)[1]),
        "soak_minimum_seconds": soak["minimum_seconds"],
        "soak_ch_concurrency": soak["clickhouse_concurrency"],
    }
    values = {}
    collection_counts = []
    connectors = set()
    for path in sorted(root.glob("*-*.json")):
        if path.name.endswith("-fixture.json"):
            continue
        samples = read(path)
        if not isinstance(samples, list) or len(samples) != 3:
            raise ValueError(f"{path}: expected three collection samples")
        first = samples[0]
        identity = tuple(first[k] for k in ["connector", "scope", "size", "assets", "edges", "partial", "duplicate_asset_rows"])
        if any(tuple(m[k] for k in ["connector", "scope", "size", "assets", "edges", "partial", "duplicate_asset_rows"]) != identity for m in samples):
            raise ValueError(f"{path}: collection cardinality changed between samples")
        if sorted(m["run"] for m in samples) != [0, 1, 2]:
            raise ValueError(f"{path}: missing collection repetition")
        connectors.add(first["connector"])
        collection_counts.append(identity)
        for key in ["seconds", "allocated_bytes", "requests"]:
            values[f"collect/{first['connector']}/{first['size']}/{key}"] = statistics.median(m[key] for m in samples)
    if not connector_names <= connectors:
        raise ValueError(f"{root}: missing connector collection measurements")
    cohort["collection_counts"] = collection_counts
    org = read(root / "aws_org.json")
    sizes = {m[2] for m in collection_counts if m[0] == "aws"}
    if len(org) != len(sizes)*3 or {(m["accounts"], m["phase"]) for m in org} != {(n, p) for n in sizes for p in ["initial", "unchanged", "unchanged_again"]}:
        raise ValueError(f"{root}: incomplete organization reconciliation")
    cohort["organization_scenarios"] = [(m["accounts"], m["phase"]) for m in org]
    for m in org:
        values[f"organization/{m['accounts']}/{m['phase']}/seconds"] = m["seconds"]
    for m in graph["measurements"]:
        for key in ["seconds", "read_rows", "read_bytes", "max_query_memory_bytes", "process_peak_rss_bytes"]:
            values[f"graph/{m['scenario']}/{key}"] = m[key]
    for m in sync["measurements"]:
        for key in ["seconds", "allocated_bytes", "queries", "read_rows", "read_bytes", "max_query_memory_bytes"]:
            values[f"sync/{m['connector']}/{m['scenario']}/{key}"] = m[key]
    for index, name in enumerate(["initial", "restart", "steady"]):
        for key in ["seconds", "heap_bytes_after_gc", "process_peak_rss_bytes"]:
            values[f"soak/{name}/{key}"] = soak["waves"][index][key]
    wave_keys = ["seconds", "heap_bytes_after_gc", "process_peak_rss_bytes"]
    for wave in soak["waves"]:
        if any(not isinstance(wave[k], (int, float)) or not math.isfinite(wave[k]) or wave[k] < 0 for k in wave_keys):
            raise ValueError(f"{root}: invalid sustained wave measurement")
    steady = soak["waves"][2:]
    values["soak/sustained/median_wave_seconds"] = statistics.median(w["seconds"] for w in steady)
    values["soak/sustained/max_wave_seconds"] = max(w["seconds"] for w in steady)
    for key in ["heap_bytes_after_gc", "process_peak_rss_bytes"]:
        values[f"soak/all_waves/max_{key}"] = max(w[key] for w in soak["waves"])
    values["soak/all_waves/final_heap_bytes_after_gc"] = soak["waves"][-1]["heap_bytes_after_gc"]
    for name, latency in soak["reads"].items():
        for key in ["p50_seconds", "p95_seconds", "p99_seconds", "max_seconds"]:
            values[f"reads/{name}/{key}"] = latency[key]
    if any(not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0 for v in values.values()):
        raise ValueError(f"{root}: invalid numeric measurement")
    if graph["commit"] != soak["commit"]:
        raise ValueError(f"{root}: mixed source revisions")
    return cohort, graph["commit"], values


def summarize(roots):
    if len(roots) < 3 or len(set(map(str, roots))) != len(roots):
        raise ValueError("at least three distinct fresh runs are required")
    runs = [measurements(root) for root in roots]
    run_ids = [read(Path(root) / "storage/environment.json")["run_id"] for root in roots]
    if len(set(run_ids)) != len(roots):
        raise ValueError("reused database run: copied reports are not independent samples")
    cohort, commit, first = runs[0]
    for current, revision, values in runs[1:]:
        if current != cohort or revision != commit or values.keys() != first.keys():
            raise ValueError("run cohort differs: fixture, environment, revision or metric set changed")
    metrics = {}
    for key in first:
        samples = [run[2][key] for run in runs]
        metrics[key] = {"median": statistics.median(samples), "min": min(samples), "max": max(samples), "samples": samples}
    return {"format_version": 1, "cohort": cohort, "commit": commit, "runs": list(map(str, roots)), "run_ids": run_ids, "metrics": metrics}


def compare(baseline, candidate, ratio, enforce):
    if ratio <= 1 or not math.isfinite(ratio):
        raise ValueError("regression ratio must be finite and greater than one")
    if baseline["format_version"] != 1 or candidate["format_version"] != 1:
        raise ValueError("unsupported summary format")
    if baseline["cohort"] != candidate["cohort"]:
        raise ValueError("incomparable cohorts: fixture, toolchain, hardware or limits differ")
    if baseline["metrics"].keys() != candidate["metrics"].keys():
        raise ValueError("incomparable metric sets")
    if enforce and not candidate["cohort"]["environment"]["stable_machine_id"]:
        raise ValueError("strict timing limits require PERF_BASELINE_MACHINE on a dedicated machine")
    changes = []
    for key, before in baseline["metrics"].items():
        after = candidate["metrics"][key]
        for m in [before, after]:
            samples = m["samples"]
            if (len(samples) < 3 or any(not math.isfinite(v) or v < 0 for v in samples)
                    or m["median"] != statistics.median(samples) or m["min"] != min(samples) or m["max"] != max(samples)):
                raise ValueError("invalid or insufficient baseline samples")
        # Require a median regression AND non-overlapping measured ranges.
        # Shared-runner reports remain informational even when this is true.
        regression = after["median"] > before["median"] * ratio and after["min"] > before["max"]
        changes.append({"metric": key, "before": before["median"], "after": after["median"],
                        "ratio": after["median"] / before["median"] if before["median"] else None,
                        "regression": regression})
    return {"format_version": 1, "enforced": enforce, "baseline_commit": baseline["commit"],
            "candidate_commit": candidate["commit"], "regressions": [c for c in changes if c["regression"]], "changes": changes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    env = commands.add_parser("environment")
    env.add_argument("postgres")
    env.add_argument("clickhouse")
    summary = commands.add_parser("summarize")
    summary.add_argument("runs", nargs="+")
    comparison = commands.add_parser("compare")
    comparison.add_argument("baseline")
    comparison.add_argument("candidate")
    comparison.add_argument("--ratio", type=float, default=1.25)
    comparison.add_argument("--enforce", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "environment":
            result = environment(args.postgres, args.clickhouse)
        elif args.command == "summarize":
            result = summarize(args.runs)
        else:
            result = compare(read(args.baseline), read(args.candidate), args.ratio, args.enforce)
        print(json.dumps(result, indent=2, allow_nan=False))
        return 1 if result.get("enforced") and result["regressions"] else 0
    except (ValueError, KeyError, OSError, TypeError) as exc:
        print(f"benchmark comparison refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
