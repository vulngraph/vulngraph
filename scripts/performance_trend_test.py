import copy
import json
from pathlib import Path
import tempfile
import unittest

import performance_trend as trend


class TrendContract(unittest.TestCase):
    def fixture(self, name):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "storage").mkdir()
        def write(path, value):
            (root / path).write_text(json.dumps(value))
        write("storage/environment.json", {"working_tree_clean": True, "run_id": name, "stable_machine_id": ""})
        (root / "environment.txt").write_text("request_delay_ms=0\nfixture\n")
        costs = {k: 1 for k in ["seconds", "read_rows", "read_bytes", "max_query_memory_bytes", "process_peak_rss_bytes", "allocated_bytes", "queries"]}
        scenarios = ["initial_build", "unchanged_1", "unchanged_2", "finding_update", "topology_update_1pct", "unchanged_after_update"]
        write("storage/report.json", {"passed": True, "profile": "smoke", "fixture_version": 1,
              "go_version": "test", "gomaxprocs": 4, "ladybug_buffer_mb": 256, "commit": "fixture",
              "measurements": [dict(costs, scenario=s) for s in scenarios]})
        connectors = ["aws", "gcp", "azure", "kubernetes", "github", "okta", "google_workspace", "demo"]
        sync = []
        for c in connectors:
            for s in ["initial", "unchanged", "change_1pct", "unchanged_after", "partial"]:
                sync.append(dict(costs, connector=c, scenario=s, verified_assets=100, verified_edges=100))
            write(f"{c}-100.json", [dict(connector=c, size=100, scope="fixture", assets=100, edges=100,
                  partial=False, duplicate_asset_rows=0, run=i, seconds=1, allocated_bytes=1, requests=1) for i in range(3)])
        write("sync.json", {"passed": True, "fixture_version": 2, "measurements": sync})
        write("aws_org.json", [dict(accounts=100, phase=p, seconds=1) for p in ["initial", "unchanged", "unchanged_again"]])
        write("soak.json", {"passed": True, "fixture_version": 1, "commit": "fixture",
              "verified_assets": 800, "verified_edges": 800, "graph_rebuilt_after_restart": True, "retried_jobs": 2,
              "waves": [dict(seconds=1, heap_bytes_after_gc=1, process_peak_rss_bytes=1) for _ in range(3)],
              "reads": {k: dict(count=1, errors=0, p50_seconds=1, p95_seconds=1, p99_seconds=1, max_seconds=1)
                        for k in ["inventory", "findings", "graph"]}})
        return root

    def test_complete_reports_and_copied_run_rejection(self):
        roots = [self.fixture(str(i)) for i in range(3)]
        summary = trend.summarize(roots)
        self.assertIn("collect/aws/100/seconds", summary["metrics"])
        self.assertIn("sync/kubernetes/initial/seconds", summary["metrics"])
        path = roots[1] / "storage/environment.json"
        data = trend.read(path)
        data["run_id"] = "0"
        path.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            trend.summarize(roots)

    def test_refuses_dirty_or_incomplete_reports(self):
        for kind in ["dirty", "duplicate_sync", "failed_read", "missing_collection"]:
            with self.subTest(kind=kind):
                root = self.fixture(kind)
                if kind == "missing_collection":
                    (root / "aws-100.json").unlink()
                else:
                    path = root / {"dirty": "storage/environment.json", "duplicate_sync": "sync.json", "failed_read": "soak.json"}[kind]
                    data = trend.read(path)
                    if kind == "dirty":
                        data["working_tree_clean"] = False
                    elif kind == "duplicate_sync":
                        data["measurements"][0] = data["measurements"][1]
                    else:
                        data["reads"]["graph"]["errors"] = 1
                    path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    trend.measurements(root)

    def summary(self, samples, machine="bench-1"):
        import statistics
        return {"format_version": 1, "commit": "fixture", "cohort": {"environment": {"stable_machine_id": machine}},
                "metrics": {"latency": {"median": statistics.median(samples), "min": min(samples), "max": max(samples), "samples": samples}}}

    def test_detects_repeatable_regression(self):
        result = trend.compare(self.summary([1, 1.1, 1.2]), self.summary([2, 2.1, 2.2]), 1.25, True)
        self.assertEqual(len(result["regressions"]), 1)

    def test_noise_is_not_a_regression(self):
        result = trend.compare(self.summary([1, 1.1, 2]), self.summary([1.5, 1.6, 1.8]), 1.25, True)
        self.assertEqual(result["regressions"], [])

    def test_rejects_incomparable_machine(self):
        with self.assertRaises(ValueError):
            trend.compare(self.summary([1, 1, 1]), self.summary([1, 1, 1], "another"), 1.25, True)

    def test_shared_runner_cannot_enforce_timings(self):
        with self.assertRaises(ValueError):
            trend.compare(self.summary([1, 1, 1], ""), self.summary([1, 1, 1], ""), 1.25, True)

    def test_rejects_fabricated_median_or_missing_samples(self):
        baseline = self.summary([1, 1, 1])
        for values in ([1, 1], [float("nan"), 1, 1], [-1, 1, 1]):
            candidate = copy.deepcopy(baseline)
            candidate["metrics"]["latency"]["samples"] = values
            with self.assertRaises(ValueError):
                trend.compare(baseline, candidate, 1.25, True)
        for key in ["median", "min", "max"]:
            candidate = copy.deepcopy(baseline)
            candidate["metrics"]["latency"][key] = 999
            with self.assertRaises(ValueError):
                trend.compare(baseline, candidate, 1.25, True)

    def test_rejects_single_run(self):
        with self.assertRaises(ValueError):
            trend.summarize(["unused"])


if __name__ == "__main__":
    unittest.main()
