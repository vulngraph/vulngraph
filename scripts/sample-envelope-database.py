#!/usr/bin/env python3
"""Sample parts, active merges and mutation backlog for an isolated fixture.

This observer issues one small system-table query every two seconds. Its CPU and
memory are included in the database container's sampled totals.
"""

import datetime
import json
import signal
import subprocess
import sys
import threading
import time


def main():
    stopped = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    query = """
SELECT 'parts' AS kind, table, count() AS entries, sum(rows) AS rows,
 sum(bytes_on_disk) AS bytes FROM system.parts
 WHERE active AND database=currentDatabase() GROUP BY table
UNION ALL
SELECT 'mutations', table, countIf(NOT is_done), sum(parts_to_do), toUInt64(0)
 FROM system.mutations WHERE database=currentDatabase() GROUP BY table
UNION ALL
SELECT 'merges', table, count(), sum(rows_read), sum(memory_usage)
 FROM system.merges WHERE database=currentDatabase() GROUP BY table
FORMAT JSONEachRow
"""
    command = [
        "docker", "exec", sys.argv[1], "sh", "-c",
        'exec clickhouse-client --user bench --password "$CLICKHOUSE_PASSWORD" --database "$1" --query "$2"',
        "sh", sys.argv[2], query,
    ]
    while not stopped.is_set():
        start = time.monotonic()
        record = {"started_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=True)
            record["rows"] = [json.loads(line) for line in result.stdout.splitlines() if line]
        except (subprocess.SubprocessError, ValueError) as error:
            record["error"] = str(error)
            if isinstance(error, subprocess.CalledProcessError):
                record["stderr"] = error.stderr
        record["elapsed_seconds"] = time.monotonic() - start
        print(json.dumps(record), flush=True)
        if "error" in record:
            return 1
        stopped.wait(max(0, 2 - record["elapsed_seconds"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
