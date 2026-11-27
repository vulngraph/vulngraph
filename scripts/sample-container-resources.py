#!/usr/bin/env python3
"""Sample Linux process/cgroup counters without querying the measured database."""

import datetime
import json
import signal
import subprocess
import sys


class Interrupted(Exception):
    pass


def interrupted(signum, _frame):
    raise Interrupted(signum)


def main():
    # One persistent exec avoids starting a new Docker process for every sample.
    command = """while test -r /proc/1/status; do
  echo @sample
  for item in /proc/uptime /proc/1/status /proc/1/stat /proc/1/io /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.peak /sys/fs/cgroup/memory.swap.current /sys/fs/cgroup/memory.swap.max /sys/fs/cgroup/memory.swap.peak /sys/fs/cgroup/memory.swap.events /sys/fs/cgroup/memory.events /sys/fs/cgroup/memory.stat /sys/fs/cgroup/cpu.stat /sys/fs/cgroup/io.stat; do
    echo "@file $item"
    cat "$item" 2>/dev/null || true
  done
  echo @end
  sleep 0.25
done
"""
    with subprocess.Popen(
        ["docker", "exec", sys.argv[1], "sh", "-c", command],
        stdout=subprocess.PIPE,
        text=True,
    ) as child:
        signal.signal(signal.SIGINT, interrupted)
        signal.signal(signal.SIGTERM, interrupted)
        try:
            record, key = {}, None
            for line in child.stdout:
                line = line.rstrip("\n")
                if line == "@sample":
                    record = {"received_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "files": {}}
                    key = None
                elif line.startswith("@file "):
                    key = line[6:]
                    record["files"][key] = []
                elif line == "@end":
                    print(json.dumps(record), flush=True)
                elif key:
                    record["files"][key].append(line)
            return child.wait()
        except Interrupted as interruption:
            return 128 + interruption.args[0]
        finally:
            # Reap the Docker client before this process exits. Otherwise group
            # shutdown can leave an orphan zombie during the parent's kill pass.
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=1)


if __name__ == "__main__":
    sys.exit(main())
