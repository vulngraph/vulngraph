#!/usr/bin/env python3
"""Bound a benchmark subprocess and its children without logging credentials."""

import os
import signal
import subprocess
import sys


class Interrupted(Exception):
    pass


def stop(child):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            continue
        # The leader may exit while another member still ignores SIGTERM.
        # Always deliver SIGKILL to the group before leaving timeout cleanup.


def main():
    seconds = float(sys.argv[1])
    if seconds <= 0 or len(sys.argv) < 3:
        raise ValueError("expected positive timeout and command")
    child = subprocess.Popen(sys.argv[2:], start_new_session=True)

    def interrupted(signum, _frame):
        # Unwind Popen.wait before waiting again: a signal can arrive while its
        # internal waitpid lock is held.
        raise Interrupted(signum)

    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        return child.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        # Arguments may contain disposable database passwords. Do not print them.
        print(f"benchmark command exceeded {seconds:g}s", file=sys.stderr)
        result = 124
    except Interrupted as interruption:
        result = 128 + interruption.args[0]
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    stop(child)
    return result


if __name__ == "__main__":
    sys.exit(main())
