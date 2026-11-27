import os
import pathlib
import select
import signal
import subprocess
import sys
import unittest


class BoundedCommandTest(unittest.TestCase):
    runner = pathlib.Path(__file__).with_name("run_bounded.py")

    def run_command(self, seconds, program, *arguments):
        return subprocess.run(
            [sys.executable, str(self.runner), str(seconds), sys.executable, "-c", program, *arguments],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_preserves_exit_and_output(self):
        result = self.run_command(5, "print('measured'); raise SystemExit(7)")
        self.assertEqual(7, result.returncode)
        self.assertEqual("measured\n", result.stdout)

    def test_stops_hung_command_without_disclosing_arguments(self):
        result = self.run_command(
            0.2,
            "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(0.6)",
            "fixture-password-must-not-be-logged",
        )
        self.assertEqual(124, result.returncode)
        self.assertIn("exceeded", result.stderr)
        self.assertNotIn("fixture-password", result.stderr)

    def test_cleanup_signal_stops_a_child_ignoring_term(self):
        command = "import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print(os.getpid(),flush=True); time.sleep(100)"
        child_pid = None
        with subprocess.Popen(
            [sys.executable, str(self.runner), "30", sys.executable, "-c", command],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ) as wrapper:
            try:
                self.assertTrue(select.select([wrapper.stdout], [], [], 5)[0], "child did not start")
                child_pid = int(wrapper.stdout.readline())
                wrapper.terminate()
                wrapper.wait(timeout=8)
                self.assertEqual(143, wrapper.returncode)
                with self.assertRaises(ProcessLookupError):
                    os.kill(child_pid, 0)
            finally:
                if child_pid is not None:
                    try:
                        os.killpg(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if wrapper.poll() is None:
                    wrapper.kill()
                    wrapper.wait(timeout=2)


if __name__ == "__main__":
    unittest.main()
