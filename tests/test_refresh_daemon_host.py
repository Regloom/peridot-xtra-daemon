"""Resident refresh daemon, HOST fake LOC + fake curl only (no modem/network)."""
import os
from pathlib import Path
import signal
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
CURL = os.environ.get("XTRA_CURL_INCLUDE")
HAS_CURL = (Path(CURL, "curl/curl.h").is_file() if CURL else
            bool(shutil.which("pkg-config") and subprocess.run(
                ["pkg-config", "--exists", "libcurl"], check=False).returncode == 0))


@unittest.skipUnless(HAS_CURL, "curl headers absent (set XTRA_CURL_INCLUDE if needed)")
class RefreshDaemonHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.makedirs("/tmp/opencode", exist_ok=True)
        cls.tmp = tempfile.TemporaryDirectory(prefix="refresh-daemon-", dir="/tmp/opencode")
        cls.dir = Path(cls.tmp.name)
        cls.flags = ["c++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread", "-I", str(ROOT / "src")]
        cls.flags += ["-I", CURL] if CURL else subprocess.check_output(
            ["pkg-config", "--cflags", "libcurl"], text=True).split()
        subprocess.run(cls.flags + ["-DXTRA_DAEMON_HOST_TEST", "-DXTRA_HOST_HTTPS_ADAPTER",
                                    str(ROOT / "src/xtra_refresh_daemon.cpp"), str(ROOT / "src/https_download_host.cpp"),
                                    str(ROOT / "tests/mock_curl.cpp"), "-ldl", "-o", str(cls.dir / "daemon")], check=True)
        subprocess.run(cls.flags + ["-shared", "-fPIC", str(ROOT / "tests/mock_daemon_loc.cpp"),
                                    "-o", str(cls.dir / "fake.so")], check=True)

    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(dir=self.dir))
        self.state = self.case / "state"
        self.trace = self.case / "trace"

    def run_daemon(self, script, seconds, args=(), **env):
        self.case = Path(tempfile.mkdtemp(dir=self.dir))  # fresh trace + state per run
        self.state = self.case / "state"
        self.trace = self.case / "trace"
        if env.pop("MOCK_PRESEED_CORRUPT", None):
            self.state.mkdir(); (self.state / "state").write_text("garbage\n")
        if env.pop("MOCK_STATE_AS_FILE", None):
            self.state.write_text("not a directory\n")  # state can never be persisted
        environment = dict(os.environ, MOCK_DAEMON_SCRIPT=script, MOCK_DAEMON_TRACE=str(self.trace), **env)
        p = subprocess.Popen([str(self.dir / "daemon"), str(self.dir / "fake.so"), str(self.state), *args],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
        time.sleep(seconds)
        cpu = self.cpu_ticks(p.pid)
        p.send_signal(signal.SIGTERM)
        out, err = p.communicate(timeout=10)
        self.assertEqual(p.returncode, 0, err)
        self.assertEqual(out, "")
        self.assertNotIn("PRIVATE_SERVER_URL", err)
        last = err.splitlines()[-1]
        self.assertTrue("stop" in last or last.endswith(": disabled"), last)  # disabled = exit 0 before any client
        lines = self.trace.read_text().splitlines() if self.trace.exists() else []
        return err.splitlines(), lines, cpu

    @staticmethod
    def cpu_ticks(pid):
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return int(fields[11]) + int(fields[12])  # utime + stime (clock ticks)

    def outcomes(self, log):
        return [l for l in log if l.startswith(("cycle ", "event "))]

    def test_event_download_and_strict_transfer(self):
        log, trace, _ = self.run_daemon("event@300", 1.5)
        self.assertEqual(trace[0], "open mask=32")
        sends = [l for l in trace if l.startswith("send")]
        self.assertEqual(sends, ["send part=1/3 len=1024 size=3000 format=1 fileinfo=0",
                                 "send part=2/3 len=1024 size=3000 format=1 fileinfo=0",
                                 "send part=3/3 len=952 size=3000 format=1 fileinfo=0"])
        self.assertTrue(any(l.startswith("cycle accepted bytes=3000") and "parts=3 mask=0x3f" in l for l in log), log)
        self.assertEqual(trace[-1], "close")
        self.assertTrue((self.state / "state").read_text().startswith("v1 "))

    def test_idle_daemon_uses_no_cpu(self):
        _, trace, cpu = self.run_daemon("", 3.0)
        self.assertEqual(trace, ["open mask=32", "close"])
        self.assertLessEqual(cpu, 2, "idle daemon should sleep, not poll")  # ticks are 10 ms

    def test_success_gap_defers_then_allows(self):
        log, trace, _ = self.run_daemon("event@300,event@900,event@2200", 3.0)
        self.assertEqual(self.outcomes(log)[0].split()[1], "accepted")
        self.assertIn("event deferred reason=recent_success", log)
        self.assertEqual(sum(l.startswith("cycle accepted") for l in log), 2)

    def test_failure_backoff_and_daily_cap(self):
        log, trace, _ = self.run_daemon("event@300,event@500,event@800,event@1700,event@3100", 3.6,
                                        MOCK_CURL_MODE="tls_failure")
        results = self.outcomes(log)
        self.assertEqual(results, ["cycle failed reason=https_transport_failed http=0 bytes=0 acked=0",
                                   "event deferred reason=backoff",
                                   "cycle failed reason=https_transport_failed http=0 bytes=0 acked=0",
                                   "cycle failed reason=https_transport_failed http=0 bytes=0 acked=0",
                                   "event deferred reason=daily_cap"])
        self.assertFalse(any(l.startswith("send") for l in trace))

    def test_modem_rejection_and_silence_stop_without_retry(self):
        log, trace, _ = self.run_daemon("event@300", 1.5, MOCK_DAEMON_ACK="reject2")
        self.assertIn("cycle failed reason=version_check_failure http=200 bytes=3000 acked=1", log)
        self.assertEqual(sum(l.startswith("send") for l in trace), 2)
        log, trace, _ = self.run_daemon("event@300", 1.5, MOCK_DAEMON_ACK="silent")
        self.assertIn("cycle failed reason=indication_timeout http=200 bytes=3000 acked=0", log)
        self.assertEqual(sum(l.startswith("send") for l in trace), 1)
        log, trace, _ = self.run_daemon("event@300", 1.5, MOCK_DAEMON_ACK="nomask")
        self.assertIn("cycle failed reason=acceptance_not_confirmed http=200 bytes=3000 acked=3", log)

    def test_unreviewed_profiles_are_ignored_without_download(self):
        for profile in ("navic", "mask2"):
            log, trace, _ = self.run_daemon("event@300", 1.0, MOCK_EVENT_PROFILE=profile)
            self.assertIn("event ignored reason=unreviewed_event_profile", log)
            self.assertFalse(any(l.startswith("send") for l in trace))
            self.assertFalse((self.state / "state").exists())

    def test_zero_or_bad_limits_are_ignored(self):
        log, _, _ = self.run_daemon("event@300", 1.0, MOCK_MAX_PART="0")
        self.assertIn("event ignored reason=zero_limits", log)
        log, _, _ = self.run_daemon("event@300", 1.0, MOCK_MAX_FILE="2999")
        self.assertIn("cycle failed reason=body_exceeds_event_limits http=0 bytes=0 acked=0", log)  # body over event cap

    def test_burst_of_events_yields_one_cycle(self):
        log, trace, _ = self.run_daemon("event@300,event@301,event@302", 1.5)
        self.assertEqual(sum(l.startswith("cycle ") for l in log), 1)
        self.assertEqual(sum(l.startswith("send") for l in trace), 3)

    def test_service_loss_reopens_and_keeps_serving(self):
        log, trace, _ = self.run_daemon("loss@300,event@900", 2.0)
        self.assertEqual(trace[:4], ["open mask=32", "loss", "close", "open mask=32"])
        self.assertTrue(any(l.startswith("cycle accepted") for l in log), log)

    def test_open_failures_retry_with_backoff(self):
        log, trace, _ = self.run_daemon("event@1200", 2.0, MOCK_OPEN_FAIL="2")
        self.assertEqual(trace[:3], ["open mask=32"] * 3)
        self.assertEqual(sum(l.startswith("LOC open failed") for l in log), 2)
        self.assertTrue(any(l.startswith("cycle accepted") for l in log), log)

    def test_corrupt_state_is_conservative(self):
        log, trace, _ = self.run_daemon("event@200", 0.8, MOCK_PRESEED_CORRUPT="1")
        self.assertIn("state corrupt: conservative back-off", log)
        self.assertIn("event deferred reason=backoff", log)
        self.assertFalse(any(l.startswith("send") for l in trace))

    def test_unwritable_state_fails_closed_without_download(self):
        log, trace, _ = self.run_daemon("event@300,event@600", 1.2, MOCK_STATE_AS_FILE="1")
        self.assertEqual(self.outcomes(log), ["event deferred reason=state_unwritable"] * 2)
        self.assertFalse(any(l.startswith("send") for l in trace))
        self.assertFalse(any("https" in l or l.startswith("cycle ") for l in log), log)

    def test_idl_minor_follows_reviewed_library(self):
        log, trace, _ = self.run_daemon("event@300", 1.2, args=("170",), MOCK_IDL_MINOR="170")
        self.assertIn("vendor LOC library reviewed idl_minor=170", log)
        self.assertTrue(any(l.startswith("cycle accepted") for l in log), log)
        log, trace, _ = self.run_daemon("event@300", 0.6, args=("161",), MOCK_IDL_MINOR="170")
        self.assertIn("unsupported LOC layout: disabled", log)
        self.assertEqual(trace, [])  # never opened a client

    def test_reviewed_library_table_is_pinned(self):
        text = (ROOT / "src/xtra_refresh_daemon.cpp").read_text()
        self.assertIn('#include "xtra_loc_profile.h"', text)
        self.assertIn('xtra::compat::kReviewedLoc', text)
        self.assertIn('if (!minor) { log("vendor LOC library hash mismatch: disabled"); return 0; }', text)
        self.assertNotIn('aad764ce43e477cbb', text)
        self.assertNotIn('9e55b90b1a0c2e31', text)
        self.assertEqual(text.count("service(2, minor, 6)"), 1)

    def test_selectors_and_no_forbidden_paths(self):
        src = ROOT / "src/xtra_refresh_daemon.cpp"
        for defs in ([], ["-DXTRA_ANDROID_REFRESH_DAEMON"], ["-DXTRA_ANDROID_REFRESH_DAEMON", "-DXTRA_DAEMON_HOST_TEST"]):
            p = subprocess.run(self.flags + ["-fsyntax-only"] + defs + [str(src)], capture_output=True, text=True)
            self.assertNotEqual(p.returncode, 0, defs)
        text = src.read_text()
        for forbidden in ("fork(", "/proc", "0x36", "0xb0", "app_process", "kill("):
            self.assertNotIn(forbidden, text.lower() if forbidden.startswith("0x") else text, forbidden)
        self.assertEqual(text.count("loc.send("), 1)


if __name__ == "__main__":
    unittest.main()
