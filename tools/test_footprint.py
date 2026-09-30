# SPDX-License-Identifier: MIT
# python3 -m unittest discover -s tools -p 'test_*.py'
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import footprint as fp  # noqa: E402

MB = fp.MB


def samples(*points):
    """(seconds, CPU µs, memory.current, resident) tuples as samples."""
    return [{"t": t, "usage_usec": u, "current": c, "resident": r} for t, u, c, r in points]


class Footprint(unittest.TestCase):
    def test_reads_cgroup_files(self):
        stat = fp.parse_keyed("anon 1503232\nfile 24301568\nactive_file 20000000\ninactive_file 4000000\nbogus x\n")
        self.assertEqual(stat["anon"], 1503232)
        self.assertNotIn("bogus", stat)
        # journalctl's page cache is reclaimable; the rest is not.
        self.assertEqual(fp.unreclaimable(27090944, stat), 3090944)
        self.assertEqual(fp.unreclaimable(100, {"active_file": 500}), 0)

    def test_cpu_is_percent_of_one_core(self):
        self.assertAlmostEqual(fp.cpu_percent(0, 20_000, 0, 1), 2.0)
        self.assertAlmostEqual(fp.cpu_percent(0, 1_500_000, 10, 11), 150.0)
        self.assertEqual(fp.cpu_percent(0, 10, 5, 5), 0.0)

    def test_summarizes_a_window(self):
        s = fp.summarize(samples((0, 0, 30 * MB, 3 * MB), (1, 5_000, 31 * MB, 4 * MB), (2, 30_000, 29 * MB, 3 * MB)))
        self.assertAlmostEqual(s["cpu_mean"], 1.5)
        self.assertAlmostEqual(s["cpu_max"], 2.5)
        self.assertEqual((s["resident_peak"], s["current_peak"]), (4 * MB, 31 * MB))
        self.assertIsNone(fp.summarize(samples((0, 0, 0, 0))))

    def test_judges_idle_cpu_and_peak_memory(self):
        quiet = {"cpu_mean": 0.1, "cpu_max": 0.4, "resident_peak": 3 * MB, "current_peak": 27 * MB}
        busy = {"cpu_mean": 9.0, "cpu_max": 15.0, "resident_peak": 45 * MB, "current_peak": 60 * MB}
        lines = fp.verdicts({"daemon": {"idle": quiet, "load": busy}}, 2, 40)
        self.assertEqual([v for v, _ in lines], ["PASS", "INFO", "FAIL"])
        self.assertIn("45.0 MB without page cache", lines[2][1])
        lines = fp.verdicts({"helper": {"idle": busy}, "daemon": {"error": "x is failed, not active"}}, 2, 40)
        self.assertEqual([v for v, _ in lines], ["FAIL", "FAIL", "FAIL"])
        self.assertEqual(lines[2][1], "daemon: x is failed, not active")

    def test_load_is_read_only(self):
        for method in fp.LOAD_METHODS:
            self.assertFalse(any(w in method for w in ("ADD", "REMOVE", "SET", "MOUNT", "PANIC", "KILL", "REFRESH",
                                                       "DECIDE", "MUTE", "RUN")), method)
        self.assertNotIn("firewall", fp.LOAD_TOPICS)


if __name__ == "__main__":
    unittest.main()
