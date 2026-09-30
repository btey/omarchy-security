# SPDX-License-Identifier: MIT
"""Tests for the pure parts of tools/system_check.py (plan task 4.4)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import system_check as sc  # noqa: E402


def chain(family, table, name, hook=None, policy=None):
    c = {"family": family, "table": table, "name": name}
    if hook:
        c.update(type="filter", hook=hook, prio=0, policy=policy)
    return {"chain": c}


UFW = [
    {"table": {"family": "ip", "name": "filter"}},
    chain("ip", "filter", "INPUT", "input", "drop"),
    chain("ip", "filter", "ufw-user-input"),
    {"table": {"family": "ip6", "name": "filter"}},
    chain("ip6", "filter", "INPUT", "input", "drop"),
]
STANDALONE = [
    {"table": {"family": "inet", "name": "omarchy_sec", "comment": "mode=standalone"}},
    chain("inet", "omarchy_sec", "input", "input", "drop"),
]
UFW_TABLE = [
    {"table": {"family": "inet", "name": "omarchy_sec"}},
    chain("inet", "omarchy_sec", "output", "output", "accept"),
]


class RulesetTests(unittest.TestCase):
    def test_modes(self):
        self.assertEqual(sc.nft_mode(UFW), "ufw")
        self.assertEqual(sc.nft_mode(UFW + UFW_TABLE), "ufw")
        self.assertEqual(sc.nft_mode(STANDALONE), "standalone")
        self.assertEqual(sc.nft_mode(UFW + STANDALONE), "both")
        self.assertEqual(sc.nft_mode(UFW_TABLE), "none")
        self.assertEqual(sc.nft_mode([]), "none")

    def test_input_drop(self):
        self.assertEqual(sc.input_drop_families(UFW), {"ip", "ip6"})
        self.assertTrue(sc.protected(sc.input_drop_families(UFW)))
        self.assertTrue(sc.protected(sc.input_drop_families(STANDALONE)))
        self.assertFalse(sc.protected(sc.input_drop_families(UFW_TABLE)))
        ipv4_only = UFW[:3]
        self.assertFalse(sc.protected(sc.input_drop_families(ipv4_only)))
        self.assertTrue(sc.protected(sc.input_drop_families(ipv4_only), need_ip6=False))
        accepting = [chain("ip", "filter", "INPUT", "input", "accept"),
                     chain("ip6", "filter", "INPUT", "input", "accept")]
        self.assertFalse(sc.protected(sc.input_drop_families(accepting)))


class SectionTests(unittest.TestCase):
    def test_every_section_has_a_function(self):
        for name in sc.SECTIONS:
            self.assertTrue(callable(getattr(sc, "section_" + name.replace("-", "_"))), name)

    def test_manual_steps_skip_without_a_person(self):
        ui = sc.Ui(manual=False)
        with self.assertRaises(sc.Skip):
            ui.enter("plug something in")
        with self.assertRaises(sc.Skip):
            ui.ask("did it work?")


if __name__ == "__main__":
    unittest.main()
