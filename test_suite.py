# Copyright 2025 DJAM Foundation / IA Commune Algeria
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Earthflow Écosystème — Test Suite v1.0
Tests for: audit, rules/engine, stop/controller, stop/exceptions (base)
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from core.audit import AuditLog, AuditEntry
from rules.engine import RulesEngine, RuleMatch
from stop.controller import StopController
from stop.exceptions import (EarthflowException, StopConditionTriggered,
                              PolicyViolation, AuthenticationError)


class TestAuditLog(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()

    def test_record_creates_entry(self):
        e = self.log.record(tenant_id="t1", status="ALLOW", model="gpt-4",
                            rules_evaluated=5, rules_triggered=[], metadata={}, latency_ms=10)
        self.assertIsInstance(e, AuditEntry)
        self.assertTrue(e.audit_id.startswith("aud_"))

    def test_record_hashes_prompt(self):
        e = self.log.record(tenant_id="t1", status="BLOCK", model="gpt-4",
                            rules_evaluated=1, rules_triggered=["r1"],
                            metadata={}, latency_ms=5, prompt="secret content")
        self.assertIsNone(getattr(e, "prompt", None))
        self.assertTrue(e.prompt_hash.startswith("sha256:"))

    def test_record_no_prompt_hash_is_none(self):
        e = self.log.record(tenant_id="t1", status="ALLOW", model="gpt-4",
                            rules_evaluated=0, rules_triggered=[], metadata={}, latency_ms=3)
        self.assertIsNone(e.prompt_hash)

    def test_query_filters_by_tenant(self):
        self.log.record(tenant_id="t1", status="ALLOW", model="m", rules_evaluated=0,
                        rules_triggered=[], metadata={}, latency_ms=1)
        self.log.record(tenant_id="t2", status="BLOCK", model="m", rules_evaluated=1,
                        rules_triggered=["r"], metadata={}, latency_ms=2)
        results = self.log.query(tenant_id="t1")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].tenant_id, "t1")

    def test_query_filters_by_status(self):
        for s in ["ALLOW", "BLOCK", "ALLOW"]:
            self.log.record(tenant_id="t1", status=s, model="m",
                            rules_evaluated=0, rules_triggered=[], metadata={}, latency_ms=1)
        results = self.log.query(status="BLOCK")
        self.assertEqual(len(results), 1)

    def test_stats_block_rate(self):
        for s in ["ALLOW", "ALLOW", "BLOCK", "BLOCK"]:
            self.log.record(tenant_id="t1", status=s, model="m",
                            rules_evaluated=0, rules_triggered=[], metadata={}, latency_ms=1)
        stats = self.log.stats(tenant_id="t1")
        self.assertAlmostEqual(stats["block_rate"], 0.5)

    def test_to_dict(self):
        e = self.log.record(tenant_id="t1", status="WARN", model="gpt-4",
                            rules_evaluated=3, rules_triggered=[], metadata={}, latency_ms=7)
        d = e.to_dict()
        self.assertIn("audit_id", d)
        self.assertIn("timestamp", d)
        self.assertEqual(d["schema_version"], 2)


class TestRulesEngine(unittest.TestCase):
    def _make_engine(self, rules=None):
        default = [
            {"id": "r1", "name": "Block SSN", "active": True, "priority": 90,
             "condition": {"operator": "regex", "value": r"\d{3}-\d{2}-\d{4}"},
             "action": "BLOCK"},
            {"id": "r2", "name": "Warn long prompt", "active": True, "priority": 20,
             "condition": {"operator": "length_gt", "value": 100},
             "action": "WARN"},
            {"id": "r3", "name": "Contains trigger", "active": True, "priority": 50,
             "condition": {"operator": "contains", "value": "forbidden"},
             "action": "BLOCK"},
        ]
        return RulesEngine(rules or default)

    def test_allow_clean_prompt(self):
        e = self._make_engine()
        r = e.evaluate("What is the weather today?")
        self.assertEqual(r["status"], "ALLOW")
        self.assertEqual(r["rules_triggered"], [])

    def test_block_on_ssn(self):
        e = self._make_engine()
        r = e.evaluate("Patient SSN is 123-45-6789")
        self.assertEqual(r["status"], "BLOCK")
        self.assertIn("r1", r["rules_triggered"])

    def test_warn_on_long_prompt(self):
        e = self._make_engine()
        r = e.evaluate("x " * 60)  # 120 chars
        self.assertEqual(r["status"], "WARN")

    def test_block_takes_priority_over_warn(self):
        e = self._make_engine()
        r = e.evaluate("forbidden content " + "x " * 60)
        self.assertEqual(r["status"], "BLOCK")

    def test_inactive_rule_not_evaluated(self):
        rules = [{"id": "r_inactive", "name": "Inactive", "active": False,
                  "priority": 99, "condition": {"operator": "contains", "value": "hello"},
                  "action": "BLOCK"}]
        e = RulesEngine(rules)
        r = e.evaluate("hello world")
        self.assertEqual(r["status"], "ALLOW")

    def test_contains_operator(self):
        e = RulesEngine([{"id": "r", "name": "Test", "active": True, "priority": 50,
                          "condition": {"operator": "contains", "value": "test_word"},
                          "action": "WARN"}])
        self.assertEqual(e.evaluate("no match")["status"], "ALLOW")
        self.assertEqual(e.evaluate("contains test_word here")["status"], "WARN")

    def test_not_contains_operator(self):
        e = RulesEngine([{"id": "r", "name": "T", "active": True, "priority": 50,
                          "condition": {"operator": "not_contains", "value": "disclaimer"},
                          "action": "WARN"}])
        self.assertEqual(e.evaluate("no disclaimer here")["status"], "ALLOW")
        self.assertEqual(e.evaluate("missing required field")["status"], "WARN")

    def test_length_lt_operator(self):
        e = RulesEngine([{"id": "r", "name": "T", "active": True, "priority": 50,
                          "condition": {"operator": "length_lt", "value": 5},
                          "action": "WARN"}])
        self.assertEqual(e.evaluate("hi")["status"], "WARN")
        self.assertEqual(e.evaluate("hello world")["status"], "ALLOW")

    def test_rules_evaluated_count(self):
        e = self._make_engine()
        r = e.evaluate("clean prompt")
        self.assertEqual(r["rules_evaluated"], 3)


class TestStopController(unittest.TestCase):
    def _make_controller(self):
        rules = [
            {"id": "block_r", "name": "Block rule", "active": True, "priority": 90,
             "condition": {"operator": "contains", "value": "BLOCK_ME"},
             "action": "BLOCK"},
            {"id": "warn_r", "name": "Warn rule", "active": True, "priority": 40,
             "condition": {"operator": "contains", "value": "WARN_ME"},
             "action": "WARN"},
        ]
        log = AuditLog()
        engine = RulesEngine(rules)
        return StopController(engine, log), log

    def test_allow_passes_through(self):
        ctrl, _ = self._make_controller()
        result = ctrl.check("Safe prompt", tenant_id="t1")
        self.assertEqual(result["status"], "ALLOW")

    def test_block_raises_exception(self):
        ctrl, _ = self._make_controller()
        with self.assertRaises(StopConditionTriggered):
            ctrl.check("Please BLOCK_ME now", tenant_id="t1")

    def test_warn_passes_through(self):
        ctrl, _ = self._make_controller()
        result = ctrl.check("Please WARN_ME now", tenant_id="t1")
        self.assertEqual(result["status"], "WARN")

    def test_stop_condition_contains_rule_id(self):
        ctrl, _ = self._make_controller()
        try:
            ctrl.check("BLOCK_ME", tenant_id="t1")
            self.fail("Should have raised")
        except StopConditionTriggered as e:
            self.assertEqual(e.rule_id, "block_r")

    def test_audit_log_records_all_requests(self):
        ctrl, log = self._make_controller()
        ctrl.check("Safe", tenant_id="t1")
        try:
            ctrl.check("BLOCK_ME", tenant_id="t1")
        except StopConditionTriggered:
            pass
        entries = log.query(tenant_id="t1")
        self.assertEqual(len(entries), 2)


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in [TestAuditLog, TestRulesEngine, TestStopController]:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    passed = result.testsRun - len(result.failures) - len(result.errors)
    print(f"\n{'='*50}\n  {passed}/{result.testsRun} tests passed "
          + ("✓" if not result.failures and not result.errors else "✗") + f"\n{'='*50}")
