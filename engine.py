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

"""rules/engine.py — Rule evaluation engine."""
import re
from typing import List, Optional


class RuleMatch:
    def __init__(self, rule_id: str, name: str, action: str, matched_field: str):
        self.rule_id = rule_id
        self.name = name
        self.action = action
        self.matched_field = matched_field

    def to_dict(self) -> dict:
        return {"rule_id": self.rule_id, "name": self.name,
                "action": self.action, "matched_field": self.matched_field}


class RulesEngine:
    PRIORITY = {"BLOCK": 4, "ESCALATE": 3, "REDACT": 2, "WARN": 1, "ALLOW": 0}

    def __init__(self, rules: list = None):
        self._rules = sorted(rules or [],
                             key=lambda r: r.get("priority", 50), reverse=True)

    def load_rules(self, rules: list):
        self._rules = sorted(rules, key=lambda r: r.get("priority", 50), reverse=True)

    def evaluate(self, prompt: str, metadata: dict = None) -> dict:
        metadata = metadata or {}
        matches: List[RuleMatch] = []

        for rule in self._rules:
            if not rule.get("active", True):
                continue
            match = self._test_rule(rule, prompt, metadata)
            if match:
                matches.append(match)

        if not matches:
            return {"status": "ALLOW", "rules_evaluated": len(self._rules),
                    "rules_triggered": [], "matches": []}

        top = max(matches, key=lambda m: self.PRIORITY.get(m.action, 0))
        return {
            "status": top.action,
            "rules_evaluated": len(self._rules),
            "rules_triggered": [m.rule_id for m in matches],
            "matches": [m.to_dict() for m in matches],
        }

    def _test_rule(self, rule: dict, prompt: str, metadata: dict) -> Optional[RuleMatch]:
        cond = rule.get("condition", {})
        if not isinstance(cond, dict):
            return None
        op = cond.get("operator", "contains")
        value = cond.get("value", "")
        target_field = cond.get("target", "prompt")
        case_sensitive = cond.get("case_sensitive", False)

        target = prompt if target_field == "prompt" else str(metadata.get(target_field, ""))
        text = target if case_sensitive else target.lower()
        val = value if case_sensitive else (value.lower() if isinstance(value, str) else value)

        matched = False
        if op == "contains":
            matched = val in text
        elif op == "not_contains":
            matched = val not in text
        elif op == "regex":
            matched = bool(re.search(value, target,
                                     0 if case_sensitive else re.IGNORECASE))
        elif op == "equals":
            matched = text == val
        elif op == "not_equals":
            matched = text != val
        elif op == "length_gt":
            matched = len(target) > int(value)
        elif op == "length_lt":
            matched = len(target) < int(value)
        elif op == "threshold":
            try:
                num = float(target)
                op2 = value.get("op", ">")
                thr = float(value.get("value", 0))
                matched = (num > thr if op2 == ">" else
                           num < thr if op2 == "<" else
                           num >= thr if op2 == ">=" else
                           num <= thr if op2 == "<=" else num == thr)
            except (ValueError, TypeError, AttributeError):
                matched = False

        if matched:
            return RuleMatch(rule["id"], rule["name"], rule["action"], target_field)
        return None
