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

"""rules/validator.py — Rule and preset schema validation."""


class ValidationError(Exception):
    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"{field}: {message}")


class RuleValidator:
    REQUIRED_RULE_FIELDS = ["id", "name", "condition", "action"]
    VALID_ACTIONS = ["ALLOW", "BLOCK", "WARN", "REDACT", "ESCALATE"]
    VALID_CONDITIONS = ["contains", "not_contains", "regex", "threshold",
                        "equals", "not_equals", "length_gt", "length_lt"]

    def validate_rule(self, rule: dict) -> list:
        errors = []
        for field in self.REQUIRED_RULE_FIELDS:
            if field not in rule:
                errors.append(ValidationError(field, "required field missing"))

        if "action" in rule and rule["action"] not in self.VALID_ACTIONS:
            errors.append(ValidationError("action",
                f"invalid action '{rule['action']}', must be one of {self.VALID_ACTIONS}"))

        if "condition" in rule:
            cond = rule["condition"]
            if isinstance(cond, dict):
                op = cond.get("operator")
                if op and op not in self.VALID_CONDITIONS:
                    errors.append(ValidationError("condition.operator",
                        f"unknown operator '{op}'"))
                if "value" not in cond:
                    errors.append(ValidationError("condition.value",
                        "condition must have a value"))
            else:
                errors.append(ValidationError("condition", "condition must be a dict"))

        if "priority" in rule:
            try:
                p = int(rule["priority"])
                if not (0 <= p <= 100):
                    errors.append(ValidationError("priority",
                        "priority must be between 0 and 100"))
            except (TypeError, ValueError):
                errors.append(ValidationError("priority", "priority must be an integer"))

        return errors

    def validate_preset(self, preset: dict) -> list:
        errors = []
        if "rules" not in preset:
            errors.append(ValidationError("rules", "preset must contain a 'rules' list"))
            return errors
        for i, rule in enumerate(preset["rules"]):
            for e in self.validate_rule(rule):
                e.field = f"rules[{i}].{e.field}"
                errors.append(e)
        return errors
