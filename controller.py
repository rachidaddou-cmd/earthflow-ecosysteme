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

"""stop/controller.py — Stop condition controller."""
from .exceptions import StopConditionTriggered


class StopController:
    """Evaluates stop conditions and raises StopConditionTriggered when met."""

    def __init__(self, rules_engine, audit_log=None):
        self.rules_engine = rules_engine
        self.audit_log = audit_log
        self._stop_actions = {"BLOCK", "ESCALATE"}

    def check(self, prompt: str, metadata: dict = None, tenant_id: str = None) -> dict:
        """
        Evaluate prompt against rules. Returns result dict if ALLOW/WARN/REDACT.
        Raises StopConditionTriggered if action is BLOCK or ESCALATE.
        """
        result = self.rules_engine.evaluate(prompt, metadata)
        status = result.get("status", "ALLOW")

        if self.audit_log and tenant_id:
            self.audit_log.record(
                tenant_id=tenant_id,
                status=status,
                model=metadata.get("model", "unknown") if metadata else "unknown",
                rules_evaluated=result.get("rules_evaluated", 0),
                rules_triggered=result.get("rules_triggered", []),
                metadata=metadata or {},
                latency_ms=None,
                prompt=prompt,
            )

        if status in self._stop_actions:
            triggered = result.get("rules_triggered", [])
            rule_id = triggered[0] if triggered else "unknown"
            matches = result.get("matches", [])
            reason = matches[0]["name"] if matches else "Rule triggered"
            raise StopConditionTriggered(rule_id=rule_id, reason=reason,
                                         severity="HIGH" if status == "BLOCK" else "MEDIUM")

        return result
