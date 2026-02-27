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

"""examples/quickstart.py — Earthflow 5-minute quickstart."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rules.engine import RulesEngine
from stop.controller import StopController
from stop.exceptions import StopConditionTriggered
from core.audit import AuditLog

print("Earthflow Écosystème — Quickstart\n" + "─"*40)

# 1. Configure rules
rules = [
    {
        "id": "block_pii", "name": "Block SSN",
        "condition": {"operator": "regex", "value": r"\d{3}-\d{2}-\d{4}"},
        "action": "BLOCK", "priority": 90, "active": True
    },
    {
        "id": "warn_long", "name": "Warn on very long prompt",
        "condition": {"operator": "length_gt", "value": 500},
        "action": "WARN", "priority": 20, "active": True
    },
]

engine = RulesEngine(rules)
audit = AuditLog()
controller = StopController(engine, audit)

# 2. Safe request
try:
    result = controller.check("What is the capital of France?",
                              metadata={"user": "demo"}, tenant_id="t1")
    print(f"✓ ALLOW — {result['rules_evaluated']} rules evaluated")
except StopConditionTriggered as e:
    print(f"✗ BLOCKED — {e.message}")

# 3. Blocked request
try:
    result = controller.check("Analyse patient SSN 123-45-6789",
                              metadata={"user": "demo"}, tenant_id="t1")
    print(f"✓ ALLOW")
except StopConditionTriggered as e:
    print(f"✗ BLOCKED — {e.message}")

# 4. Audit stats
stats = audit.stats(tenant_id="t1")
print(f"\nAudit: {stats['total']} requests | block rate: {stats['block_rate']:.0%}")
