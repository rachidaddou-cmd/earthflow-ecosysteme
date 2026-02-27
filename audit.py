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

"""core/audit.py — Immutable audit log with SHA-256 prompt hashing."""
import hashlib
import json
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Optional


class AuditEntry:
    def __init__(self, tenant_id: str, status: str, model: str,
                 rules_evaluated: int, rules_triggered: list,
                 metadata: dict, latency_ms: Optional[float],
                 prompt: Optional[str] = None):
        self.audit_id = "aud_" + uuid.uuid4().hex[:12]
        self.request_id = "req_" + uuid.uuid4().hex[:12]
        self.tenant_id = tenant_id
        self.timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.status = status
        self.model = model
        self.rules_evaluated = rules_evaluated
        self.rules_triggered = rules_triggered
        self.metadata = metadata or {}
        self.latency_ms = latency_ms
        self.prompt_hash = ("sha256:" + hashlib.sha256(prompt.encode()).hexdigest()
                            if prompt else None)
        self.schema_version = 2

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


class AuditLog:
    def __init__(self, retention_days: int = 365):
        self._entries: list = []
        self._lock = threading.Lock()
        self.retention_days = retention_days

    def record(self, **kwargs) -> AuditEntry:
        entry = AuditEntry(**kwargs)
        with self._lock:
            self._entries.append(entry)
        return entry

    def query(self, tenant_id: str = None, status: str = None,
              limit: int = 100, offset: int = 0) -> list:
        with self._lock:
            results = list(self._entries)
        if tenant_id:
            results = [e for e in results if e.tenant_id == tenant_id]
        if status:
            results = [e for e in results if e.status == status]
        return results[offset:offset + limit]

    def stats(self, tenant_id: str = None) -> dict:
        entries = self.query(tenant_id=tenant_id, limit=10_000)
        counts = {}
        for e in entries:
            counts[e.status] = counts.get(e.status, 0) + 1
        total = len(entries)
        return {
            "total": total,
            "by_status": counts,
            "block_rate": counts.get("BLOCK", 0) / total if total else 0,
        }
