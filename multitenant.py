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

"""core/multitenant.py — Multi-tenant manager with key-based routing."""
import threading
from datetime import datetime, timezone


class TenantConfig:
    def __init__(self, tenant_id: str, name: str, rules_preset: str = "default",
                 max_requests_per_minute: int = 1000, api_keys: list = None):
        self.tenant_id = tenant_id
        self.name = name
        self.rules_preset = rules_preset
        self.max_requests_per_minute = max_requests_per_minute
        self.api_keys: set = set(api_keys or [])
        self.created_at = datetime.now(tz=timezone.utc).isoformat()
        self.active = True


class MultitenantManager:
    def __init__(self):
        self._tenants: dict = {}
        self._key_index: dict = {}
        self._lock = threading.Lock()

    def register_tenant(self, config: TenantConfig):
        with self._lock:
            self._tenants[config.tenant_id] = config
            for key in config.api_keys:
                self._key_index[key] = config.tenant_id

    def get_tenant(self, tenant_id: str) -> TenantConfig:
        return self._tenants.get(tenant_id)

    def resolve_tenant_by_key(self, api_key: str) -> TenantConfig:
        tid = self._key_index.get(api_key)
        return self._tenants.get(tid) if tid else None

    def add_api_key(self, tenant_id: str, api_key: str):
        with self._lock:
            t = self._tenants.get(tenant_id)
            if t:
                t.api_keys.add(api_key)
                self._key_index[api_key] = tenant_id

    def revoke_api_key(self, api_key: str):
        with self._lock:
            self._key_index.pop(api_key, None)
            for t in self._tenants.values():
                t.api_keys.discard(api_key)

    def deactivate_tenant(self, tenant_id: str):
        with self._lock:
            t = self._tenants.get(tenant_id)
            if t:
                t.active = False

    def list_tenants(self) -> list:
        return [t for t in self._tenants.values() if t.active]
