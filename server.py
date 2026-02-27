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

"""dashboard/server.py — Read-only metrics dashboard (FastAPI)."""
try:
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse, PlainTextResponse
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

# Injected at startup from proxy/server.py
audit_log = None
tenant_mgr = None

if HAS_FASTAPI:
    app = FastAPI(title="Earthflow Dashboard", version="2.0.0")

    @app.get("/v1/dashboard/summary")
    async def summary():
        if not audit_log:
            return {"error": "audit_log not initialised"}
        stats = audit_log.stats()
        return {
            "period_24h": stats,
            "active_tenants": len(tenant_mgr.list_tenants()) if tenant_mgr else 0,
            "system_health": "OK",
        }

    @app.get("/v1/dashboard/metrics")
    async def metrics():
        """Prometheus-compatible text format."""
        if not audit_log:
            return PlainTextResponse("# audit_log not initialised\n")
        stats = audit_log.stats()
        lines = [
            "# HELP earthflow_requests_total Total requests processed",
            "# TYPE earthflow_requests_total counter",
        ]
        for status, count in stats.get("by_status", {}).items():
            lines.append(f'earthflow_requests_total{{status="{status}"}} {count}')
        return PlainTextResponse("\n".join(lines) + "\n")
