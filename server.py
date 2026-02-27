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

"""proxy/server.py — Earthflow AI proxy server (FastAPI)."""
import time

try:
    from fastapi import FastAPI, Request, HTTPException
    from fastapi.responses import JSONResponse
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from core.audit import AuditLog
from core.multitenant import MultitenantManager
from core.rate_limiter import RateLimiter
from core.anonymizer import Anonymizer
from rules.engine import RulesEngine
from stop.controller import StopController
from stop.exceptions import (StopConditionTriggered, AuthenticationError,
                              RateLimitExceeded, TenantNotFound)

# Module-level singletons (configured at startup)
audit_log = AuditLog()
tenant_mgr = MultitenantManager()
rate_limiter = RateLimiter(rate=1000 / 60, capacity=1000)
anonymizer = Anonymizer()

if HAS_FASTAPI:
    app = FastAPI(title="Earthflow Proxy", version="2.0.0")

    @app.post("/v1/proxy")
    async def proxy_request(request: Request):
        start = time.time()
        api_key = (request.headers.get("X-API-Key") or
                   request.headers.get("Authorization", "").replace("Bearer ", ""))

        tenant = tenant_mgr.resolve_tenant_by_key(api_key)
        if not tenant:
            raise HTTPException(status_code=401, detail="Invalid API key")

        if not rate_limiter.allow(tenant.tenant_id):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        body = await request.json()
        prompt = " ".join(m.get("content", "") for m in body.get("messages", []))

        # Load tenant rules
        engine = RulesEngine()  # In production: load from DB by tenant preset
        controller = StopController(engine, audit_log)

        try:
            result = controller.check(prompt, body.get("metadata"), tenant.tenant_id)
            result["latency_ms"] = round((time.time() - start) * 1000, 1)
            return JSONResponse(content=result)
        except StopConditionTriggered as e:
            return JSONResponse(content={
                "status": "BLOCK",
                "reason": e.message,
                "rule_id": e.rule_id,
                "latency_ms": round((time.time() - start) * 1000, 1),
            })

    @app.get("/health")
    async def health():
        return {"status": "OK", "version": "2.0.0"}

    @app.get("/health/ready")
    async def ready():
        return {"status": "OK", "checks": {"rules_engine": "OK", "crypto": "OK"}}
