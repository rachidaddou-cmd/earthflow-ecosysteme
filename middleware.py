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

"""proxy/middleware.py — Request logging, timing, and correlation ID middleware."""
import time
import uuid


class RequestMiddleware:
    """WSGI/ASGI-compatible middleware for logging and tracing."""

    def __init__(self, app, log_fn=None):
        self.app = app
        self.log = log_fn or print

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = str(uuid.uuid4())[:8]
        scope["state"] = scope.get("state", {})
        scope["state"]["request_id"] = request_id
        start = time.time()

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                headers[b"x-request-id"] = request_id.encode()
                message["headers"] = list(headers.items())
            await send(message)

        await self.app(scope, receive, send_wrapper)
        elapsed = round((time.time() - start) * 1000, 1)
        self.log(f"[{request_id}] {scope.get('method', 'GET')} "
                 f"{scope.get('path', '/')} — {elapsed}ms")
