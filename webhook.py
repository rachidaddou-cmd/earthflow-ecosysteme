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

"""core/webhook.py — HMAC-signed webhook delivery with retry."""
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request


class WebhookDelivery:
    def __init__(self, url: str, secret: str = None,
                 max_retries: int = 3, timeout: int = 5):
        self.url = url
        self.secret = secret
        self.max_retries = max_retries
        self.timeout = timeout
        self.delivery_log: list = []

    def _build_headers(self, payload: str) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.secret:
            sig = hmac.new(self.secret.encode(), payload.encode(),
                           hashlib.sha256).hexdigest()
            headers["X-Earthflow-Signature"] = f"sha256={sig}"
        return headers

    def deliver(self, event: dict) -> bool:
        payload = json.dumps(event)
        headers = self._build_headers(payload)
        for attempt in range(1, self.max_retries + 1):
            try:
                req = urllib.request.Request(
                    self.url, data=payload.encode(),
                    headers=headers, method="POST"
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    success = 200 <= resp.status < 300
                    self.delivery_log.append(
                        {"attempt": attempt, "status": resp.status, "success": success})
                    return success
            except Exception as e:
                self.delivery_log.append(
                    {"attempt": attempt, "error": str(e), "success": False})
                if attempt < self.max_retries:
                    time.sleep(0.5 * attempt)
        return False

    def verify_incoming(self, payload: str, signature: str) -> bool:
        if not self.secret:
            return True
        expected = "sha256=" + hmac.new(
            self.secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)
