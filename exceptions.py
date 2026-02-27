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

"""stop/exceptions.py — Earthflow exception hierarchy."""
from datetime import datetime, timezone


class EarthflowException(Exception):
    def __init__(self, message: str, code: str = None, context: dict = None):
        super().__init__(message)
        self.message = message
        self.code = code or "EARTHFLOW_ERROR"
        self.context = context or {}
        self.timestamp = datetime.now(tz=timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {"error": self.code, "message": self.message,
                "context": self.context, "timestamp": self.timestamp}


class StopConditionTriggered(EarthflowException):
    def __init__(self, rule_id: str, reason: str, severity: str = "HIGH"):
        super().__init__(
            message=f"Stop condition triggered by rule '{rule_id}': {reason}",
            code="STOP_CONDITION_TRIGGERED",
            context={"rule_id": rule_id, "severity": severity})
        self.rule_id = rule_id
        self.severity = severity


class PolicyViolation(EarthflowException):
    def __init__(self, policy: str, detail: str):
        super().__init__(message=f"Policy violation [{policy}]: {detail}",
                         code="POLICY_VIOLATION", context={"policy": policy})
        self.policy = policy


class AuthenticationError(EarthflowException):
    def __init__(self, reason: str = "Invalid or missing API key"):
        super().__init__(message=reason, code="AUTH_ERROR")


class TenantNotFound(EarthflowException):
    def __init__(self, tenant_id: str):
        super().__init__(message=f"Tenant '{tenant_id}' not found",
                         code="TENANT_NOT_FOUND", context={"tenant_id": tenant_id})


class RateLimitExceeded(EarthflowException):
    def __init__(self, key: str, limit: int):
        super().__init__(message=f"Rate limit exceeded for '{key}' (limit: {limit})",
                         code="RATE_LIMIT_EXCEEDED", context={"key": key, "limit": limit})


class ConfigurationError(EarthflowException):
    def __init__(self, field: str, reason: str):
        super().__init__(message=f"Configuration error on field '{field}': {reason}",
                         code="CONFIG_ERROR", context={"field": field})
