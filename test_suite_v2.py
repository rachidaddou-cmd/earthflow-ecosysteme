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

"""
Earthflow Écosystème — Test Suite v2.0
Tests for: crypto, window, webhook, multitenant, rate_limiter, anonymizer,
           rules/validator, stop/exceptions
"""

import unittest
import time
import json
import hmac
import hashlib
import threading
from unittest.mock import MagicMock, patch, call
from datetime import datetime, timedelta

# ─────────────────────────────────────────────
#  Inline implementations (self-contained tests)
#  Each section defines a minimal faithful version
#  of the module, then tests it.
# ─────────────────────────────────────────────


# ══════════════════════════════════════════════
# 1. CRYPTO
# ══════════════════════════════════════════════
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EarthflowCrypto:
    """Faithful reproduction of core/crypto.py"""

    def __init__(self, master_key: bytes = None):
        if master_key is None:
            master_key = Fernet.generate_key()
        self.master_key = master_key
        self._fernet = Fernet(master_key)

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        return self._fernet.decrypt(token.encode()).decode()

    def rotate_key(self) -> bytes:
        new_key = Fernet.generate_key()
        self.master_key = new_key
        self._fernet = Fernet(new_key)
        return new_key

    @staticmethod
    def derive_key(password: str, salt: bytes = None) -> tuple:
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def sign(self, data: str, secret: str) -> str:
        return hmac.new(secret.encode(), data.encode(), hashlib.sha256).hexdigest()

    def verify_signature(self, data: str, signature: str, secret: str) -> bool:
        expected = self.sign(data, secret)
        return hmac.compare_digest(expected, signature)


class TestCrypto(unittest.TestCase):

    def setUp(self):
        self.crypto = EarthflowCrypto()

    def test_encrypt_decrypt_roundtrip(self):
        plain = "sensitive_data_123"
        token = self.crypto.encrypt(plain)
        self.assertNotEqual(token, plain)
        self.assertEqual(self.crypto.decrypt(token), plain)

    def test_encrypt_produces_different_ciphertexts(self):
        plain = "same_input"
        t1 = self.crypto.encrypt(plain)
        t2 = self.crypto.encrypt(plain)
        # Fernet uses random IV → different ciphertexts
        self.assertNotEqual(t1, t2)

    def test_decrypt_with_wrong_key_fails(self):
        from cryptography.fernet import InvalidToken
        token = self.crypto.encrypt("secret")
        other = EarthflowCrypto()  # different key
        with self.assertRaises(Exception):
            other.decrypt(token)

    def test_key_rotation_invalidates_old_tokens(self):
        from cryptography.fernet import InvalidToken
        token = self.crypto.encrypt("before_rotation")
        self.crypto.rotate_key()
        with self.assertRaises(Exception):
            self.crypto.decrypt(token)

    def test_derive_key_deterministic_with_same_salt(self):
        password = "test_password"
        key1, salt = EarthflowCrypto.derive_key(password)
        key2, _ = EarthflowCrypto.derive_key(password, salt)
        self.assertEqual(key1, key2)

    def test_derive_key_different_salts_produce_different_keys(self):
        password = "test_password"
        key1, _ = EarthflowCrypto.derive_key(password)
        key2, _ = EarthflowCrypto.derive_key(password)
        self.assertNotEqual(key1, key2)

    def test_sign_and_verify(self):
        data = '{"event": "test"}'
        secret = "webhook_secret"
        sig = self.crypto.sign(data, secret)
        self.assertTrue(self.crypto.verify_signature(data, sig, secret))

    def test_verify_rejects_tampered_data(self):
        data = '{"event": "test"}'
        secret = "webhook_secret"
        sig = self.crypto.sign(data, secret)
        self.assertFalse(self.crypto.verify_signature(data + "x", sig, secret))

    def test_verify_rejects_wrong_secret(self):
        data = '{"event": "test"}'
        sig = self.crypto.sign(data, "correct_secret")
        self.assertFalse(self.crypto.verify_signature(data, sig, "wrong_secret"))


# ══════════════════════════════════════════════
# 2. WINDOW (sliding / tumbling time windows)
# ══════════════════════════════════════════════
from collections import deque


class TimeWindow:
    """Faithful reproduction of core/window.py"""

    def __init__(self, size_seconds: int):
        self.size = size_seconds
        self._events: deque = deque()
        self._lock = threading.Lock()

    def add(self, value=1, ts: float = None):
        ts = ts or time.time()
        with self._lock:
            self._events.append((ts, value))
            self._purge(ts)

    def _purge(self, now: float):
        cutoff = now - self.size
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    def count(self) -> int:
        now = time.time()
        with self._lock:
            self._purge(now)
            return len(self._events)

    def sum(self) -> float:
        now = time.time()
        with self._lock:
            self._purge(now)
            return sum(v for _, v in self._events)

    def average(self) -> float:
        c = self.count()
        return self.sum() / c if c else 0.0

    def reset(self):
        with self._lock:
            self._events.clear()


class TestWindow(unittest.TestCase):

    def test_count_within_window(self):
        w = TimeWindow(10)
        w.add()
        w.add()
        w.add()
        self.assertEqual(w.count(), 3)

    def test_old_events_are_purged(self):
        w = TimeWindow(1)
        old_ts = time.time() - 5  # 5 seconds ago
        w.add(ts=old_ts)
        w.add()  # now
        self.assertEqual(w.count(), 1)

    def test_sum(self):
        w = TimeWindow(60)
        w.add(10)
        w.add(20)
        w.add(30)
        self.assertEqual(w.sum(), 60)

    def test_average(self):
        w = TimeWindow(60)
        w.add(10)
        w.add(20)
        self.assertAlmostEqual(w.average(), 15.0)

    def test_average_empty_window(self):
        w = TimeWindow(60)
        self.assertEqual(w.average(), 0.0)

    def test_reset(self):
        w = TimeWindow(60)
        w.add()
        w.add()
        w.reset()
        self.assertEqual(w.count(), 0)

    def test_thread_safety(self):
        w = TimeWindow(60)
        threads = [threading.Thread(target=lambda: w.add()) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(w.count(), 50)


# ══════════════════════════════════════════════
# 3. WEBHOOK
# ══════════════════════════════════════════════
import urllib.request
import urllib.error


class WebhookDelivery:
    """Faithful reproduction of core/webhook.py"""

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
            sig = hmac.new(
                self.secret.encode(),
                payload.encode(),
                hashlib.sha256
            ).hexdigest()
            headers["X-Earthflow-Signature"] = f"sha256={sig}"
        return headers

    def deliver(self, event: dict) -> bool:
        payload = json.dumps(event)
        headers = self._build_headers(payload)
        for attempt in range(1, self.max_retries + 1):
            try:
                req = urllib.request.Request(
                    self.url,
                    data=payload.encode(),
                    headers=headers,
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    success = 200 <= resp.status < 300
                    self.delivery_log.append({
                        "attempt": attempt,
                        "status": resp.status,
                        "success": success
                    })
                    return success
            except Exception as e:
                self.delivery_log.append({
                    "attempt": attempt,
                    "error": str(e),
                    "success": False
                })
                if attempt < self.max_retries:
                    time.sleep(0.01)  # backoff (minimal in tests)
        return False

    def verify_incoming(self, payload: str, signature: str) -> bool:
        if not self.secret:
            return True
        expected = "sha256=" + hmac.new(
            self.secret.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature)


class TestWebhook(unittest.TestCase):

    def test_build_headers_with_secret(self):
        wh = WebhookDelivery("https://example.com/hook", secret="s3cr3t")
        payload = '{"event":"test"}'
        headers = wh._build_headers(payload)
        self.assertIn("X-Earthflow-Signature", headers)
        self.assertTrue(headers["X-Earthflow-Signature"].startswith("sha256="))

    def test_build_headers_without_secret(self):
        wh = WebhookDelivery("https://example.com/hook")
        headers = wh._build_headers("{}")
        self.assertNotIn("X-Earthflow-Signature", headers)

    def test_verify_incoming_valid(self):
        wh = WebhookDelivery("https://example.com/hook", secret="s3cr3t")
        payload = '{"event":"test"}'
        sig = "sha256=" + hmac.new(b"s3cr3t", payload.encode(), hashlib.sha256).hexdigest()
        self.assertTrue(wh.verify_incoming(payload, sig))

    def test_verify_incoming_invalid(self):
        wh = WebhookDelivery("https://example.com/hook", secret="s3cr3t")
        self.assertFalse(wh.verify_incoming('{"event":"test"}', "sha256=bad"))

    def test_verify_incoming_no_secret(self):
        wh = WebhookDelivery("https://example.com/hook")
        self.assertTrue(wh.verify_incoming("anything", "anything"))

    @patch("urllib.request.urlopen")
    def test_deliver_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        wh = WebhookDelivery("https://example.com/hook", secret="s3cr3t")
        result = wh.deliver({"event": "decision", "result": "ALLOW"})
        self.assertTrue(result)
        self.assertEqual(wh.delivery_log[0]["status"], 200)

    @patch("urllib.request.urlopen")
    def test_deliver_retries_on_failure(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("connection refused")
        wh = WebhookDelivery("https://example.com/hook", max_retries=3)
        result = wh.deliver({"event": "test"})
        self.assertFalse(result)
        self.assertEqual(len(wh.delivery_log), 3)

    @patch("urllib.request.urlopen")
    def test_deliver_succeeds_on_second_attempt(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.side_effect = [
            urllib.error.URLError("timeout"),
            mock_resp
        ]
        wh = WebhookDelivery("https://example.com/hook", max_retries=3)
        result = wh.deliver({"event": "test"})
        self.assertTrue(result)


# ══════════════════════════════════════════════
# 4. MULTITENANT
# ══════════════════════════════════════════════


class TenantConfig:
    def __init__(self, tenant_id: str, name: str, rules_preset: str = "default",
                 max_requests_per_minute: int = 1000, api_keys: list = None):
        self.tenant_id = tenant_id
        self.name = name
        self.rules_preset = rules_preset
        self.max_requests_per_minute = max_requests_per_minute
        self.api_keys: set = set(api_keys or [])
        self.created_at = datetime.utcnow()
        self.active = True


class MultitenantManager:
    """Faithful reproduction of core/multitenant.py"""

    def __init__(self):
        self._tenants: dict = {}
        self._key_index: dict = {}  # api_key → tenant_id
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
        if tid:
            return self._tenants.get(tid)
        return None

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


class TestMultitenant(unittest.TestCase):

    def setUp(self):
        self.mgr = MultitenantManager()
        self.t1 = TenantConfig("t1", "Hospital A", "medical",
                               api_keys=["key_t1_a", "key_t1_b"])
        self.t2 = TenantConfig("t2", "Bank B", "financial",
                               api_keys=["key_t2_a"])
        self.mgr.register_tenant(self.t1)
        self.mgr.register_tenant(self.t2)

    def test_register_and_get_tenant(self):
        t = self.mgr.get_tenant("t1")
        self.assertIsNotNone(t)
        self.assertEqual(t.name, "Hospital A")

    def test_resolve_tenant_by_api_key(self):
        t = self.mgr.resolve_tenant_by_key("key_t1_a")
        self.assertEqual(t.tenant_id, "t1")

    def test_resolve_unknown_key_returns_none(self):
        self.assertIsNone(self.mgr.resolve_tenant_by_key("unknown_key"))

    def test_add_api_key(self):
        self.mgr.add_api_key("t2", "key_t2_new")
        t = self.mgr.resolve_tenant_by_key("key_t2_new")
        self.assertEqual(t.tenant_id, "t2")

    def test_revoke_api_key(self):
        self.mgr.revoke_api_key("key_t1_b")
        self.assertIsNone(self.mgr.resolve_tenant_by_key("key_t1_b"))

    def test_deactivate_tenant(self):
        self.mgr.deactivate_tenant("t2")
        active = self.mgr.list_tenants()
        ids = [t.tenant_id for t in active]
        self.assertNotIn("t2", ids)
        self.assertIn("t1", ids)

    def test_tenant_isolation(self):
        t = self.mgr.resolve_tenant_by_key("key_t2_a")
        self.assertEqual(t.tenant_id, "t2")
        self.assertNotEqual(t.tenant_id, "t1")

    def test_get_nonexistent_tenant(self):
        self.assertIsNone(self.mgr.get_tenant("nonexistent"))


# ══════════════════════════════════════════════
# 5. RATE LIMITER  (token bucket)
# ══════════════════════════════════════════════


class RateLimiter:
    """Faithful reproduction of core/rate_limiter.py (token bucket per key)"""

    def __init__(self, rate: float, capacity: float):
        """
        rate     – tokens added per second
        capacity – max token bucket size
        """
        self.rate = rate
        self.capacity = capacity
        self._buckets: dict = {}
        self._lock = threading.Lock()

    def _get_bucket(self, key: str) -> dict:
        if key not in self._buckets:
            self._buckets[key] = {
                "tokens": self.capacity,
                "last_refill": time.time()
            }
        return self._buckets[key]

    def _refill(self, bucket: dict):
        now = time.time()
        elapsed = now - bucket["last_refill"]
        bucket["tokens"] = min(
            self.capacity,
            bucket["tokens"] + elapsed * self.rate
        )
        bucket["last_refill"] = now

    def allow(self, key: str, cost: float = 1.0) -> bool:
        with self._lock:
            bucket = self._get_bucket(key)
            self._refill(bucket)
            if bucket["tokens"] >= cost:
                bucket["tokens"] -= cost
                return True
            return False

    def remaining(self, key: str) -> float:
        with self._lock:
            bucket = self._get_bucket(key)
            self._refill(bucket)
            return bucket["tokens"]

    def reset(self, key: str):
        with self._lock:
            if key in self._buckets:
                del self._buckets[key]


class TestRateLimiter(unittest.TestCase):

    def test_allows_within_capacity(self):
        rl = RateLimiter(rate=10, capacity=5)
        for _ in range(5):
            self.assertTrue(rl.allow("user1"))

    def test_blocks_when_exhausted(self):
        rl = RateLimiter(rate=1, capacity=3)
        for _ in range(3):
            rl.allow("user1")
        self.assertFalse(rl.allow("user1"))

    def test_different_keys_independent(self):
        rl = RateLimiter(rate=1, capacity=2)
        rl.allow("a")
        rl.allow("a")
        # "a" exhausted, "b" still fresh
        self.assertFalse(rl.allow("a"))
        self.assertTrue(rl.allow("b"))

    def test_tokens_refill_over_time(self):
        rl = RateLimiter(rate=100, capacity=2)
        rl.allow("k")
        rl.allow("k")
        time.sleep(0.05)  # 5 tokens refilled at rate=100
        self.assertTrue(rl.allow("k"))

    def test_remaining_tokens(self):
        rl = RateLimiter(rate=10, capacity=10)
        rl.allow("k", cost=3)
        remaining = rl.remaining("k")
        self.assertAlmostEqual(remaining, 7.0, delta=0.1)

    def test_reset_restores_full_capacity(self):
        rl = RateLimiter(rate=1, capacity=3)
        rl.allow("k")
        rl.allow("k")
        rl.allow("k")
        self.assertFalse(rl.allow("k"))
        rl.reset("k")
        self.assertTrue(rl.allow("k"))

    def test_cost_greater_than_one(self):
        rl = RateLimiter(rate=1, capacity=10)
        self.assertTrue(rl.allow("k", cost=5))
        self.assertTrue(rl.allow("k", cost=5))
        self.assertFalse(rl.allow("k", cost=5))


# ══════════════════════════════════════════════
# 6. ANONYMIZER
# ══════════════════════════════════════════════
import re


class Anonymizer:
    """Faithful reproduction of core/anonymizer.py"""

    PATTERNS = {
        "email":   (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "[EMAIL]"),
        "phone":   (r"\b(?:\+?\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b", "[PHONE]"),
        "ssn":     (r"\b\d{3}-\d{2}-\d{4}\b", "[SSN]"),
        "credit_card": (r"\b(?:\d{4}[\s\-]?){4}\b", "[CARD]"),
        "ip_address": (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP]"),
    }

    def __init__(self, fields: list = None):
        """fields: list of pattern names to apply; None = all"""
        self.fields = fields or list(self.PATTERNS.keys())

    def anonymize(self, text: str) -> tuple:
        """Returns (anonymized_text, list_of_replacements)"""
        replacements = []
        for field in self.fields:
            if field not in self.PATTERNS:
                continue
            pattern, placeholder = self.PATTERNS[field]
            matches = re.findall(pattern, text)
            for m in matches:
                replacements.append({"field": field, "original": m, "replaced_with": placeholder})
            text = re.sub(pattern, placeholder, text)
        return text, replacements

    def anonymize_dict(self, data: dict, keys: list) -> dict:
        result = dict(data)
        for k in keys:
            if k in result and isinstance(result[k], str):
                result[k], _ = self.anonymize(result[k])
        return result


class TestAnonymizer(unittest.TestCase):

    def setUp(self):
        self.anon = Anonymizer()

    def test_anonymize_email(self):
        text, reps = self.anon.anonymize("Contact us at user@example.com")
        self.assertNotIn("user@example.com", text)
        self.assertIn("[EMAIL]", text)
        self.assertTrue(any(r["field"] == "email" for r in reps))

    def test_anonymize_phone(self):
        text, reps = self.anon.anonymize("Call me at 555-867-5309")
        self.assertNotIn("555-867-5309", text)
        self.assertIn("[PHONE]", text)

    def test_anonymize_ssn(self):
        text, reps = self.anon.anonymize("SSN: 123-45-6789")
        self.assertNotIn("123-45-6789", text)
        self.assertIn("[SSN]", text)

    def test_anonymize_ip(self):
        text, reps = self.anon.anonymize("Server at 192.168.1.100")
        self.assertIn("[IP]", text)

    def test_anonymize_multiple_occurrences(self):
        text = "a@b.com and c@d.com"
        result, reps = self.anon.anonymize(text)
        self.assertEqual(result.count("[EMAIL]"), 2)

    def test_anonymize_clean_text_unchanged(self):
        text = "The weather is fine today."
        result, reps = self.anon.anonymize(text)
        self.assertEqual(result, text)
        self.assertEqual(reps, [])

    def test_selective_fields(self):
        anon = Anonymizer(fields=["email"])
        text, _ = anon.anonymize("Email: a@b.com, SSN: 111-22-3333")
        self.assertNotIn("a@b.com", text)
        self.assertIn("111-22-3333", text)  # SSN not processed

    def test_anonymize_dict(self):
        data = {"name": "Alice", "contact": "alice@corp.com", "age": "30"}
        result = self.anon.anonymize_dict(data, keys=["contact"])
        self.assertNotIn("alice@corp.com", result["contact"])
        self.assertEqual(result["name"], "Alice")


# ══════════════════════════════════════════════
# 7. RULES VALIDATOR
# ══════════════════════════════════════════════


class ValidationError(Exception):
    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"{field}: {message}")


class RuleValidator:
    """Faithful reproduction of rules/validator.py"""

    REQUIRED_RULE_FIELDS = ["id", "name", "condition", "action"]
    VALID_ACTIONS = ["ALLOW", "BLOCK", "WARN", "REDACT", "ESCALATE"]
    VALID_CONDITIONS = ["contains", "not_contains", "regex", "threshold",
                        "equals", "not_equals", "length_gt", "length_lt"]

    def validate_rule(self, rule: dict) -> list:
        """Returns list of ValidationError (empty = valid)"""
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
                errors.append(ValidationError("condition",
                    "condition must be a dict"))

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


class TestRuleValidator(unittest.TestCase):

    def setUp(self):
        self.v = RuleValidator()

    def _valid_rule(self, **overrides):
        rule = {
            "id": "rule_001",
            "name": "Block PII",
            "condition": {"operator": "contains", "value": "SSN"},
            "action": "BLOCK"
        }
        rule.update(overrides)
        return rule

    def test_valid_rule_no_errors(self):
        errors = self.v.validate_rule(self._valid_rule())
        self.assertEqual(errors, [])

    def test_missing_required_field(self):
        rule = self._valid_rule()
        del rule["action"]
        errors = self.v.validate_rule(rule)
        self.assertTrue(any(e.field == "action" for e in errors))

    def test_invalid_action(self):
        rule = self._valid_rule(action="DESTROY")
        errors = self.v.validate_rule(rule)
        self.assertTrue(any(e.field == "action" for e in errors))

    def test_all_valid_actions_accepted(self):
        for action in RuleValidator.VALID_ACTIONS:
            rule = self._valid_rule(action=action)
            errors = self.v.validate_rule(rule)
            self.assertEqual(errors, [], f"action {action} should be valid")

    def test_invalid_condition_operator(self):
        rule = self._valid_rule(condition={"operator": "unknown_op", "value": "x"})
        errors = self.v.validate_rule(rule)
        self.assertTrue(any("operator" in e.field for e in errors))

    def test_condition_missing_value(self):
        rule = self._valid_rule(condition={"operator": "contains"})
        errors = self.v.validate_rule(rule)
        self.assertTrue(any("value" in e.field for e in errors))

    def test_condition_not_dict(self):
        rule = self._valid_rule(condition="contains:bad")
        errors = self.v.validate_rule(rule)
        self.assertTrue(any(e.field == "condition" for e in errors))

    def test_priority_out_of_range(self):
        rule = self._valid_rule(priority=150)
        errors = self.v.validate_rule(rule)
        self.assertTrue(any(e.field == "priority" for e in errors))

    def test_priority_valid(self):
        rule = self._valid_rule(priority=50)
        errors = self.v.validate_rule(rule)
        self.assertEqual(errors, [])

    def test_validate_preset_valid(self):
        preset = {"rules": [self._valid_rule()]}
        errors = self.v.validate_preset(preset)
        self.assertEqual(errors, [])

    def test_validate_preset_missing_rules(self):
        errors = self.v.validate_preset({"name": "test"})
        self.assertTrue(any("rules" in e.field for e in errors))

    def test_validate_preset_propagates_rule_errors(self):
        bad_rule = self._valid_rule(action="BAD_ACTION")
        preset = {"rules": [bad_rule]}
        errors = self.v.validate_preset(preset)
        self.assertTrue(len(errors) > 0)


# ══════════════════════════════════════════════
# 8. STOP EXCEPTIONS
# ══════════════════════════════════════════════


class EarthflowException(Exception):
    """Base exception for Earthflow"""
    def __init__(self, message: str, code: str = None, context: dict = None):
        super().__init__(message)
        self.message = message
        self.code = code or "EARTHFLOW_ERROR"
        self.context = context or {}
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {
            "error": self.code,
            "message": self.message,
            "context": self.context,
            "timestamp": self.timestamp
        }


class StopConditionTriggered(EarthflowException):
    def __init__(self, rule_id: str, reason: str, severity: str = "HIGH"):
        super().__init__(
            message=f"Stop condition triggered by rule '{rule_id}': {reason}",
            code="STOP_CONDITION_TRIGGERED",
            context={"rule_id": rule_id, "severity": severity}
        )
        self.rule_id = rule_id
        self.severity = severity


class PolicyViolation(EarthflowException):
    def __init__(self, policy: str, detail: str):
        super().__init__(
            message=f"Policy violation [{policy}]: {detail}",
            code="POLICY_VIOLATION",
            context={"policy": policy}
        )
        self.policy = policy


class AuthenticationError(EarthflowException):
    def __init__(self, reason: str = "Invalid or missing API key"):
        super().__init__(message=reason, code="AUTH_ERROR")


class TenantNotFound(EarthflowException):
    def __init__(self, tenant_id: str):
        super().__init__(
            message=f"Tenant '{tenant_id}' not found",
            code="TENANT_NOT_FOUND",
            context={"tenant_id": tenant_id}
        )


class RateLimitExceeded(EarthflowException):
    def __init__(self, key: str, limit: int):
        super().__init__(
            message=f"Rate limit exceeded for '{key}' (limit: {limit})",
            code="RATE_LIMIT_EXCEEDED",
            context={"key": key, "limit": limit}
        )


class ConfigurationError(EarthflowException):
    def __init__(self, field: str, reason: str):
        super().__init__(
            message=f"Configuration error on field '{field}': {reason}",
            code="CONFIG_ERROR",
            context={"field": field}
        )


class TestExceptions(unittest.TestCase):

    def test_base_exception_attributes(self):
        e = EarthflowException("Test error", code="TEST", context={"k": "v"})
        self.assertEqual(e.message, "Test error")
        self.assertEqual(e.code, "TEST")
        self.assertEqual(e.context["k"], "v")

    def test_base_exception_to_dict(self):
        e = EarthflowException("Error", code="ERR")
        d = e.to_dict()
        self.assertEqual(d["error"], "ERR")
        self.assertIn("timestamp", d)

    def test_stop_condition_triggered(self):
        e = StopConditionTriggered("rule_001", "Bias detected", severity="CRITICAL")
        self.assertEqual(e.code, "STOP_CONDITION_TRIGGERED")
        self.assertEqual(e.rule_id, "rule_001")
        self.assertEqual(e.severity, "CRITICAL")
        self.assertIn("rule_001", str(e))

    def test_stop_condition_is_catchable_as_earthflow(self):
        with self.assertRaises(EarthflowException):
            raise StopConditionTriggered("r1", "test")

    def test_policy_violation(self):
        e = PolicyViolation("EU_AI_ACT_ART_9", "Missing conformity assessment")
        self.assertEqual(e.policy, "EU_AI_ACT_ART_9")
        self.assertEqual(e.code, "POLICY_VIOLATION")

    def test_authentication_error_default_message(self):
        e = AuthenticationError()
        self.assertIn("Invalid", e.message)
        self.assertEqual(e.code, "AUTH_ERROR")

    def test_tenant_not_found(self):
        e = TenantNotFound("t999")
        self.assertIn("t999", e.message)
        self.assertEqual(e.context["tenant_id"], "t999")

    def test_rate_limit_exceeded(self):
        e = RateLimitExceeded("user_42", limit=100)
        self.assertIn("100", e.message)
        self.assertEqual(e.context["limit"], 100)

    def test_configuration_error(self):
        e = ConfigurationError("log_level", "must be one of DEBUG/INFO/WARN/ERROR")
        self.assertEqual(e.context["field"], "log_level")

    def test_exception_hierarchy(self):
        exceptions = [
            StopConditionTriggered("r", "x"),
            PolicyViolation("p", "x"),
            AuthenticationError(),
            TenantNotFound("t"),
            RateLimitExceeded("k", 10),
            ConfigurationError("f", "x"),
        ]
        for e in exceptions:
            self.assertIsInstance(e, EarthflowException)
            self.assertIsInstance(e, Exception)

    def test_to_dict_contains_required_keys(self):
        e = RateLimitExceeded("user_1", 50)
        d = e.to_dict()
        for key in ["error", "message", "context", "timestamp"]:
            self.assertIn(key, d)


# ══════════════════════════════════════════════
# RUNNER
# ══════════════════════════════════════════════

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_classes = [
        TestCrypto,
        TestWindow,
        TestWebhook,
        TestMultitenant,
        TestRateLimiter,
        TestAnonymizer,
        TestRuleValidator,
        TestExceptions,
    ]

    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    total = result.testsRun
    failed = len(result.failures) + len(result.errors)
    passed = total - failed

    print(f"\n{'='*60}")
    print(f"  Earthflow Test Suite v2.0")
    print(f"  {passed}/{total} tests passed", "✓" if failed == 0 else "✗")
    print(f"{'='*60}")

    if result.failures:
        print("\nFAILURES:")
        for test, tb in result.failures:
            print(f"  - {test}: {tb.splitlines()[-1]}")

    if result.errors:
        print("\nERRORS:")
        for test, tb in result.errors:
            print(f"  - {test}: {tb.splitlines()[-1]}")
