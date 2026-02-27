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

"""core/rate_limiter.py — Token bucket rate limiter, per-key."""
import threading
import time


class RateLimiter:
    def __init__(self, rate: float, capacity: float):
        self.rate = rate
        self.capacity = capacity
        self._buckets: dict = {}
        self._lock = threading.Lock()

    def _get_bucket(self, key: str) -> dict:
        if key not in self._buckets:
            self._buckets[key] = {"tokens": self.capacity, "last_refill": time.time()}
        return self._buckets[key]

    def _refill(self, bucket: dict):
        now = time.time()
        bucket["tokens"] = min(
            self.capacity,
            bucket["tokens"] + (now - bucket["last_refill"]) * self.rate
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
            self._buckets.pop(key, None)
