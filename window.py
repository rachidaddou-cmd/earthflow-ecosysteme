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

"""core/window.py — Thread-safe sliding time window."""
import threading
import time
from collections import deque


class TimeWindow:
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
        with self._lock:
            self._purge(time.time())
            return len(self._events)

    def sum(self) -> float:
        with self._lock:
            self._purge(time.time())
            return sum(v for _, v in self._events)

    def average(self) -> float:
        c = self.count()
        return self.sum() / c if c else 0.0

    def reset(self):
        with self._lock:
            self._events.clear()
