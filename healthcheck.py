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

#!/usr/bin/env python3
"""scripts/healthcheck.py — Liveness and readiness health check."""
import argparse
import sys
import urllib.request
import json


def check(host: str, port: int, tls: bool = False) -> bool:
    scheme = "https" if tls else "http"
    url = f"{scheme}://{host}:{port}/health/ready"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
            ok = data.get("status") == "OK"
            print("✓ HEALTHY" if ok else "✗ UNHEALTHY", data)
            return ok
    except Exception as e:
        print(f"✗ UNREACHABLE: {e}")
        return False


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="localhost")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--tls", action="store_true")
    args = p.parse_args()
    sys.exit(0 if check(args.host, args.port, args.tls) else 1)
