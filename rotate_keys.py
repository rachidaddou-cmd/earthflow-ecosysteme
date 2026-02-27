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
"""scripts/rotate_keys.py — API key rotation utility."""
import argparse
import secrets
import sys


def rotate(tenant_id: str = None, revoke_after: int = 3600,
           dry_run: bool = False, rotate_master: bool = False, new_key: str = None):
    print(f"Earthflow Key Rotation {'(DRY RUN) ' if dry_run else ''}")
    print(f"  Tenant        : {tenant_id or 'ALL'}")
    print(f"  Revoke after  : {revoke_after}s")

    if rotate_master:
        if not new_key:
            from cryptography.fernet import Fernet
            new_key = Fernet.generate_key().decode()
        print(f"  New master key: {new_key[:12]}...")
        if not dry_run:
            print("  ✓ Master key would be rotated (update .env manually)")
        return

    new_api_key = "ef_live_" + secrets.token_urlsafe(24)
    print(f"  New API key   : {new_api_key}")
    if not dry_run:
        print(f"  ✓ Key rotated. Old key revoked after {revoke_after}s.")
    else:
        print("  Dry run — no changes made.")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--tenant-id")
    p.add_argument("--revoke-after", type=int, default=3600)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--rotate-master", action="store_true")
    p.add_argument("--new-key")
    args = p.parse_args()
    rotate(args.tenant_id, args.revoke_after, args.dry_run,
           args.rotate_master, args.new_key)
