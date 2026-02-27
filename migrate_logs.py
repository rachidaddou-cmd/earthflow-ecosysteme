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
"""
scripts/migrate_logs.py
=======================
Migrates Earthflow audit log files from v1.x format to v2.x format.

V1 format (one JSON object per line):
    {"ts": 1706784060, "action": "BLOCK", "rule": "rule_001", "prompt": "...", "tenant": "t1"}

V2 format (one JSON object per line):
    {
      "audit_id": "aud_<hash>",
      "request_id": "req_<hash>",
      "tenant_id": "t1",
      "timestamp": "2025-02-01T14:23:11Z",
      "status": "BLOCK",
      "model": "unknown",
      "rules_evaluated": null,
      "rules_triggered": ["rule_001"],
      "metadata": {},
      "latency_ms": null,
      "prompt_hash": "sha256:<hash>",
      "schema_version": 2
    }

Usage:
    python scripts/migrate_logs.py --input audit_v1.jsonl --output audit_v2.jsonl
    python scripts/migrate_logs.py --input audit_v1.jsonl --output audit_v2.jsonl --dry-run
    python scripts/migrate_logs.py --input audit_v1.jsonl --output audit_v2.jsonl --from-version 1 --to-version 2
"""

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


# ─────────────────────────────────────────────
# Schema definitions
# ─────────────────────────────────────────────

def detect_version(record: dict) -> int:
    """Detect the schema version of a log record."""
    if record.get("schema_version") == 2:
        return 2
    if "audit_id" in record and "request_id" in record:
        return 2
    if "ts" in record and "action" in record and "audit_id" not in record:
        return 1
    return 0  # unknown


def _make_id(prefix: str, seed: str) -> str:
    h = hashlib.sha256(seed.encode()).hexdigest()[:12]
    return f"{prefix}_{h}"


def _hash_prompt(prompt: str) -> str:
    if not prompt:
        return None
    return "sha256:" + hashlib.sha256(prompt.encode()).hexdigest()


def _ts_to_iso(ts) -> str:
    """Convert unix timestamp (int or float) or ISO string to ISO 8601 UTC."""
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(ts, str):
        return ts  # assume already ISO
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─────────────────────────────────────────────
# Migration functions
# ─────────────────────────────────────────────

def migrate_v1_to_v2(record: dict, line_number: int) -> dict:
    """
    Transform a v1 log record into v2 format.

    V1 fields:
        ts        – unix timestamp
        action    – ALLOW | BLOCK | WARN | REDACT
        rule      – rule_id that triggered (optional)
        prompt    – raw prompt text (will be hashed, never stored)
        tenant    – tenant identifier
        model     – model name (optional)
        user_id   – user identifier (optional)
        latency   – latency in ms (optional)
    """
    seed = f"{record.get('ts', '')}{record.get('tenant', '')}{line_number}"
    timestamp = _ts_to_iso(record.get("ts"))

    # Build rules_triggered list
    rule = record.get("rule") or record.get("rule_id")
    rules_triggered = [rule] if rule else []

    # Build metadata
    metadata = {}
    if record.get("user_id"):
        metadata["user_id"] = record["user_id"]
    if record.get("session_id"):
        metadata["session_id"] = record["session_id"]
    # Preserve any extra v1 fields as metadata
    known_v1_keys = {"ts", "action", "rule", "rule_id", "prompt", "tenant",
                     "model", "user_id", "session_id", "latency"}
    for k, v in record.items():
        if k not in known_v1_keys:
            metadata[f"v1_{k}"] = v

    return {
        "audit_id": _make_id("aud", seed + "audit"),
        "request_id": _make_id("req", seed + "req"),
        "tenant_id": record.get("tenant") or record.get("tenant_id", "unknown"),
        "timestamp": timestamp,
        "status": record.get("action", "UNKNOWN").upper(),
        "model": record.get("model", "unknown"),
        "rules_evaluated": None,   # not available in v1
        "rules_triggered": rules_triggered,
        "metadata": metadata,
        "latency_ms": record.get("latency"),
        "prompt_hash": _hash_prompt(record.get("prompt")),
        "schema_version": 2,
        "_migrated_from": 1,
        "_migrated_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def migrate_v2_to_v2(record: dict) -> dict:
    """V2 → V2: ensure all required fields are present, fill gaps."""
    record.setdefault("schema_version", 2)
    record.setdefault("rules_evaluated", None)
    record.setdefault("rules_triggered", [])
    record.setdefault("metadata", {})
    record.setdefault("latency_ms", None)

    # Ensure prompt is hashed if present in raw form
    if "prompt" in record and "prompt_hash" not in record:
        record["prompt_hash"] = _hash_prompt(record.pop("prompt"))
    elif "prompt" in record:
        del record["prompt"]  # never store raw prompt

    return record


MIGRATION_MAP = {
    (1, 2): migrate_v1_to_v2,
    (2, 2): lambda r, _ln: migrate_v2_to_v2(r),
}


# ─────────────────────────────────────────────
# Core migration engine
# ─────────────────────────────────────────────

class MigrationStats:
    def __init__(self):
        self.total = 0
        self.migrated = 0
        self.skipped = 0
        self.errors = 0
        self.already_target = 0
        self.start_time = time.time()

    def elapsed(self) -> float:
        return time.time() - self.start_time

    def summary(self) -> str:
        lines = [
            "─" * 50,
            f"  Migration complete in {self.elapsed():.2f}s",
            f"  Total lines    : {self.total}",
            f"  Migrated       : {self.migrated}",
            f"  Already v2     : {self.already_target}",
            f"  Skipped        : {self.skipped}",
            f"  Errors         : {self.errors}",
            "─" * 50,
        ]
        return "\n".join(lines)


def migrate_file(
    input_path: Path,
    output_path: Path,
    from_version: int,
    to_version: int,
    dry_run: bool = False,
    verbose: bool = False,
) -> MigrationStats:
    stats = MigrationStats()
    migration_fn = MIGRATION_MAP.get((from_version, to_version))

    if migration_fn is None:
        print(f"ERROR: No migration path defined from v{from_version} to v{to_version}.",
              file=sys.stderr)
        sys.exit(1)

    output_lines = []

    with open(input_path, "r", encoding="utf-8") as f:
        for line_number, raw_line in enumerate(f, start=1):
            raw_line = raw_line.strip()
            if not raw_line:
                continue

            stats.total += 1

            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError as e:
                stats.errors += 1
                if verbose:
                    print(f"  [line {line_number}] JSON parse error: {e}", file=sys.stderr)
                continue

            detected = detect_version(record)

            if detected == to_version and from_version != to_version:
                # Record is already in target format
                stats.already_target += 1
                output_lines.append(json.dumps(record, ensure_ascii=False))
                continue

            if detected != from_version and from_version != 0:
                # Unknown or mismatched version — skip
                stats.skipped += 1
                if verbose:
                    print(f"  [line {line_number}] Skipped: detected v{detected}, "
                          f"expected v{from_version}")
                continue

            try:
                if from_version == 2:
                    migrated = migration_fn(record)
                else:
                    migrated = migration_fn(record, line_number)
                stats.migrated += 1
                output_lines.append(json.dumps(migrated, ensure_ascii=False))
                if verbose:
                    print(f"  [line {line_number}] ✓ Migrated  "
                          f"{record.get('ts', '?')} → {migrated['timestamp']}")
            except Exception as e:
                stats.errors += 1
                if verbose:
                    print(f"  [line {line_number}] Migration error: {e}", file=sys.stderr)

    if not dry_run:
        with open(output_path, "w", encoding="utf-8") as f:
            for line in output_lines:
                f.write(line + "\n")

    return stats


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Migrate Earthflow audit logs between schema versions.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "--input", "-i", required=True,
        help="Path to input log file (.jsonl)"
    )
    parser.add_argument(
        "--output", "-o", required=True,
        help="Path to output log file (.jsonl)"
    )
    parser.add_argument(
        "--from-version", type=int, default=1, dest="from_version",
        help="Source schema version (default: 1)"
    )
    parser.add_argument(
        "--to-version", type=int, default=2, dest="to_version",
        help="Target schema version (default: 2)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Parse and validate without writing output"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print per-line migration details"
    )
    parser.add_argument(
        "--backup", action="store_true",
        help="Create a .bak copy of the input file before migrating"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"ERROR: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    if output_path.exists() and not args.dry_run:
        print(f"WARNING: Output file already exists: {output_path}")
        confirm = input("Overwrite? [y/N] ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            sys.exit(0)

    if args.backup and not args.dry_run:
        backup_path = input_path.with_suffix(input_path.suffix + ".bak")
        import shutil
        shutil.copy2(input_path, backup_path)
        print(f"Backup created: {backup_path}")

    print(f"\nEarthflow Log Migration")
    print(f"  Source  : {input_path}  ({input_path.stat().st_size / 1024:.1f} KB)")
    print(f"  Target  : {output_path}")
    print(f"  Version : v{args.from_version} → v{args.to_version}")
    if args.dry_run:
        print(f"  Mode    : DRY RUN (no file will be written)")
    print()

    stats = migrate_file(
        input_path=input_path,
        output_path=output_path,
        from_version=args.from_version,
        to_version=args.to_version,
        dry_run=args.dry_run,
        verbose=args.verbose,
    )

    print(stats.summary())

    if stats.errors > 0:
        print(f"\n  ⚠  {stats.errors} errors encountered — review output carefully.")
        sys.exit(2)
    elif args.dry_run:
        print(f"\n  Dry run complete. Use without --dry-run to write output.")
    else:
        print(f"\n  Output written to: {output_path}")


# ─────────────────────────────────────────────
# Self-test (run with: python migrate_logs.py --self-test)
# ─────────────────────────────────────────────

def self_test():
    import tempfile

    print("Running migrate_logs self-test...")

    v1_records = [
        {"ts": 1706784060, "action": "BLOCK", "rule": "rule_001",
         "prompt": "SSN: 123-45-6789", "tenant": "t1"},
        {"ts": 1706784120, "action": "ALLOW", "tenant": "t2",
         "model": "gpt-4", "user_id": "u42"},
        {"ts": 1706784180, "action": "WARN", "rule": "rule_004",
         "prompt": "gender pay gap analysis", "tenant": "t1",
         "latency": 18},
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        for r in v1_records:
            f.write(json.dumps(r) + "\n")
        in_path = Path(f.name)

    out_path = in_path.with_suffix(".v2.jsonl")

    stats = migrate_file(in_path, out_path, from_version=1, to_version=2)

    assert stats.total == 3, f"Expected 3, got {stats.total}"
    assert stats.migrated == 3, f"Expected 3 migrated, got {stats.migrated}"
    assert stats.errors == 0, f"Expected 0 errors, got {stats.errors}"

    with open(out_path) as f:
        results = [json.loads(line) for line in f if line.strip()]

    assert len(results) == 3
    for r in results:
        assert r["schema_version"] == 2
        assert "audit_id" in r
        assert "request_id" in r
        assert "prompt" not in r   # raw prompt must not be stored
        assert r.get("prompt_hash") is None or r["prompt_hash"].startswith("sha256:")
        assert r["_migrated_from"] == 1

    assert results[0]["status"] == "BLOCK"
    assert results[0]["rules_triggered"] == ["rule_001"]
    assert results[1]["status"] == "ALLOW"
    assert results[1]["metadata"].get("user_id") == "u42"
    assert results[2]["latency_ms"] == 18

    # Cleanup
    in_path.unlink()
    out_path.unlink()

    print("  ✓ All self-tests passed.")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    else:
        main()
