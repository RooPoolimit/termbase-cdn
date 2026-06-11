#!/usr/bin/env python3
"""
Compile source/termbase.published.db and optionally write api/termbase outputs.

This is the script used by the GitHub Action. It supports a safe dry-run mode
that prints diffs without writing API files.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compiled_schema import validate_compiled_payload


DOWNLOAD_URL = "https://roopoolimit.github.io/termbase-cdn/api/termbase/compiled"


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_source_version(path: str) -> dict[str, str]:
    expected: dict[str, str] = {}
    in_files = False
    if not os.path.exists(path):
        return expected
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if line == "files:":
                in_files = True
                continue
            if in_files and line.startswith("  ") and ": " in line:
                name, digest = line.strip().split(": ", 1)
                expected[name] = digest.strip()
    return expected


def check_source_hashes(source_dir: str) -> list[str]:
    expected = parse_source_version(os.path.join(source_dir, "SOURCE_VERSION.txt"))
    warnings: list[str] = []
    for name, expected_hash in expected.items():
        path = os.path.join(source_dir, name)
        if not os.path.exists(path):
            warnings.append(f"{name}: missing; expected {expected_hash}")
            continue
        actual = sha256_file(path)
        if actual != expected_hash:
            warnings.append(f"{name}: expected {expected_hash}, actual {actual}")
    return warnings


def load_compiler(source_dir: str):
    compiler_path = os.path.join(source_dir, "termbase_compiler.py")
    if source_dir not in sys.path:
        sys.path.insert(0, source_dir)
    spec = importlib.util.spec_from_file_location("termbase_compiler_action", compiler_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load compiler from {compiler_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def compile_from_source(source_dir: str) -> tuple[bytes, str, dict[str, Any]]:
    compiler = load_compiler(source_dir)
    compiler.invalidate_termbase_cache()
    raw, checksum = compiler.compile_termbase()
    payload = json.loads(raw.decode("utf-8"))
    return raw, checksum, payload


def load_previous(api_dir: str) -> dict[str, Any] | None:
    path = os.path.join(api_dir, "compiled")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as f:
            return json.loads(f.read().decode("utf-8"))
    except Exception as exc:
        print(f"WARNING: cannot read previous compiled at {path}: {exc}")
        return None


def build_version(payload: dict[str, Any], checksum: str) -> dict[str, str]:
    return {
        "schema_version": payload.get("schema_version", "v3"),
        "termbase_version": payload.get("termbase_version") or datetime.date.today().isoformat(),
        "min_extension_version": payload.get("min_extension_version", "0.0.0"),
        "checksum": checksum,
        "download_url": DOWNLOAD_URL,
        "generated_at": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }


def publish(source_dir: str, repo_root: str, mode: str = "dry-run") -> dict[str, Any]:
    if mode not in {"dry-run", "apply"}:
        raise ValueError("mode must be 'dry-run' or 'apply'")

    source_dir = os.path.abspath(source_dir)
    repo_root = os.path.abspath(repo_root)
    api_dir = os.path.join(repo_root, "api", "termbase")

    hash_warnings = check_source_hashes(source_dir)
    for warning in hash_warnings:
        print(f"WARNING: SOURCE_VERSION hash mismatch: {warning}")
    # apply must refuse a snapshot whose files don't match what sync_to_cdn.py
    # recorded — a tampered/partially-synced source dir would otherwise publish
    # straight to production. dry-run keeps reporting only, so a mismatch can
    # still be inspected from the Action logs.
    if mode == "apply" and hash_warnings:
        raise SystemExit(
            "FATAL: SOURCE_VERSION hash mismatch; refusing to apply. "
            "Re-run the backend sync (python sync_to_cdn.py) and commit a consistent snapshot."
        )

    raw, checksum, payload = compile_from_source(source_dir)
    # Schema contract gate: this is the LAST check before bytes reach the CDN.
    # It blocks e.g. an accidentally empty published.db (payload with no terms)
    # or a compiler/schema drift from publishing.
    try:
        validate_compiled_payload(payload)
    except ValueError as exc:
        raise SystemExit(f"FATAL: compiled payload failed the schema contract: {exc}")
    previous = load_previous(api_dir)
    previous_count = len(previous.get("terms", [])) if previous else 0
    current_count = len(payload.get("terms", []))
    delta = current_count - previous_count
    sign = "+" if delta >= 0 else ""

    print("Compiled diff:")
    print(f"  terms: {previous_count} -> {current_count} ({sign}{delta})")
    print(f"  checksum: {checksum}")
    print(f"  bytes: {len(raw)}")
    print(f"  mode: {mode}")

    version = build_version(payload, checksum)
    applied = mode == "apply"
    if applied:
        os.makedirs(api_dir, exist_ok=True)
        with open(os.path.join(api_dir, "compiled"), "wb") as f:
            f.write(raw)
        with open(os.path.join(api_dir, "version"), "w", encoding="utf-8") as f:
            json.dump(version, f, ensure_ascii=False, indent=2)
            f.write("\n")
        print(f"Wrote {os.path.join(api_dir, 'compiled')}")
        print(f"Wrote {os.path.join(api_dir, 'version')}")
    else:
        print("Dry-run only: did not write api/termbase files.")

    return {
        "applied": applied,
        "hash_warnings": hash_warnings,
        "previous_count": previous_count,
        "current_count": current_count,
        "delta": delta,
        "checksum": checksum,
        "bytes": len(raw),
        "version": version,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Publish termbase CDN files from source snapshot.")
    parser.add_argument("--mode", choices=["dry-run", "apply"], default="dry-run")
    parser.add_argument("--source-dir", default=os.path.dirname(os.path.abspath(__file__)))
    parser.add_argument("--repo-root", default=os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))
    args = parser.parse_args(argv)
    publish(args.source_dir, args.repo_root, mode=args.mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
