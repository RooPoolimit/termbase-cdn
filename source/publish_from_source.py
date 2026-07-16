#!/usr/bin/env python3
"""
Compile source/termbase.published.db and optionally write api/termbase outputs.

This is the script used by the GitHub Action. It supports a safe dry-run mode
that prints diffs without writing API files.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import importlib.util
import json
import os
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compiled_schema import validate_compiled_payload
import runtime_contract as rc
import termbase_signing as ts


DOWNLOAD_URL = "https://roopoolimit.github.io/termbase-cdn/api/termbase/compiled"
SIGNATURE_FILENAME = "SIGNATURE"
PUBKEYS_FILENAME = "PUBKEYS.json"


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


def load_signature(source_dir: str) -> dict[str, Any] | None:
    """Read source/SIGNATURE (the offline signer's output). None if absent."""
    path = os.path.join(source_dir, SIGNATURE_FILENAME)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_trusted_keys(source_dir: str) -> dict[str, bytes]:
    """Read source/PUBKEYS.json -> {key_id: raw 32-byte public key}.

    Non-secret: this is the CI defense-in-depth trust list. The EXTENSION embeds
    its own public key (PR-C) and is the authoritative verifier; this check just
    stops an accidentally- or obviously-wrong payload from being published.
    """
    path = os.path.join(source_dir, PUBKEYS_FILENAME)
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    keys: dict[str, bytes] = {}
    for key_id, b64 in (data or {}).items():
        try:
            keys[key_id] = base64.b64decode(b64, validate=True)
        except (ValueError, TypeError):
            continue  # a malformed key entry is simply not trusted
    return keys


def current_published_publish_seq(api_dir: str) -> int:
    """publish_seq of the currently-published /version, or 0 if none/absent — so
    the first signed publish (seq 1) is strictly greater."""
    path = os.path.join(api_dir, "version")
    if not os.path.exists(path):
        return 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (ValueError, OSError):
        return 0
    seq = data.get("publish_seq", 0)
    return seq if isinstance(seq, int) and not isinstance(seq, bool) else 0


def verify_signature(
    source_dir: str, api_dir: str, raw: bytes, payload: dict[str, Any]
) -> tuple[dict[str, Any] | None, list[str]]:
    """Verify the offline SIGNATURE against the freshly-compiled bytes.

    A signature is mandatory. The extension rejects unsigned manifests, so
    publishing one would strand clients on their previous snapshot.

    Returns (record, errors); an EMPTY errors list means "ok to publish".
    FAIL-CLOSED — a non-empty list must
    abort `apply`. For a PRESENT signature the checks are: well-formed; key_id
    trusted (else "unknown key"); the signed compiled_sha256 equals sha256(raw); the
    Ed25519 signature verifies over PR-A's canonical message (derived fields read
    from the payload); and publish_seq is strictly greater than the currently-
    published one.
    """
    record = load_signature(source_dir)
    if record is None:
        return None, ["SIGNATURE is required for every publish"]
    missing = [f for f in ("key_id", "publish_seq", "compiled_sha256", "signature")
               if f not in record]
    if missing:
        return record, [f"SIGNATURE missing field(s): {missing}"]

    key_id = record["key_id"]
    publish_seq = record["publish_seq"]
    signed_sha = record["compiled_sha256"]

    public_key = load_trusted_keys(source_dir).get(key_id)
    if public_key is None:
        # Without the key the signature cannot be checked at all — stop here.
        return record, [f"unknown key_id {key_id!r} (not in {PUBKEYS_FILENAME})"]

    errors: list[str] = []
    actual_sha = ts.sha256_hex(raw)
    if signed_sha != actual_sha:
        errors.append(f"compiled_sha256 mismatch: signed {signed_sha}, recompiled {actual_sha}")

    try:
        derived = ts.compiled_fields(payload)
    except ValueError as exc:
        return record, errors + [str(exc)]

    # Verifies over the SIGNED compiled_sha256; the mismatch check above is what
    # catches "bytes changed but the old signature was kept".
    if not ts.verify_manifest(
        public_key, record["signature"],
        key_id=key_id, publish_seq=publish_seq, compiled_sha256=signed_sha, **derived,
    ):
        errors.append("Ed25519 signature does not verify")

    prev_seq = current_published_publish_seq(api_dir)
    if not isinstance(publish_seq, int) or isinstance(publish_seq, bool) or publish_seq <= prev_seq:
        errors.append(
            f"publish_seq must be strictly greater than the current publish_seq "
            f"({publish_seq!r} <= {prev_seq})"
        )
    return record, errors


def build_version(
    payload: dict[str, Any], checksum: str, signature_record: dict[str, Any] | None = None
) -> dict[str, Any]:
    version: dict[str, Any] = {
        "schema_version": payload.get("schema_version", "v3"),
        "termbase_version": payload.get("termbase_version") or datetime.date.today().isoformat(),
        "min_extension_version": payload.get("min_extension_version", "0.0.0"),
        "checksum": checksum,
        "download_url": DOWNLOAD_URL,
        "generated_at": datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
    }
    if signature_record is not None:
        version["key_id"] = signature_record["key_id"]
        version["publish_seq"] = signature_record["publish_seq"]
        version["compiled_sha256"] = signature_record["compiled_sha256"]
        version["signature"] = signature_record["signature"]
    return version


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

    # Schema-valid bytes can still silently lose a reviewed alias, a
    # symbol-tailed term, the intended domain, or a keep strategy. Enforce those
    # runtime semantics before signature/apply handling.
    contract_path = os.path.join(source_dir, "runtime_contract.json")
    try:
        contract = rc.load_runtime_contract(contract_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"FATAL: cannot load runtime contract: {exc}") from exc
    runtime_errors = rc.validate_runtime_contract(payload, contract)
    if runtime_errors:
        raise SystemExit(
            "FATAL: compiled payload failed the runtime contract: "
            + "; ".join(runtime_errors)
        )

    # Signature gate (PR-B): verify the offline SIGNATURE against the freshly
    # compiled bytes. FAIL-CLOSED on apply; dry-run reports and continues.
    signature_record, sig_errors = verify_signature(source_dir, api_dir, raw, payload)
    for err in sig_errors:
        print(f"WARNING: signature check: {err}")
    if mode == "apply" and sig_errors:
        raise SystemExit(
            "FATAL: signature verification failed; refusing to apply: " + "; ".join(sig_errors)
        )

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
    if signature_record and not sig_errors:
        print(f"  signed: key_id={signature_record['key_id']} publish_seq={signature_record['publish_seq']}")

    version = build_version(payload, checksum, None if sig_errors else signature_record)
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
        "signature_errors": sig_errors,
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
