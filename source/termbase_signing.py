"""Ed25519 offline payload-signing primitives for the termbase publish chain.

This module is the SINGLE source of truth for what gets signed: the canonical
signed message. The offline signer (sign_compiled.py) and every verifier — the
future CDN-side pre-publish check (PR-B) and the extension's runtime check
(PR-C) — MUST build the same bytes from the same fields, or a signature made by
one will not verify in another. Centralizing the builder here is how we keep
them from drifting.

Design: docs/superpowers/specs/2026-06-23-ed25519-termbase-signing-design.md
(in the gloss-translator repo).

Used OFFLINE — the private key never reaches CI or the CDN. Depends on
`cryptography` for the Ed25519 primitive (a backend tooling dependency only;
it does not reach the compiled payload clients download).
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# Domain-separation prefix. Bump the version suffix if the SIGNED field set or
# its order ever changes, so an old signature can never validate a new layout.
CANONICAL_PREFIX = "termbase-cdn-sig/v1"

# Fields covered by the signature, in canonical order. key_id is FIRST and MUST
# stay covered — an uncovered key_id could be swapped to redirect a verifier to a
# different embedded key.
SIGNED_FIELDS = (
    "key_id",
    "publish_seq",
    "compiled_sha256",
    "termbase_version",
    "min_extension_version",
    "schema_version",
)

# Fields the signer DERIVES from the compiled payload (not carried in SIGNATURE).
# Read in exactly one place so the signer and verifier can't disagree on them.
_COMPILED_DERIVED_FIELDS = ("schema_version", "termbase_version", "min_extension_version")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_clean_str(name: str, value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    if not value:
        raise ValueError(f"{name} must be non-empty")
    if "\n" in value or "\r" in value:
        raise ValueError(f"{name} must not contain a newline (the canonical delimiter)")
    return value


def canonical_signed_message(
    *,
    key_id: str,
    publish_seq: int,
    compiled_sha256: str,
    termbase_version: str,
    min_extension_version: str,
    schema_version: str,
) -> bytes:
    """The exact bytes that are signed: domain-separated, newline-delimited.

    Every string field is rendered newline-free (rejected otherwise), so the
    '\\n' delimiter is unambiguous. publish_seq is a positive integer (>= 1)
    rendered in base 10. The field order matches SIGNED_FIELDS.
    """
    # bool is an int subclass — reject it explicitly so True/False can't sneak in.
    if isinstance(publish_seq, bool) or not isinstance(publish_seq, int):
        raise TypeError("publish_seq must be an int")
    # Strictly positive: the first signed publish is seq 1, so 0 (and negatives)
    # are never valid sequence numbers.
    if publish_seq < 1:
        raise ValueError("publish_seq must be a positive integer (>= 1)")

    rendered = {
        "key_id": _require_clean_str("key_id", key_id),
        "publish_seq": str(publish_seq),
        "compiled_sha256": _require_clean_str("compiled_sha256", compiled_sha256),
        "termbase_version": _require_clean_str("termbase_version", termbase_version),
        "min_extension_version": _require_clean_str("min_extension_version", min_extension_version),
        "schema_version": _require_clean_str("schema_version", schema_version),
    }
    lines = [CANONICAL_PREFIX] + [rendered[name] for name in SIGNED_FIELDS]
    return "\n".join(lines).encode("utf-8")


def compiled_fields(payload: dict[str, Any]) -> dict[str, str]:
    """Extract the signer-derived fields from a compiled payload dict — the one
    place both signer and verifier read them, so they can't drift."""
    out: dict[str, str] = {}
    for name in _COMPILED_DERIVED_FIELDS:
        value = payload.get(name)
        if not isinstance(value, str) or not value:
            raise ValueError(f"compiled payload missing/invalid required field: {name!r}")
        out[name] = value
    return out


# ── keys ──────────────────────────────────────────────────────────────────────
def private_key_from_seed(seed: bytes) -> Ed25519PrivateKey:
    """Load a private key from its 32-byte seed (deterministic)."""
    return Ed25519PrivateKey.from_private_bytes(seed)


def generate_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    """Generate a fresh keypair; returns (private_key, raw_public_key_bytes)."""
    sk = Ed25519PrivateKey.generate()
    return sk, public_key_raw(sk)


def public_key_raw(private_key: Ed25519PrivateKey) -> bytes:
    """The 32-byte raw public key (what the extension embeds, base64-encoded)."""
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


# ── sign / verify ─────────────────────────────────────────────────────────────
def sign_manifest(private_key: Ed25519PrivateKey, **fields: Any) -> str:
    """Sign the canonical message for `fields`; returns a base64 signature.

    Strict — raises if any field is invalid; the signer must never sign garbage.
    """
    message = canonical_signed_message(**fields)
    signature = private_key.sign(message)
    return base64.b64encode(signature).decode("ascii")


def verify_manifest(public_key_raw_bytes: bytes, signature_b64: str, **fields: Any) -> bool:
    """Verify a base64 signature over the canonical message for `fields`.

    Lenient — returns False (never raises) on a bad signature, bad base64, a
    malformed public key, or fields that can't form a canonical message.
    (binascii.Error subclasses ValueError, so it's covered.)
    """
    try:
        message = canonical_signed_message(**fields)
        signature = base64.b64decode(signature_b64, validate=True)
        public_key = Ed25519PublicKey.from_public_bytes(public_key_raw_bytes)
        public_key.verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
