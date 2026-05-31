"""Shared schema contract for compiled termbase payloads."""

from __future__ import annotations

from typing import Any


COMPILED_SCHEMA_VERSION = "v3"

KEEP_ENGLISH_MODES = frozenset({
    "always",
    "preferred",
    "contextual",
    "never",
})

REQUIRED_COMPILED_TERM_FIELDS = frozenset({
    "source_term",
    "target_term",
    "source_lang",
    "target_lang",
    "preferred_translation",
    "keep_english_mode",
    "aliases",
    "wrong_translations",
    "domain_tags",
    "contexts",
    "relations",
})


def validate_compiled_payload(payload: dict[str, Any]) -> None:
    """Raise ValueError if a compiled payload does not satisfy the runtime contract."""
    if payload.get("schema_version") != COMPILED_SCHEMA_VERSION:
        raise ValueError(f"unexpected schema_version={payload.get('schema_version')!r}")

    terms = payload.get("terms")
    if not isinstance(terms, list) or not terms:
        raise ValueError("compiled payload has no terms array")

    for idx, term in enumerate(terms):
        if not isinstance(term, dict):
            raise ValueError(f"compiled term at index {idx} is not an object")
        missing = REQUIRED_COMPILED_TERM_FIELDS - set(term)
        if missing:
            label = term.get("source_term", idx)
            raise ValueError(f"compiled term {label!r} is missing fields: {sorted(missing)}")
        if term.get("keep_english_mode") not in KEEP_ENGLISH_MODES:
            label = term.get("source_term", idx)
            raise ValueError(f"compiled term {label!r} has invalid keep_english_mode")
