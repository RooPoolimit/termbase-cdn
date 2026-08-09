"""Semantic release contract for the compiled termbase payload.

The JSON schema validator can prove that a payload is structurally valid, but
it cannot prove that important runtime spellings still resolve to the intended
entry.  This module checks a small, reviewed set of end-to-end invariants (for
example ``Finetuning`` -> ``Fine-tuning`` and symbol-tailed ``C++``).
"""

from __future__ import annotations

import json
import os
from typing import Any


DEFAULT_CONTRACT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "runtime_contract.json"
)


def load_runtime_contract(path: str = DEFAULT_CONTRACT_PATH) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        contract = json.load(f)
    if not isinstance(contract, dict):
        raise ValueError("runtime contract root must be an object")
    if contract.get("schema_version") != 1:
        raise ValueError("unsupported runtime contract schema_version")
    cases = contract.get("required_surfaces")
    if not isinstance(cases, list):
        raise ValueError("runtime contract required_surfaces must be an array")
    return contract


def _normalized(value: Any) -> str:
    return str(value or "").strip().casefold()


def validate_runtime_contract(
    payload: dict[str, Any], contract: dict[str, Any] | None = None
) -> list[str]:
    """Return semantic contract violations; an empty list means pass."""
    contract = contract if contract is not None else load_runtime_contract()
    cases = contract.get("required_surfaces")
    if not isinstance(cases, list):
        return ["required_surfaces must be an array"]
    terms = payload.get("terms") if isinstance(payload, dict) else None
    if not isinstance(terms, list):
        return ["compiled payload terms must be an array"]

    errors: list[str] = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            errors.append(f"case[{index}] must be an object")
            continue
        case_id = str(case.get("id") or f"case[{index}]")
        surface = case.get("surface")
        canonical = case.get("canonical_source")
        if not isinstance(surface, str) or not surface.strip():
            errors.append(f"{case_id}: surface must be a non-empty string")
            continue
        if not isinstance(canonical, str) or not canonical.strip():
            errors.append(f"{case_id}: canonical_source must be a non-empty string")
            continue

        surface_key = _normalized(surface)
        candidates = []
        for term in terms:
            if not isinstance(term, dict):
                continue
            surfaces = [term.get("source_term"), *(term.get("aliases") or [])]
            if any(_normalized(item) == surface_key for item in surfaces):
                candidates.append(term)

        matches = [
            term for term in candidates
            if _normalized(term.get("source_term")) == _normalized(canonical)
        ]
        if not candidates:
            errors.append(f"{case_id}: required surface {surface!r} is missing")
            continue
        allow_other_candidates = case.get("allow_other_candidates") is True
        if len(matches) != 1 or (len(candidates) != 1 and not allow_other_candidates):
            found = [str(term.get("source_term") or "") for term in candidates]
            errors.append(
                f"{case_id}: surface {surface!r} must resolve exactly once to "
                f"{canonical!r}; candidates={found}"
            )
            continue

        term = matches[0]
        expected_fields = {
            "target_term": case.get("target_term"),
            "keep_english_mode": case.get("keep_english_mode"),
            "policy_mode": case.get("policy_mode"),
        }
        for field, expected in expected_fields.items():
            if expected is not None and term.get(field) != expected:
                errors.append(
                    f"{case_id}: {field} expected {expected!r}, got {term.get(field)!r}"
                )

        domain = case.get("domain")
        if domain is not None:
            tags = term.get("domain_tags") or []
            if not isinstance(tags, list) or _normalized(domain) not in {
                _normalized(tag) for tag in tags
            }:
                errors.append(
                    f"{case_id}: expected domain {domain!r}, got {tags!r}"
                )

        if "ungated" in case:
            actual_ungated = term.get("ungated") == 1
            if actual_ungated is not bool(case["ungated"]):
                errors.append(
                    f"{case_id}: ungated expected {bool(case['ungated'])!r}, "
                    f"got {actual_ungated!r}"
                )

    return errors


def require_runtime_contract(
    payload: dict[str, Any], contract: dict[str, Any] | None = None
) -> None:
    errors = validate_runtime_contract(payload, contract)
    if errors:
        raise ValueError("; ".join(errors))
