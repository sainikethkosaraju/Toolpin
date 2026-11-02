"""Deterministic canonicalisation of tool definitions.

Equivalent JSON (key order, whitespace, escapes) canonicalises identically; ANY semantic change
(including a single character in a description) changes the hash. Strings are NOT unicode-
normalised on purpose: normalisation would hide look-alike substitutions.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any


def _check(o: Any) -> Any:
    if isinstance(o, float) and (math.isnan(o) or math.isinf(o)):
        raise ValueError("NaN/Infinity cannot appear in a tool definition")
    if isinstance(o, dict):
        return {str(k): _check(v) for k, v in o.items()}
    if isinstance(o, list | tuple):
        return [_check(v) for v in o]
    return o


def canonical_json(obj: Any) -> str:
    return json.dumps(_check(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def tool_to_dict(tool: Any) -> dict[str, Any]:
    """Accept a dict (tools/list entry) or an SDK Tool model; return a camelCase wire dict."""
    if isinstance(tool, dict):
        d = dict(tool)
    elif hasattr(tool, "model_dump"):
        d = tool.model_dump(by_alias=True, exclude_none=True, mode="json")
    else:
        raise TypeError(f"cannot read tool definition from {type(tool)}")
    if "input_schema" in d and "inputSchema" not in d:
        d["inputSchema"] = d.pop("input_schema")
    if "output_schema" in d and "outputSchema" not in d:
        d["outputSchema"] = d.pop("output_schema")
    return {k: v for k, v in d.items() if v is not None}


def tool_hash(tool: Any) -> str:
    return hashlib.sha256(canonical_json(tool_to_dict(tool)).encode()).hexdigest()


def args_hash(arguments: dict[str, Any] | None) -> str:
    return hashlib.sha256(canonical_json(arguments or {}).encode()).hexdigest()
