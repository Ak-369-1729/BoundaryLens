"""Response normalization so that comparisons ignore volatile fields."""

from __future__ import annotations

from typing import Any

_MISSING = object()


def strip_fields(value: Any, ignore: set[str], _path: str = "") -> Any:
    """Remove keys whose name or dotted path is listed in ``ignore``."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            path = f"{_path}.{key}" if _path else str(key)
            if key in ignore or path in ignore:
                continue
            out[key] = strip_fields(item, ignore, path)
        return out
    if isinstance(value, list):
        return [strip_fields(item, ignore, _path) for item in value]
    return value


def shape(value: Any) -> Any:
    """Type skeleton of a JSON value; lists are represented by their first element."""
    if isinstance(value, dict):
        return {k: shape(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [shape(value[0])] if value else []
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if value is None:
        return "null"
    return "string"


def get_path(value: Any, path: str, default: Any = None) -> Any:
    current = value
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return default
    return current


def compare(baseline: Any, observed: Any, ignore: set[str], fields: list[str]) -> dict:
    """Compare two parsed JSON bodies after removing volatile fields."""
    b = strip_fields(baseline, ignore)
    o = strip_fields(observed, ignore)
    selected = []
    for field in fields:
        bv, ov = get_path(b, field, _MISSING), get_path(o, field, _MISSING)
        selected.append({
            "field": field,
            "baseline": None if bv is _MISSING else bv,
            "observed": None if ov is _MISSING else ov,
            "equal": bv is not _MISSING and bv == ov,
        })
    return {
        "ignored_fields": sorted(ignore),
        "structure_equal": shape(b) == shape(o),
        "body_equal": b == o,
        "fields": selected,
    }
