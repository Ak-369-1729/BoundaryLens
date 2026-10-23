"""HAR (HTTP Archive) import -> normalized endpoints.

Focuses on API traffic (JSON or api-path requests), deduplicates, and conservatively
infers parameterized paths (/api/orders/123 and /api/orders/456 -> /api/orders/{id}).
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit

from ..endpoint import Endpoint, looks_like_identifier, templatize_path

_STATIC_SUFFIXES = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2",
                    ".ico", ".map", ".ttf", ".webp", ".mp4", ".html")


def import_har(text: str) -> list[Endpoint]:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"not valid JSON: {exc}") from exc
    entries = (data.get("log") or {}).get("entries")
    if not isinstance(entries, list):
        raise ValueError("not a HAR file (missing log.entries)")

    # Group concrete observed paths by (method, template) to infer parameters only
    # when several distinct identifier values are seen at the same position.
    raw: list[tuple[str, str, dict]] = []
    for entry in entries:
        req = entry.get("request", {})
        method = req.get("method", "GET")
        url = req.get("url", "")
        path = urlsplit(url).path or "/"
        if _is_static(path) or not _is_api_like(path, entry):
            continue
        query = [q.get("name", "") for q in req.get("queryString", []) if isinstance(q, dict)]
        resp_fields = _response_fields(entry)
        raw.append((method.upper(), path, {"query": query, "response_fields": resp_fields,
                                           "requires_auth": _has_auth(req)}))

    # Count identifier variety per (method, template-with-position-markers)
    variety: dict[tuple, set] = defaultdict(set)
    for method, path, _ in raw:
        segs = path.split("/")
        for i, seg in enumerate(segs):
            if looks_like_identifier(seg):
                variety[(method, len(segs), i)].add(seg)

    endpoints: list[Endpoint] = []
    seen: set[tuple[str, str]] = set()
    for method, path, meta in raw:
        segs = path.split("/")
        templated = []
        for i, seg in enumerate(segs):
            if looks_like_identifier(seg) and len(variety[(method, len(segs), i)]) >= 2:
                templated.append("{id}")
            else:
                templated.append(seg)
        tpath = "/".join(templated) or "/"
        key = (method, tpath)
        if key in seen:
            continue
        seen.add(key)
        endpoints.append(Endpoint(
            method=method, path=tpath, source="har",
            query_params=sorted(set(meta["query"])),
            response_fields=meta["response_fields"],
            requires_auth=meta["requires_auth"] or None,
        ))
    return endpoints


def _is_static(path: str) -> bool:
    return path.lower().endswith(_STATIC_SUFFIXES)


def _is_api_like(path: str, entry: dict) -> bool:
    if "/api" in path or "/v1" in path or "/v2" in path:
        return True
    mime = ((entry.get("response") or {}).get("content") or {}).get("mimeType", "")
    return "json" in mime.lower()


def _has_auth(req: dict) -> bool:
    for h in req.get("headers", []):
        if isinstance(h, dict) and h.get("name", "").lower() in ("authorization", "cookie"):
            return True
    return False


def _response_fields(entry: dict) -> list[str]:
    content = (entry.get("response") or {}).get("content") or {}
    text = content.get("text")
    if not text or "json" not in content.get("mimeType", "").lower():
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if isinstance(data, dict):
        return list(data.keys())[:30]
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return list(data[0].keys())[:30]
    return []
