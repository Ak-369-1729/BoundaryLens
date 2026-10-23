"""Postman Collection v2.1 import -> normalized endpoints.

Unsupported scripting (pre-request/test scripts, complex auth flows) is ignored rather
than failing the import.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..endpoint import Endpoint

# {{var}} -> {var} so Postman variables become path parameters.
_VAR = re.compile(r"\{\{([^}]+)\}\}")


def import_postman(text: str) -> list[Endpoint]:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or "item" not in data:
        raise ValueError("not a Postman collection (missing 'item')")
    endpoints: list[Endpoint] = []
    _walk(data.get("item", []), endpoints)
    return endpoints


def _walk(items: list, out: list[Endpoint]) -> None:
    for entry in items:
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("item"), list):  # folder
            _walk(entry["item"], out)
            continue
        request = entry.get("request")
        if not isinstance(request, dict):
            continue
        ep = _endpoint_from_request(request, entry.get("name", ""))
        if ep:
            out.append(ep)


def _endpoint_from_request(request: dict, name: str) -> Endpoint | None:
    method = str(request.get("method", "GET"))
    url = request.get("url")
    path, query = _extract_path(url)
    if path is None:
        return None
    headers = request.get("header", [])
    header_names = [h.get("key", "") for h in headers if isinstance(h, dict) and not h.get("disabled")]
    auth = request.get("auth", {})
    security = [auth.get("type")] if isinstance(auth, dict) and auth.get("type") else []
    requires_auth = bool(security) or any(h.lower() in ("authorization", "cookie") for h in header_names)
    body_fields = _body_fields(request.get("body"))
    return Endpoint(
        method=method, path=path, source="postman", summary=name,
        query_params=query, security=[s for s in security if s],
        requires_auth=requires_auth or None, request_body_fields=body_fields,
    )


def _templatize(path: str) -> str:
    return _VAR.sub(r"{\1}", path)


def _extract_path(url: Any) -> tuple[str | None, list[str]]:
    if isinstance(url, str):
        raw = _VAR.sub(r"{\1}", url)
        from ..endpoint import path_of
        # strip scheme/host if present
        p = path_of(raw) if "://" in raw else raw.split("?", 1)[0]
        return (_normalize(p), [])
    if isinstance(url, dict):
        segs = url.get("path", [])
        if isinstance(segs, list):
            path = "/" + "/".join(_templatize(str(s)) for s in segs)
        else:
            path = _templatize(str(url.get("raw", "")))
        query = [q.get("key", "") for q in url.get("query", []) if isinstance(q, dict) and q.get("key")]
        return (_normalize(path), query)
    return (None, [])


def _normalize(path: str) -> str:
    path = path.split("?", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    return path or "/"


def _body_fields(body: Any) -> list[str]:
    if not isinstance(body, dict):
        return []
    if body.get("mode") == "raw" and body.get("raw"):
        try:
            parsed = json.loads(body["raw"])
            if isinstance(parsed, dict):
                return list(parsed.keys())
        except ValueError:
            return []
    if body.get("mode") == "urlencoded":
        return [f.get("key", "") for f in body.get("urlencoded", []) if isinstance(f, dict)]
    return []
