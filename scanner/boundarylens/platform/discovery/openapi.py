"""OpenAPI 3.x / Swagger 2.0 import -> normalized endpoints."""

from __future__ import annotations

import json
from typing import Any

import yaml

from ..endpoint import Endpoint

HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}


class ImportError_(ValueError):
    pass


def parse_spec(text: str) -> dict:
    text = text.strip()
    try:
        data = json.loads(text)
    except ValueError:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ImportError_(f"not valid JSON or YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ImportError_("OpenAPI document must be a mapping")
    if "paths" not in data:
        raise ImportError_("OpenAPI document has no 'paths'")
    return data


def _schema_fields(schema: dict, root: dict, depth: int = 0) -> list[str]:
    if not isinstance(schema, dict) or depth > 4:
        return []
    if "$ref" in schema:
        schema = _resolve_ref(schema["$ref"], root) or {}
    props = schema.get("properties")
    if isinstance(props, dict):
        return list(props.keys())
    items = schema.get("items")
    if isinstance(items, dict):
        return _schema_fields(items, root, depth + 1)
    return []


def _resolve_ref(ref: str, root: dict) -> dict | None:
    if not ref.startswith("#/"):
        return None
    node: Any = root
    for part in ref[2:].split("/"):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node if isinstance(node, dict) else None


def _response_fields(operation: dict, root: dict) -> list[str]:
    responses = operation.get("responses", {})
    for code in ("200", "201", 200, 201, "default"):
        resp = responses.get(code)
        if not isinstance(resp, dict):
            continue
        content = resp.get("content", {})
        for media in content.values():
            fields = _schema_fields(media.get("schema", {}), root)
            if fields:
                return fields
        if "schema" in resp:  # swagger 2.0
            return _schema_fields(resp["schema"], root)
    return []


def _request_fields(operation: dict, root: dict) -> list[str]:
    body = operation.get("requestBody", {})
    if isinstance(body, dict):
        for media in body.get("content", {}).values():
            fields = _schema_fields(media.get("schema", {}), root)
            if fields:
                return fields
    return []


def import_openapi(text: str) -> list[Endpoint]:
    spec = parse_spec(text)
    global_security = _security_names(spec.get("security", []))
    base = _swagger_base(spec)
    endpoints: list[Endpoint] = []
    for raw_path, item in spec.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        common_params = item.get("parameters", [])
        for method, operation in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            params = list(common_params) + list(operation.get("parameters", []))
            path_params = [p["name"] for p in params if isinstance(p, dict) and p.get("in") == "path"]
            query_params = [p["name"] for p in params if isinstance(p, dict) and p.get("in") == "query"]
            sec = operation.get("security", None)
            sec_names = _security_names(sec) if sec is not None else global_security
            requires_auth = None
            if sec is not None:
                requires_auth = bool(sec_names) and sec != []
            elif spec.get("security") is not None:
                requires_auth = bool(global_security)
            endpoints.append(Endpoint(
                method=method, path=base + raw_path, source="openapi",
                operation_id=operation.get("operationId"),
                tags=list(operation.get("tags", [])),
                path_params=path_params, query_params=query_params,
                security=sec_names, requires_auth=requires_auth,
                request_body_fields=_request_fields(operation, spec),
                response_fields=_response_fields(operation, spec),
                summary=operation.get("summary") or operation.get("description", "")[:160],
            ))
    return endpoints


def _security_names(security: Any) -> list[str]:
    names: list[str] = []
    if isinstance(security, list):
        for req in security:
            if isinstance(req, dict):
                names.extend(req.keys())
    return sorted(set(names))


def _swagger_base(spec: dict) -> str:
    base = spec.get("basePath", "")  # swagger 2.0
    if isinstance(base, str) and base not in ("", "/"):
        return base.rstrip("/")
    return ""
