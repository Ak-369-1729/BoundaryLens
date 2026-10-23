"""Discovery adapters: OpenAPI, Postman, HAR -> normalized endpoints."""

import json

import pytest

from boundarylens.platform.discovery import import_har, import_openapi, import_postman
from boundarylens.platform.endpoint import Endpoint, dedupe_endpoints, normalize_template, templatize_path


def test_openapi_json_extracts_methods_paths_params():
    schema = {"properties": {"id": {}, "email": {}}}
    get_users = {
        "operationId": "getUser", "tags": ["users"],
        "parameters": [{"name": "id", "in": "path"}, {"name": "expand", "in": "query"}],
        "security": [{"bearer": []}],
        "responses": {"200": {"content": {"application/json": {"schema": schema}}}},
    }
    spec = {"openapi": "3.0.0", "paths": {
        "/api/users/{id}": {"get": get_users},
        "/api/admin/stats": {"get": {"operationId": "stats", "responses": {}}},
    }}
    eps = import_openapi(json.dumps(spec))
    users = next(e for e in eps if e.path == "/api/users/{id}")
    assert users.method == "GET"
    assert users.path_params == ["id"]
    assert users.query_params == ["expand"]
    assert users.security == ["bearer"]
    assert users.requires_auth is True
    assert "email" in users.response_fields


def test_openapi_yaml_supported():
    yaml_spec = """
openapi: 3.0.0
paths:
  /api/orders/{orderId}:
    get:
      operationId: getOrder
      responses:
        '200': {description: ok}
"""
    eps = import_openapi(yaml_spec)
    assert eps[0].path == "/api/orders/{orderId}"
    assert eps[0].path_params == ["orderId"]


def test_openapi_invalid_raises():
    with pytest.raises(ValueError):
        import_openapi("{}")


def test_postman_v21_extracts_requests():
    coll = {"info": {"schema": "v2.1.0"}, "item": [
        {"name": "Get order", "request": {"method": "GET",
         "url": {"raw": "{{base}}/api/orders/{{orderId}}", "path": ["api", "orders", "{{orderId}}"]},
         "header": [{"key": "Authorization", "value": "Bearer x"}]}},
        {"name": "folder", "item": [
            {"name": "List", "request": {"method": "GET", "url": {"path": ["api", "orders"]}}}]},
    ]}
    eps = import_postman(json.dumps(coll))
    paths = {e.path for e in eps}
    assert "/api/orders/{orderId}" in paths
    assert "/api/orders" in paths
    order = next(e for e in eps if e.path == "/api/orders/{orderId}")
    assert order.requires_auth is True


def test_postman_ignores_unsupported_without_failing():
    coll = {"info": {}, "item": [
        {"name": "scripted", "event": [{"listen": "test", "script": {"exec": ["pm.test()"]}}],
         "request": {"method": "GET", "url": {"path": ["api", "x"]}}}]}
    eps = import_postman(json.dumps(coll))
    assert eps[0].path == "/api/x"


def test_har_infers_parameterized_paths_and_dedups():
    har = {"log": {"entries": [
        _entry("GET", "http://h/api/orders/123"),
        _entry("GET", "http://h/api/orders/456"),
        _entry("GET", "http://h/app.js", mime="application/javascript"),
    ]}}
    eps = import_har(json.dumps(har))
    paths = {e.path for e in eps}
    assert "/api/orders/{id}" in paths          # two distinct ids -> parameterized
    assert not any(e.path.endswith(".js") for e in eps)  # static asset dropped


def test_har_single_id_not_over_inferred():
    har = {"log": {"entries": [_entry("GET", "http://h/api/orders/123")]}}
    eps = import_har(json.dumps(har))
    assert eps[0].path == "/api/orders/123"     # only one value seen -> not parameterized


def test_normalize_and_templatize():
    assert normalize_template("/x/{id}") == normalize_template("/x/{orderId}")
    assert templatize_path("/api/orders/ord_29873") == "/api/orders/{id}"


def test_dedupe_prefers_richer_record():
    poor = Endpoint(method="GET", path="/api/x", source="har")
    rich = Endpoint(method="GET", path="/api/x", source="openapi", operation_id="getX",
                    security=["bearer"], response_fields=["id"])
    merged = dedupe_endpoints([poor, rich])
    assert len(merged) == 1
    assert merged[0].source == "openapi"


def _entry(method, url, mime="application/json"):
    return {"request": {"method": method, "url": url, "headers": [], "queryString": []},
            "response": {"status": 200, "content": {"mimeType": mime, "text": "{}"}}}
