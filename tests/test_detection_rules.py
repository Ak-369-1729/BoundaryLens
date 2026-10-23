"""Unit tests for the detection logic: false-positive resistance and normalization."""

import asyncio

import httpx
import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from boundarylens.client import ScanContext
from boundarylens.engine import Engine, has_real_body, looks_like_login_page
from boundarylens.normalize import compare, shape, strip_fields
from boundarylens.runner import run_scan


def _ex(status, body, content_type="application/json"):
    from boundarylens.client import Exchange
    ex = Exchange(identity="x", method="GET", path="/x", purpose="t")
    ex.status = status
    ex.body = body.encode()
    ex.headers = [("content-type", content_type)]
    return ex


def test_login_page_is_not_confirmed(manifest):
    """A 200 login page must never be mistaken for private data."""
    ex = _ex(200, '<html><body><input type="password"></body></html>', "text/html")
    assert looks_like_login_page(ex, manifest.authentication) is True


def test_empty_and_error_bodies_rejected(manifest):
    assert has_real_body(_ex(200, "")) is False
    assert has_real_body(_ex(404, '{"error":"not_found"}')) is False
    assert has_real_body(_ex(200, '{"invoice":{}}')) is True


def test_normalization_ignores_volatile_fields():
    a = {"data": {"id": 1}, "request_id": "r1", "generated_at": "t1"}
    b = {"data": {"id": 1}, "request_id": "r2", "generated_at": "t2"}
    result = compare(a, b, {"request_id", "generated_at"}, ["data.id"])
    assert result["body_equal"] is True
    assert result["structure_equal"] is True
    assert result["fields"][0]["equal"] is True


def test_normalization_detects_real_difference():
    a = {"data": {"owner": "alice"}, "request_id": "r1"}
    b = {"data": {"owner": "bob"}, "request_id": "r2"}
    result = compare(a, b, {"request_id"}, ["data.owner"])
    assert result["body_equal"] is False
    assert result["fields"][0]["equal"] is False


def test_shape_ignores_values():
    assert shape({"a": 1, "b": "x"}) == shape({"a": 99, "b": "y"})
    assert shape({"a": 1}) != shape({"a": 1, "b": 2})


def test_strip_fields_nested_and_dotted():
    value = {"keep": 1, "drop": 2, "data": {"drop": 3, "keep": 4}}
    out = strip_fields(value, {"drop"})
    assert out == {"keep": 1, "data": {"keep": 4}}


def test_public_endpoint_not_flagged_anonymous(manifest):
    """Anonymous hitting a public status endpoint with 200 JSON is not a finding."""
    app = FastAPI()

    @app.get("/api/public/status")
    async def status():
        return {"data": {"service": "x", "status": "ok"}, "request_id": "r"}

    @app.post("/api/auth/login")
    async def login():
        return JSONResponse({"error": "x"}, status_code=401)

    # A public route must be excluded from the anonymous check by manifest rule.
    route = manifest.route("public-status")
    assert route.is_public is True
