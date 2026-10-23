"""Integration: run the real automated scanner against the real demo app (both configs).

Imports the demo's own OpenAPI, discovers resources under each identity, generates and runs
cross-identity tests, and confirms violations with evidence — no mocked findings.
"""

import asyncio

import httpx
import pytest
from fastapi.openapi.utils import get_openapi

from boundarylens.manifest import Limits
from boundarylens.platform.autoscan import AutoAuth, AutoScanConfig, run_autoscan
from boundarylens.platform.discovery import import_openapi
from boundarylens.platform.identities import PlatformIdentity
from ledgerly.app import create_app

AUTO_CHECKS = {"BL-AUTO-BOLA", "BL-AUTO-BFLA", "BL-AUTO-ANON"}


def _identities():
    return [
        PlatformIdentity(id="anonymous", role="anonymous", kind="anonymous"),
        PlatformIdentity(id="alice", role="user", kind="login", username="alice", password_env="BL_ALICE_PASSWORD"),
        PlatformIdentity(id="bob", role="user", kind="login", username="bob", password_env="BL_BOB_PASSWORD"),
        PlatformIdentity(id="admin", role="admin", kind="login", username="admin", password_env="BL_ADMIN_PASSWORD"),
    ]


import json as _json


def _run_mode(mode):
    app = create_app(mode)
    spec = _json.dumps(get_openapi(title="Ledgerly", version="1", routes=app.routes))
    endpoints = import_openapi(spec)
    cfg = AutoScanConfig(origin="http://127.0.0.1", identities=_identities(), endpoints=endpoints,
                         auth=AutoAuth(session_cookie="ledgerly_session", verify_path="/api/me"),
                         limits=Limits())
    return asyncio.run(run_autoscan(cfg, transport=httpx.ASGITransport(app=app)))


def _confirmed(res):
    return [f for f in res.findings if f["confirmation"] == "confirmed"]


def test_autoscan_vulnerable_confirms_all_auto_checks():
    res = _run_mode("vulnerable")
    assert res.status == "completed", res.error
    checks = {f["check_id"] for f in _confirmed(res)}
    assert AUTO_CHECKS <= checks, f"missing: {AUTO_CHECKS - checks}"
    # resources were discovered per authenticated identity
    assert res.resources["by_identity"].get("alice", 0) > 0
    assert res.resources["by_identity"].get("bob", 0) > 0


def test_autoscan_fixed_has_no_violations():
    res = _run_mode("fixed")
    assert res.status == "completed", res.error
    assert _confirmed(res) == [], [f["check_id"] for f in _confirmed(res)]
    assert not any(c["status"] == "VIOLATION" for c in res.matrix)


def test_bola_finding_has_confidence_and_evidence():
    res = _run_mode("vulnerable")
    bola = [f for f in _confirmed(res) if f["check_id"] == "BL-AUTO-BOLA"]
    assert bola
    assert bola[0]["evidence"]["confidence"] >= 60
    assert bola[0]["evidence"]["owasp"].startswith("API1")


def test_matrix_and_graph_reflect_violations():
    res = _run_mode("vulnerable")
    violations = [c for c in res.matrix if c["status"] == "VIOLATION"]
    assert violations
    assert any(e["violation"] for e in res.graph["edges"])


def test_autoscan_no_secrets_in_output():
    res = _run_mode("vulnerable")
    blob = _json.dumps({"findings": res.findings, "activity": res.activity, "resources": res.resources})
    assert "alice-local-demo" not in blob
    assert "ledgerly_session=" not in blob or "[REDACTED]" in blob


def test_mutating_methods_not_executed_by_default():
    # The demo exposes POST /api/admin/users/{username}/disable; the planner must never run it.
    res = _run_mode("vulnerable")
    for entry in res.activity:
        assert entry["method"] in ("GET", "HEAD", "POST") or entry["method"] == "POST"
        if entry["method"] == "POST":
            # only auth logins are POST; no disable/delete operations
            assert "disable" not in entry["path"] and "/delete" not in entry["path"]
