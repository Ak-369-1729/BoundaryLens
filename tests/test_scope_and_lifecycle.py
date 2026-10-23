"""Scope restriction, redirect validation, dedup, cancellation, failure handling."""

import asyncio

import httpx
import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse, RedirectResponse

from boundarylens.client import OutOfScope, ScanContext, TargetClient
from boundarylens.findings import Confirmation, Finding, Severity, deduplicate
from boundarylens.manifest import ManifestError, host_permitted, load_manifest, origin_of
from boundarylens.runner import run_scan


def ctx(**kw):
    from boundarylens.manifest import Limits
    return ScanContext(limits=Limits(**kw))


def test_host_permitted_allows_loopback_only():
    assert host_permitted("http://127.0.0.1:8081", set())
    assert host_permitted("http://localhost:8080", set())
    assert not host_permitted("http://example.com", set())
    assert host_permitted("http://scanner-demo", {"scanner-demo"})  # explicit allowlist


def test_origin_normalization():
    assert origin_of("http://127.0.0.1:8081") == "http://127.0.0.1:8081"
    assert origin_of("https://localhost") == "https://localhost:443"


def test_manifest_rejects_nonloopback_target(tmp_path):
    bad = tmp_path / "m.yaml"
    bad.write_text("""
version: 1
name: bad
authorization: {statement: x}
targets: [{id: t, label: t, origin: "http://evil.example.com"}]
authentication:
  login: {path: /login}
  logout: {path: /logout}
  session_cookie: s
  verify_path: /me
identities: [{id: anonymous, role: anonymous}]
routes: [{id: r, method: GET, path: /x, allow: [public]}]
""")
    with pytest.raises(ManifestError):
        load_manifest(bad)


def test_out_of_scope_request_blocked():
    async def go():
        c = TargetClient(ctx(), "http://127.0.0.1:9", "x")
        try:
            with pytest.raises(OutOfScope):
                await c.request("GET", "http://evil.example.com/x", purpose="t")
        finally:
            await c.aclose()
    asyncio.run(go())


def test_redirect_to_other_origin_not_followed():
    app = FastAPI()

    @app.get("/go")
    async def go():
        return RedirectResponse("http://evil.example.com/stolen", status_code=302)

    async def run():
        transport = httpx.ASGITransport(app=app)
        c = TargetClient(ctx(), "http://127.0.0.1:1234", "x")
        c._http = httpx.AsyncClient(base_url="http://127.0.0.1:1234", transport=transport, follow_redirects=False)
        try:
            ex = await c.request("GET", "/go", purpose="t")
            assert ex.redirect_blocked is not None
            assert "evil.example.com" in ex.redirect_blocked
        finally:
            await c.aclose()
    asyncio.run(run())


def test_deduplication_merges_and_keeps_instances():
    def make():
        return Finding(check_id="BL-CROSS-USER", severity=Severity.high, confirmation=Confirmation.confirmed,
                       method="GET", route="/api/invoices/{resource}", actor_identity="bob",
                       expected_rule="r", expected_behavior="e", observed_behavior="o",
                       severity_rationale="s", remediation="rem", limitations="l",
                       instances=[{"path": "/api/invoices/x"}])
    merged = deduplicate([make(), make()])
    assert len(merged) == 1
    assert len(merged[0].instances) == 2


def test_cancellation_stops_scan():
    manifest = load_manifest(__import__("pathlib").Path(__file__).resolve().parents[1] / "manifests" / "ledgerly.yaml")
    from ledgerly.app import create_app
    target = manifest.target("ledgerly-vulnerable")

    async def run():
        cancel = asyncio.Event()
        cancel.set()  # cancel before it starts
        transport = httpx.ASGITransport(app=create_app("vulnerable"))
        return await run_scan(manifest, target, cancel=cancel, transport=transport)

    out = asyncio.run(run())
    assert out.status == "cancelled"


def test_unreachable_target_fails_gracefully():
    from boundarylens.manifest import Target
    manifest = load_manifest(__import__("pathlib").Path(__file__).resolve().parents[1] / "manifests" / "ledgerly.yaml")
    # A loopback port with nothing listening: the scan must fail gracefully, not crash.
    target = Target(id="dead", label="dead", origin="http://127.0.0.1:9", configuration="vulnerable",
                    local_demo=True, health_path="/api/public/status")
    out = asyncio.run(run_scan(manifest, target))
    assert out.status == "failed"
    assert out.error
