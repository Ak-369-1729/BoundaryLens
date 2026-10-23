"""Integration test: run the real scanner against the real demo app (both configurations).

This uses an in-process ASGI transport against the actual Ledgerly FastAPI app — no mocked
findings. It is the test that proves the end-to-end behaviour the project is judged on.
"""

import asyncio

import httpx
import pytest

from boundarylens.runner import run_scan, severity_counts
from ledgerly.app import create_app

CONFIRMED_CHECKS = {"BL-CROSS-USER", "BL-ADMIN-READ", "BL-ANON-API", "BL-SESSION-REUSE"}


def scan(manifest, mode):
    target = manifest.target(f"ledgerly-{mode}")
    transport = httpx.ASGITransport(app=create_app(mode))
    return asyncio.run(run_scan(manifest, target, transport=transport))


def confirmed(outcome):
    return [f for f in outcome.findings if f["confirmation"] == "confirmed"]


def test_vulnerable_confirms_all_required_checks(manifest):
    out = scan(manifest, "vulnerable")
    assert out.status == "completed", out.error
    checks = {f["check_id"] for f in confirmed(out)}
    assert CONFIRMED_CHECKS <= checks, f"missing confirmed checks: {CONFIRMED_CHECKS - checks}"
    # every check was actually executed
    assert all(v == "assessed" for v in out.check_coverage.values()), out.check_coverage


def test_cross_user_finding_has_ownership_evidence(manifest):
    out = scan(manifest, "vulnerable")
    cross = [f for f in confirmed(out) if f["check_id"] == "BL-CROSS-USER"]
    assert cross, "expected a confirmed cross-user finding"
    # at least one instance exposes another user's seeded private marker
    markers = [m for f in cross for inst in f["instances"] for m in inst.get("markers_found", [])]
    assert any(m.startswith("BLM-") for m in markers), markers


def test_fixed_has_no_confirmed_findings(manifest):
    out = scan(manifest, "fixed")
    assert out.status == "completed", out.error
    assert confirmed(out) == [], [f["check_id"] for f in confirmed(out)]
    # the checks still ran; they simply found nothing
    assert all(v == "assessed" for v in out.check_coverage.values())


def test_session_lifecycle_workflow_differs_by_mode(manifest):
    vuln = scan(manifest, "vulnerable")
    fixed = scan(manifest, "fixed")
    # vulnerable: the retry-after-logout step is NOT ok (session still valid)
    vuln_retry = next(s for s in vuln.workflow["steps"] if s["id"] == "retry")
    fixed_retry = next(s for s in fixed.workflow["steps"] if s["id"] == "retry")
    assert vuln_retry["ok"] is False
    assert fixed_retry["ok"] is True


def test_severity_counts_consistent(manifest):
    out = scan(manifest, "vulnerable")
    counts = severity_counts(out.findings)
    assert counts["confirmed"] >= 4
    assert counts["total"] == len(out.findings)
