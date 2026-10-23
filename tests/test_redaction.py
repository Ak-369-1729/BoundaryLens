"""Secrets must never appear in evidence, logs or exports."""

import json

from boundarylens.redact import (REDACTED, redact_set_cookie, scrub_body, scrub_headers,
                                  scrub_json, scrub_text)
from boundarylens.reporting import build_report, render_html


def test_scrub_headers_removes_cookie_and_auth():
    headers = [("Cookie", "ledgerly_session=abc123def456"), ("Authorization", "Bearer secrettoken123"),
               ("Content-Type", "application/json")]
    out = scrub_headers(headers)
    assert "abc123def456" not in json.dumps(out)
    assert "secrettoken123" not in json.dumps(out)
    assert out["content-type"] == "application/json"
    assert out["cookie"] == f"ledgerly_session={REDACTED}"


def test_set_cookie_keeps_attributes_drops_value():
    out = redact_set_cookie("ledgerly_session=abc123def456; HttpOnly; Path=/; SameSite=lax")
    assert "abc123def456" not in out
    assert "HttpOnly" in out and "SameSite=lax" in out
    assert REDACTED in out


def test_scrub_json_redacts_sensitive_keys():
    out = scrub_json({"username": "alice", "password": "hunter2", "token": "xyz", "nested": {"secret": "s"}})
    assert out["username"] == "alice"
    assert out["password"] == REDACTED
    assert out["token"] == REDACTED
    assert out["nested"]["secret"] == REDACTED


def test_scrub_text_redacts_known_secrets_and_inline_pairs():
    text = 'logged in with password=hunter2 and session_id: abc123'
    out = scrub_text(text, secrets={"hunter2"})
    assert "hunter2" not in out
    assert "abc123" not in out


def test_scrub_body_truncates():
    body = json.dumps({"items": ["x" * 100] * 100})
    out = scrub_body(body, "application/json", limit=200)
    assert len(out) < 400
    assert "truncated" in out


def test_report_html_escapes_content():
    scan = {
        "id": "s1", "target_id": "t", "configuration": "vulnerable", "origin": "http://127.0.0.1",
        "status": "completed", "created_at": "t", "started_at": "t", "finished_at": "t",
        "requests_sent": 1, "error": None,
        "result": {"findings": [{
            "finding_id": "F1", "check_id": "BL-CROSS-USER", "title": "<script>alert(1)</script>",
            "severity": "high", "confirmation": "confirmed", "method": "GET", "route": "/x",
            "actor_identity": "bob", "expected_rule": "r", "expected_behavior": "e",
            "observed_behavior": "<img src=x onerror=alert(1)>", "severity_rationale": "r",
            "cwe": "CWE-639", "remediation": "r", "limitations": "l", "instance_count": 1,
            "instances": [], "evidence": {}}],
            "severity_counts": {"high": 1, "confirmed": 1}, "check_coverage": {}, "workflow": None,
            "request_budget": 150, "limits": {}},
    }
    html = render_html(build_report(scan, "m", "auth"))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "onerror=alert(1)" not in html or "&lt;img" in html
