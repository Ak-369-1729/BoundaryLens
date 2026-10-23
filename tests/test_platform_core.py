"""Resource extraction, JWT decoding, planner, evidence/confidence, SARIF, regression."""

import base64
import json

from boundarylens.platform.evidence import analyze_cross_identity
from boundarylens.platform.identities import PlatformIdentity, decode_jwt
from boundarylens.platform.resources import ResourceGraph, extract_resources
from boundarylens.platform.sarif import build_sarif
from boundarylens.platform.regression import build_baseline, compare_to_baseline


# ---- resource extraction ----
def test_extract_recognizes_id_keys_and_types():
    data = {"data": {"invoice": {"id": "inv_77", "orderId": 412, "owner": "alice",
                                 "email": "a@x.test", "password": "secret"}}}
    refs = extract_resources(data, identity="alice", method="GET", path="/api/invoices")
    types = {r.resource_type for r in refs}
    values = {r.value for r in refs}
    assert "inv_77" in values and "412" in values
    assert "order" in types
    # secrets are never extracted as resources
    assert "secret" not in values
    assert any("owner" in r.protected_fields for r in refs)


def test_resource_graph_owners_and_summary():
    g = ResourceGraph()
    g.add(extract_resources({"id": "ord_100"}, identity="alice", method="GET", path="/x"))
    g.add(extract_resources({"id": "ord_200"}, identity="bob", method="GET", path="/x"))
    owners = g.owners()
    # top-level {"id": ...} has no container hint, so the type is the generic "resource"
    assert owners[("resource", "ord_100")] == "alice"
    assert g.summary()["by_identity"] == {"alice": 1, "bob": 1}


# ---- JWT ----
def _jwt(payload, alg="HS256"):
    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    return f"{seg({'alg': alg, 'typ': 'JWT'})}.{seg(payload)}.sig"


def test_jwt_decode_extracts_claims_without_verifying():
    ctx = decode_jwt(_jwt({"sub": "alice", "role": "admin", "scope": "read", "secretx": "y"}))
    assert ctx["alg"] == "HS256"
    assert ctx["claims"]["role"] == "admin"
    assert ctx["signature_verified"] is False
    assert "secretx" not in ctx["claims"]  # only known claims surface


def test_jwt_decode_rejects_non_jwt():
    assert decode_jwt("not-a-jwt") is None
    assert decode_jwt("a.b") is None


def test_identity_bearer_header_and_secret(monkeypatch):
    monkeypatch.setenv("TOK", "abc.def.ghi")
    ident = PlatformIdentity(id="svc", role="user", kind="bearer", token_env="TOK")
    assert ident.auth_headers()["Authorization"] == "Bearer abc.def.ghi"
    assert "abc.def.ghi" in ident.secret_values()
    # the secret VALUE never leaks; public_dict exposes only the env var name as the source
    assert "abc.def.ghi" not in json.dumps(ident.public_dict())
    assert ident.public_dict()["credential_source"] == "env:TOK"


# ---- evidence / confidence ----
def test_denial_body_not_confirmed():
    r = analyze_cross_identity(baseline_status=200, baseline_body='{"id":1,"owner":"alice"}',
                               baseline_json={"id": 1, "owner": "alice"},
                               cand_status=200, cand_body='{"error":"not authorized"}',
                               cand_json={"error": "not authorized"},
                               target_markers=[], target_value="1", looks_like_login=False)
    assert r.confirmed is False
    assert r.confidence == 0


def test_cross_user_marker_confirms_high_confidence():
    base = {"id": 412, "owner": "alice", "email": "alice@x.test", "ref": "BLM-ALICE-1"}
    r = analyze_cross_identity(baseline_status=200, baseline_body=json.dumps(base), baseline_json=base,
                               cand_status=200, cand_body=json.dumps(base), cand_json=base,
                               target_markers=["BLM-ALICE-1"], target_value="412", looks_like_login=False)
    assert r.confirmed is True
    assert r.confidence >= 80
    assert any("marker" in reason for reason in r.reasons)


def test_login_page_and_403_not_confirmed():
    assert analyze_cross_identity(baseline_status=200, baseline_body="{}", baseline_json={},
                                  cand_status=200, cand_body="<input type=password>", cand_json=None,
                                  target_markers=["m"], target_value=None, looks_like_login=True).confirmed is False
    assert analyze_cross_identity(baseline_status=200, baseline_body="{}", baseline_json={},
                                  cand_status=403, cand_body="{}", cand_json={},
                                  target_markers=["m"], target_value=None, looks_like_login=False).confirmed is False


# ---- SARIF ----
def test_sarif_structure_and_only_confirmed():
    findings = [
        {"finding_id": "F1", "check_id": "BL-AUTO-BOLA", "title": "Broken Object Level Authorization",
         "severity": "high", "confirmation": "confirmed", "method": "GET", "route": "/api/orders/{id}",
         "actor_identity": "bob", "expected_rule": "x", "expected_behavior": "e", "observed_behavior": "o",
         "cwe": "CWE-639", "evidence": {"confidence": 97, "owasp": "API1:2023"}},
        {"finding_id": "F2", "check_id": "BL-SEC-CONFIG", "title": "Obs", "severity": "low",
         "confirmation": "observation", "method": "GET", "route": "/x", "actor_identity": "n/a",
         "expected_rule": "", "expected_behavior": "", "observed_behavior": "", "cwe": "", "evidence": {}},
    ]
    sarif = build_sarif(findings, target="http://127.0.0.1")
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert len(run["results"]) == 1  # observation excluded
    assert run["results"][0]["ruleId"] == "BL-AUTO-BOLA"
    assert run["results"][0]["properties"]["confidence"] == 97
    assert run["tool"]["driver"]["rules"][0]["id"] == "BL-AUTO-BOLA"


# ---- regression ----
def _result(check_ids):
    return {"findings": [
        {"finding_id": f"F{i}", "check_id": c, "method": "GET", "route": "/api/orders/{id}",
         "actor_identity": "bob", "severity": "high", "confirmation": "confirmed",
         "observed_behavior": "o", "evidence": {"confidence": 95}}
        for i, c in enumerate(check_ids)], "matrix": [], "severity_counts": {}}


def test_baseline_and_regression_detection():
    clean = _result([])
    broken = _result(["BL-AUTO-BOLA"])
    baseline = build_baseline(clean, name="clean")
    diff = compare_to_baseline(baseline, broken, fail_on="high")
    assert len(diff["regressions"]) == 1
    assert diff["regressions"][0]["current_status"] == "VIOLATION"
    assert diff["passed"] is False


def test_regression_fixed_and_pass_below_threshold():
    baseline = build_baseline(_result(["BL-AUTO-BOLA"]), name="b")
    diff = compare_to_baseline(baseline, _result([]), fail_on="high")
    assert len(diff["fixed"]) == 1
    assert diff["passed"] is True  # no new regressions
