"""SARIF 2.1.0 export for authorization findings (GitHub Code Scanning compatible)."""

from __future__ import annotations

from ..findings import Severity

SARIF_VERSION = "2.1.0"
SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _rules(findings: list[dict]) -> list[dict]:
    rules: dict[str, dict] = {}
    for f in findings:
        rid = f["check_id"]
        if rid in rules:
            continue
        owasp = (f.get("evidence") or {}).get("owasp", "")
        rules[rid] = {
            "id": rid,
            "name": f["title"].replace(" ", ""),
            "shortDescription": {"text": f["title"]},
            "fullDescription": {"text": f.get("expected_rule", f["title"])},
            "helpUri": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
            "properties": {"cwe": f.get("cwe", ""), "owasp": owasp,
                           "tags": ["security", "authorization", f.get("cwe", "")]},
            "defaultConfiguration": {"level": _LEVEL.get(f["severity"], "warning")},
        }
    return list(rules.values())


def _result(f: dict) -> dict:
    confidence = (f.get("evidence") or {}).get("confidence")
    message = (f"{f['title']} ({f['severity']}). {f['observed_behavior']} "
               f"Expected: {f['expected_behavior']}")
    endpoint = f"{f['method']} {f['route']}"
    props = {
        "severity": f["severity"], "confirmation": f["confirmation"],
        "endpoint": endpoint, "method": f["method"], "cwe": f.get("cwe", ""),
        "owasp": (f.get("evidence") or {}).get("owasp", ""),
        "actorIdentity": f["actor_identity"], "security-severity": _security_severity(f["severity"]),
    }
    if confidence is not None:
        props["confidence"] = confidence
    return {
        "ruleId": f["check_id"],
        "level": _LEVEL.get(f["severity"], "warning"),
        "message": {"text": message},
        "locations": [{
            "logicalLocations": [{"fullyQualifiedName": endpoint, "kind": "endpoint"}],
            "physicalLocation": {"artifactLocation": {"uri": f["route"].lstrip("/") or "/"}},
        }],
        "partialFingerprints": {"boundarylens/finding": f["finding_id"]},
        "properties": props,
    }


def _security_severity(sev: str) -> str:
    return {"critical": "9.1", "high": "7.5", "medium": "5.3", "low": "3.1", "info": "1.0"}.get(sev, "5.0")


def build_sarif(findings: list[dict], *, tool_version: str = "1.0.0",
                target: str | None = None) -> dict:
    actionable = [f for f in findings if f.get("confirmation") == "confirmed"]
    run = {
        "tool": {"driver": {
            "name": "BoundaryLens",
            "informationUri": "https://github.com/boundarylens/boundarylens",
            "version": tool_version,
            "rules": _rules(actionable),
        }},
        "results": [_result(f) for f in actionable],
    }
    if target:
        run["properties"] = {"target": target}
    return {"version": SARIF_VERSION, "$schema": SCHEMA, "runs": [run]}
