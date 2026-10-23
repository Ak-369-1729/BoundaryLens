"""Authorization regression: snapshot a scan as a baseline and diff a later scan against it.

A baseline records the authorization *outcome* per (check, method, route, identity) — not
secrets or raw bodies — so a later scan can detect when a previously-blocked boundary becomes
a violation (a regression) or vice-versa.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..findings import Severity

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _key(f: dict) -> str:
    return f"{f['check_id']}|{f['method']}|{f['route']}|{f['actor_identity']}"


def build_baseline(scan_result: dict, *, name: str, target: str | None = None) -> dict:
    """Create a baseline snapshot from a scan result's findings + matrix."""
    findings = scan_result.get("findings", [])
    entries = {}
    for f in findings:
        if f.get("confirmation") != "confirmed":
            continue
        entries[_key(f)] = {
            "check_id": f["check_id"], "method": f["method"], "route": f["route"],
            "identity": f["actor_identity"], "severity": f["severity"],
            "status": "VIOLATION",
            "confidence": (f.get("evidence") or {}).get("confidence"),
        }
    # Record the explicitly-tested boundaries that were clean (BLOCKED), from the matrix.
    tested = []
    for cell in scan_result.get("matrix", []):
        tested.append({"identity": cell.get("identity"), "resource": cell.get("resource"),
                       "operation": cell.get("operation"), "status": cell.get("status")})
    return {
        "baseline_version": 1,
        "name": name,
        "target": target,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "violations": entries,
        "tested_cells": tested,
        "counts": scan_result.get("severity_counts", {}),
    }


def compare_to_baseline(baseline: dict, scan_result: dict, *, fail_on: str = "high") -> dict:
    """Diff current findings against a baseline. Returns regressions, fixed, and gate decision."""
    base = baseline.get("violations", {})
    current = {}
    for f in scan_result.get("findings", []):
        if f.get("confirmation") == "confirmed":
            current[_key(f)] = f

    base_keys, cur_keys = set(base), set(current)
    regressions = []
    for k in sorted(cur_keys - base_keys):
        f = current[k]
        regressions.append({
            "key": k, "check_id": f["check_id"], "method": f["method"], "route": f["route"],
            "identity": f["actor_identity"], "severity": f["severity"],
            "previous_status": "BLOCKED", "current_status": "VIOLATION",
            "confidence": (f.get("evidence") or {}).get("confidence"),
            "evidence_summary": f.get("observed_behavior", ""),
        })
    fixed = []
    for k in sorted(base_keys - cur_keys):
        b = base[k]
        fixed.append({"key": k, "check_id": b["check_id"], "method": b["method"], "route": b["route"],
                      "identity": b["identity"], "severity": b["severity"],
                      "previous_status": "VIOLATION", "current_status": "BLOCKED"})
    persisting = [current[k] for k in sorted(base_keys & cur_keys)]

    threshold = SEVERITY_ORDER.index(fail_on) if fail_on in SEVERITY_ORDER else SEVERITY_ORDER.index("high")
    gating = [r for r in regressions if SEVERITY_ORDER.index(r["severity"]) >= threshold]
    return {
        "baseline_name": baseline.get("name"),
        "baseline_created_at": baseline.get("created_at"),
        "fail_on": fail_on,
        "regressions": regressions,
        "fixed": fixed,
        "persisting": [{"key": _key(p), "check_id": p["check_id"], "route": p["route"],
                        "identity": p["actor_identity"], "severity": p["severity"]} for p in persisting],
        "gating_regressions": gating,
        "passed": len(gating) == 0,
    }
