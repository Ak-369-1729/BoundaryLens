"""Structured JSON and self-contained printable HTML reports. All content is escaped."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .findings import CHECKS


def _checks_executed(result: dict) -> list[dict]:
    is_auto = result.get("scan_kind") == "autoscan"
    present = {f["check_id"] for f in result.get("findings", [])}
    cids = [c for c in CHECKS if (c.startswith("BL-AUTO-") == is_auto)]
    coverage = result.get("check_coverage", {})
    out = []
    for cid in cids:
        cov = coverage.get(cid) or ("assessed" if cid in present else ("assessed" if is_auto else "not_assessed"))
        out.append({"check_id": cid, "title": CHECKS[cid]["title"], "coverage": cov})
    return out


def build_report(scan: dict, manifest_name: str, authorization: str) -> dict:
    result = scan.get("result") or {}
    return {
        "report_type": "boundarylens.scan-report",
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "manifest": manifest_name,
            "authorization_statement": authorization,
            "note": "Authorized scan of a developer-owned target. Findings and evidence are sanitized: "
                    "no passwords, session tokens or authorization headers are included.",
        },
        "target": {"id": scan["target_id"], "configuration": scan["configuration"], "origin": scan["origin"]},
        "scan": {
            "id": scan["id"], "status": scan["status"],
            "created_at": scan["created_at"], "started_at": scan["started_at"], "finished_at": scan["finished_at"],
            "requests_sent": scan["requests_sent"], "request_budget": result.get("request_budget"),
            "limits": result.get("limits", {}), "error": scan.get("error"),
        },
        "checks_executed": _checks_executed(result),
        "severity_counts": result.get("severity_counts", {}),
        "workflow": result.get("workflow"),
        "limitations": [
            "The scanner verifies the authorization rules declared in the manifest; it does not infer the "
            "application's complete business policy.",
            "Confirmations are proven against seeded demo resources named in the manifest, not an exhaustive "
            "enumeration of every object.",
            "Security-header and cookie items are hardening observations, interpreted for local HTTP development.",
        ],
        "findings": result.get("findings", []),
    }


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _evidence_block(evidence: dict) -> str:
    if not evidence:
        return ""
    req = evidence.get("request", {})
    resp = evidence.get("response") or {}
    parts = ["<div class='ev'>"]
    parts.append("<h4>Request</h4><pre>")
    parts.append(_esc(f"{req.get('method','')} {req.get('url','')}"))
    for k, v in (req.get("headers") or {}).items():
        parts.append("\n" + _esc(f"{k}: {v}"))
    if req.get("body"):
        parts.append("\n\n" + _esc(req["body"]))
    parts.append("</pre>")
    if resp:
        parts.append(f"<h4>Response — HTTP {_esc(resp.get('status'))}</h4><pre>")
        for k, v in (resp.get("headers") or {}).items():
            parts.append(_esc(f"{k}: {v}") + "\n")
        if resp.get("redirect_blocked"):
            parts.append("\n" + _esc(f"[redirect not followed: {resp['redirect_blocked']}]") + "\n")
        parts.append("\n" + _esc(resp.get("body_excerpt", "")))
        parts.append("</pre>")
    if evidence.get("error"):
        parts.append(f"<p class='err'>Transport error: {_esc(evidence['error'])}</p>")
    parts.append("</div>")
    return "".join(parts)


def _finding_html(f: dict) -> str:
    sev = _esc(f["severity"])
    rows = [
        ("Finding ID", f["finding_id"]),
        ("Check", f"{f['check_id']} — {f['title']}"),
        ("Endpoint", f"{f['method']} {f['route']}"),
        ("Actor identity", f["actor_identity"]),
        ("Expected rule", f["expected_rule"]),
        ("Expected behavior", f["expected_behavior"]),
        ("Observed behavior", f["observed_behavior"]),
        ("Severity", f"{f['severity']} — {f['severity_rationale']}"),
        ("Confirmation", f["confirmation"]),
        ("CWE", f["cwe"] or "n/a"),
        ("Remediation", f["remediation"]),
        ("Limitations", f["limitations"]),
        ("Affected instances", f["instance_count"]),
    ]
    body = "".join(f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>" for k, v in rows)
    evidence = _evidence_block(f.get("evidence", {}))
    instances = ""
    for inst in f.get("instances", []):
        inst_ev = _evidence_block(inst.get("evidence", {})) if inst.get("evidence") else ""
        label = _esc(f"{inst.get('method','')} {inst.get('path', inst.get('observation',''))} → {inst.get('status','')}")
        markers = f" · markers: {_esc(inst.get('markers_found'))}" if inst.get("markers_found") else ""
        instances += f"<details><summary>Instance: {label}{markers}</summary>{inst_ev}</details>"
    return (f"<section class='finding sev-{sev}'><h3>{_esc(f['title'])} "
            f"<span class='badge sev-{sev}'>{sev}</span> "
            f"<span class='badge conf'>{_esc(f['confirmation'])}</span></h3>"
            f"<table>{body}</table>{evidence}{instances}</section>")


def render_html(report: dict) -> str:
    t = report["target"]
    s = report["scan"]
    counts = report["severity_counts"]
    coverage = "".join(
        f"<li><strong>{_esc(c['check_id'])}</strong> {_esc(c['title'])} — {_esc(c['coverage'])}</li>"
        for c in report["checks_executed"])
    findings = report["findings"]
    findings_html = "".join(_finding_html(f) for f in findings) or "<p class='empty'>No findings in this scan.</p>"
    limitations = "".join(f"<li>{_esc(x)}</li>" for x in report["limitations"])
    count_chips = "".join(
        f"<span class='chip sev-{k}'>{_esc(k)}: {_esc(v)}</span>"
        for k, v in counts.items() if k in ("critical", "high", "medium", "low", "info") and v)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BoundaryLens report — {_esc(t['configuration'])}</title>
<style>
:root{{color-scheme:light}}
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:900px;margin:0 auto;padding:24px;color:#1b1f24;line-height:1.5}}
h1{{margin-bottom:4px}}.muted{{color:#5b636d}}
table{{border-collapse:collapse;width:100%;margin:8px 0}}th,td{{border:1px solid #d9dee4;padding:6px 10px;text-align:left;vertical-align:top;font-size:14px}}
th{{background:#f3f5f8;width:190px}}
pre{{background:#0f1419;color:#e6e8eb;padding:12px;border-radius:6px;overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-word}}
.finding{{border:1px solid #d9dee4;border-left-width:5px;border-radius:8px;padding:14px 18px;margin:18px 0}}
.sev-critical{{border-left-color:#b00020}}.sev-high{{border-left-color:#d7263d}}.sev-medium{{border-left-color:#e08600}}
.sev-low{{border-left-color:#2f80ed}}.sev-info{{border-left-color:#777}}
.badge{{font-size:12px;padding:2px 8px;border-radius:10px;background:#eef1f5;margin-left:6px}}
.badge.sev-critical,.badge.sev-high{{background:#fde0e3;color:#b00020}}.badge.sev-medium{{background:#fde6cf;color:#8a5200}}
.badge.sev-low{{background:#e2edff;color:#1b4fa0}}.badge.conf{{background:#e4f6ea;color:#1b6b38}}
.chip{{display:inline-block;padding:3px 10px;border-radius:12px;margin:2px;font-size:13px;background:#eef1f5}}
.chip.sev-critical,.chip.sev-high{{background:#fde0e3}}.chip.sev-medium{{background:#fde6cf}}.chip.sev-low{{background:#e2edff}}
details{{margin:8px 0}}summary{{cursor:pointer;font-weight:600}}.empty{{color:#5b636d}}.err{{color:#b00020}}
@media print{{.finding{{break-inside:avoid}}pre{{white-space:pre-wrap}}}}
</style></head><body>
<h1>BoundaryLens scan report</h1>
<p class="muted">Role-aware authorization scan · generated {_esc(report['generated_at'])}</p>
<table>
<tr><th>Target</th><td>{_esc(t['id'])} ({_esc(t['configuration'])}) — {_esc(t['origin'])}</td></tr>
<tr><th>Scan</th><td>{_esc(s['id'])} · status {_esc(s['status'])}</td></tr>
<tr><th>Requests</th><td>{_esc(s['requests_sent'])} of budget {_esc(s['request_budget'])}</td></tr>
<tr><th>Window</th><td>{_esc(s['started_at'])} → {_esc(s['finished_at'])}</td></tr>
<tr><th>Authorization</th><td>{_esc(report['scope']['authorization_statement'])}</td></tr>
</table>
<p>{count_chips or '<span class="muted">No confirmed findings or observations.</span>'}</p>
<h2>Checks executed</h2><ul>{coverage}</ul>
<h2>Findings</h2>{findings_html}
<h2>Scope and limitations</h2><ul>{limitations}</ul>
<p class="muted">{_esc(report['scope']['note'])}</p>
</body></html>"""
