"""BoundaryLens CLI: run an automated authorization scan and gate CI on regressions.

    python -m boundarylens.cli scan --config boundarylens.yaml \
        --baseline baseline.json --fail-on high --report sarif --out report.sarif

Exit codes: 0 = pass, 2 = gating authorization regression(s), 3 = scan failed, 4 = config/usage error.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .platform.autoscan import run_autoscan
from .platform.config import ConfigError, load_project_config, to_autoscan_config
from .platform.discovery import dedupe_endpoints, import_har, import_openapi, import_postman
from .platform.regression import build_baseline, compare_to_baseline
from .platform.sarif import build_sarif
from .reporting import build_report, render_html
from .runner import severity_counts


def _load_endpoints(cfg) -> list:
    d = cfg.discovery
    eps = []
    if d.openapi:
        eps += import_openapi(Path(d.openapi).read_text())
    if d.openapi_url:
        eps += import_openapi(_fetch(d.openapi_url))
    if d.postman:
        eps += import_postman(Path(d.postman).read_text())
    if d.har:
        eps += import_har(Path(d.har).read_text())
    if not eps:
        raise ConfigError("no discovery inputs produced any endpoints (set discovery.openapi/postman/har)")
    return dedupe_endpoints(eps)


def _fetch(url: str) -> str:
    import httpx
    with httpx.Client(timeout=10, trust_env=False) as c:
        r = c.get(url)
        r.raise_for_status()
        return r.text


def _scan_result_dict(result) -> dict:
    return {
        "findings": result.findings,
        "matrix": result.matrix,
        "graph": result.graph,
        "resources": result.resources,
        "endpoints": result.endpoints,
        "identities": result.identities,
        "severity_counts": severity_counts(result.findings),
        "check_coverage": {}, "workflow": None,
        "request_budget": result.request_budget, "limits": result.limits,
    }


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        cfg = load_project_config(args.config)
        endpoints = _load_endpoints(cfg)
        autocfg = to_autoscan_config(cfg, endpoints)
    except (ConfigError, OSError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 4

    result = asyncio.run(run_autoscan(autocfg))
    if result.status == "failed":
        print(f"scan failed: {result.error}", file=sys.stderr)
        return 3

    counts = severity_counts(result.findings)
    print(f"BoundaryLens: {len(result.endpoints)} endpoints, {result.resources['total']} resources, "
          f"{result.test_count} tests, {counts.get('confirmed', 0)} confirmed violation(s), "
          f"{result.requests_sent}/{result.request_budget} requests.")

    scan_dict = _scan_result_dict(result)
    _write_reports(cfg, args, result, scan_dict)

    # baseline creation mode
    if args.create_baseline:
        baseline = build_baseline(scan_dict, name=args.baseline_name or "baseline", target=autocfg.origin)
        Path(args.create_baseline).write_text(json.dumps(baseline, indent=2))
        print(f"baseline written to {args.create_baseline}")
        return 0

    # regression gate
    baseline_path = args.baseline or cfg.regression.baseline
    fail_on = args.fail_on or cfg.regression.fail_on
    if baseline_path:
        if not Path(baseline_path).exists():
            print(f"baseline {baseline_path} not found; treating current scan as the new baseline is not automatic.",
                  file=sys.stderr)
            return 4
        baseline = json.loads(Path(baseline_path).read_text())
        diff = compare_to_baseline(baseline, scan_dict, fail_on=fail_on)
        for r in diff["regressions"]:
            print(f"  REGRESSION [{r['severity']}] {r['check_id']} {r['method']} {r['route']} "
                  f"identity={r['identity']}: {r['previous_status']} -> {r['current_status']}")
        for f in diff["fixed"]:
            print(f"  FIXED [{f['severity']}] {f['check_id']} {f['method']} {f['route']} identity={f['identity']}")
        if diff["passed"]:
            print(f"Authorization regression gate: PASS (threshold {fail_on}).")
            return 0
        print(f"Authorization regression gate: FAIL — {len(diff['gating_regressions'])} "
              f"regression(s) at or above '{fail_on}'.", file=sys.stderr)
        return 2
    return 0


def _write_reports(cfg, args, result, scan_dict) -> None:
    rep = cfg.report
    target_meta = {"id": "autoscan", "configuration": "autoscan", "origin": result.__dict__.get("origin", "")}
    base_scan = {"id": "autoscan", "target_id": "autoscan", "configuration": "autoscan",
                 "origin": "", "status": result.status, "created_at": result.started_at,
                 "started_at": result.started_at, "finished_at": result.finished_at,
                 "requests_sent": result.requests_sent, "error": result.error, "result": scan_dict}
    if rep.json_report:
        Path(rep.json_report).write_text(json.dumps(build_report(base_scan, "autoscan", "authorized local scan"), indent=2))
    if rep.html:
        Path(rep.html).write_text(render_html(build_report(base_scan, "autoscan", "authorized local scan")))
    if rep.sarif or (args.report == "sarif"):
        out = args.out or rep.sarif or "boundarylens.sarif"
        Path(out).write_text(json.dumps(build_sarif(result.findings, target=result.__dict__.get("origin")), indent=2))
        print(f"SARIF written to {out}")
    if args.report == "json" and args.out:
        Path(args.out).write_text(json.dumps(scan_dict, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="boundarylens", description="Automated authorization scanner")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="run an automated authorization scan")
    scan.add_argument("--config", required=True, help="path to boundarylens.yaml")
    scan.add_argument("--baseline", help="baseline JSON to compare against")
    scan.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"],
                      help="minimum regression severity that fails the gate")
    scan.add_argument("--report", choices=["sarif", "json"], help="also write this report format to --out")
    scan.add_argument("--out", help="output path for --report")
    scan.add_argument("--create-baseline", metavar="PATH", help="write a baseline snapshot and exit")
    scan.add_argument("--baseline-name", help="name for the created baseline")
    scan.set_defaults(func=cmd_scan)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
