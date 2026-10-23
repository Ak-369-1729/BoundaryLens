"""BoundaryLens backend API. Serves the dashboard, runs scans, exposes findings and exports."""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import Settings, load_settings
from .findings import CHECKS
from .manager import ScanManager
from .manifest import Manifest, Target, describe_rule, load_manifest
from .replay import replay_instance
from .reporting import build_report, render_html
from .storage import Store


class StartScanRequest(BaseModel):
    target_id: str = Field(min_length=1, max_length=64)
    authorization_acknowledged: bool = False


class ReplayRequest(BaseModel):
    scan_id: str
    finding_id: str
    instance_index: int = Field(0, ge=0)


class AutoScanRequest(BaseModel):
    target_id: str = Field(min_length=1, max_length=64)
    authorization_acknowledged: bool = False
    confidence_threshold: int = Field(60, ge=0, le=100)


class ImportRequest(BaseModel):
    source: str = Field(pattern=r"^(openapi|swagger|postman|har)$")
    content: str = Field(min_length=1, max_length=4_000_000)


class BaselineRequest(BaseModel):
    scan_id: str
    name: str = Field(min_length=1, max_length=128)


class RegressionRequest(BaseModel):
    baseline_id: str
    scan_id: str
    fail_on: str = Field("high", pattern=r"^(info|low|medium|high|critical)$")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    manifest = load_manifest(settings.manifest_path, extra_hosts=settings.allowed_hosts)
    store = Store(settings.database_url)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        recovered = store.recover_interrupted()
        app.state.recovered = recovered
        yield
        await app.state.manager.shutdown()

    app = FastAPI(title="BoundaryLens", version="1.0.0",
                  description="Role-aware authorization scanner for developer-owned web applications.",
                  lifespan=lifespan)
    manager = ScanManager(manifest, store)
    app.state.manager = manager
    app.state.manifest = manifest
    app.state.store = store
    app.state.settings = settings

    def require_target(target_id: str) -> Target:
        target = manifest.target(target_id)
        if not target:
            raise HTTPException(404, f"unknown target '{target_id}'")
        return target

    def scan_detail(scan_id: str) -> dict:
        scan = store.get(scan_id)
        if not scan:
            raise HTTPException(404, "scan not found")
        detail = scan.to_detail()
        if manager.is_active(scan_id):
            detail["live"] = manager.progress(scan_id)
        return detail

    # --------------------------------------------------------------- config
    @app.get("/api/config")
    async def config():
        return {
            "manifest_name": manifest.name,
            "authorization_statement": manifest.authorization.statement,
            "require_acknowledgment": settings.require_ack,
            "targets": [
                {"id": t.id, "label": t.label, "origin": t.origin, "configuration": t.configuration,
                 "local_demo": t.local_demo}
                for t in manifest.targets],
            "identities": [
                {"id": i.id, "role": i.role, "username": i.username, "authenticated": i.authenticated}
                for i in manifest.identities],
            "limits": {
                "max_requests": manifest.limits.max_requests, "concurrency": manifest.limits.concurrency,
                "timeout_seconds": manifest.limits.timeout_seconds,
                "max_response_bytes": manifest.limits.max_response_bytes,
                "max_redirects": manifest.limits.max_redirects},
            "checks": [{"id": c, **CHECKS[c]} for c in CHECKS],
            "routes": [
                {"id": r.id, "method": r.method, "path": r.path, "rule": describe_rule(r),
                 "executed": r.executable, "safe": r.safe}
                for r in manifest.routes],
        }

    # ---------------------------------------------------------------- scans
    @app.post("/api/scans", status_code=201)
    async def start_scan(req: StartScanRequest):
        target = require_target(req.target_id)
        if settings.require_ack and not req.authorization_acknowledged:
            raise HTTPException(400, "authorization must be acknowledged before scanning")
        scan_id = manager.start(target)
        return JSONResponse(scan_detail(scan_id), status_code=201)

    @app.post("/api/autoscans", status_code=201)
    async def start_autoscan(req: AutoScanRequest):
        target = require_target(req.target_id)
        if settings.require_ack and not req.authorization_acknowledged:
            raise HTTPException(400, "authorization must be acknowledged before scanning")
        scan_id = manager.start_autoscan(target, confidence_threshold=req.confidence_threshold)
        return JSONResponse(scan_detail(scan_id), status_code=201)

    @app.get("/api/scans")
    async def list_scans(limit: int = 50, kind: str | None = None):
        scans = store.list(min(max(limit, 1), 200))
        if kind:
            scans = [s for s in scans if s.get("kind") == kind]
        return {"scans": scans}

    @app.get("/api/scans/{scan_id}")
    async def get_scan(scan_id: str):
        return scan_detail(scan_id)

    @app.post("/api/scans/{scan_id}/cancel")
    async def cancel_scan(scan_id: str):
        if not store.get(scan_id):
            raise HTTPException(404, "scan not found")
        cancelled = manager.cancel(scan_id)
        return {"scan_id": scan_id, "cancel_requested": cancelled}

    # ------------------------------------------------------------- findings
    @app.get("/api/scans/{scan_id}/findings")
    async def findings(scan_id: str):
        detail = scan_detail(scan_id)
        result = detail.get("result") or {}
        return {"scan_id": scan_id, "status": detail["status"],
                "findings": result.get("findings", []),
                "check_coverage": result.get("check_coverage", {})}

    def _find_instance(scan: dict, finding_id: str, index: int):
        result = scan.get("result") or {}
        finding = next((f for f in result.get("findings", []) if f["finding_id"] == finding_id), None)
        if not finding:
            raise HTTPException(404, "finding not found")
        instances = finding.get("instances", [])
        if index >= len(instances):
            raise HTTPException(404, "instance index out of range")
        return finding, instances[index]

    # --------------------------------------------------------------- replay
    @app.post("/api/replay")
    async def replay(req: ReplayRequest):
        scan = store.get(req.scan_id)
        if not scan:
            raise HTTPException(404, "scan not found")
        detail = scan.to_detail()
        finding, instance = _find_instance(detail, req.finding_id, req.instance_index)
        target = require_target(detail["target_id"])
        if not target.local_demo:
            raise HTTPException(400, "replay is available for the included local demo only")
        method = instance.get("method", finding["method"])
        path = instance.get("path")
        if not path:
            raise HTTPException(400, "this finding has no replayable request instance")
        identity = finding["actor_identity"].split(" ")[0]
        try:
            return await replay_instance(manifest, target, method, path, identity)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        except Exception as exc:
            raise HTTPException(502, f"replay failed: {type(exc).__name__}: {exc}")

    # --------------------------------------------------- discovery import
    @app.post("/api/discovery/import")
    async def discovery_import(req: ImportRequest):
        from .platform.discovery import dedupe_endpoints, import_source
        try:
            endpoints = dedupe_endpoints(import_source(req.source, req.content))
        except ValueError as exc:
            raise HTTPException(400, f"import failed: {exc}")
        return {"source": req.source, "count": len(endpoints),
                "endpoints": [e.to_dict() for e in endpoints]}

    @app.post("/api/jwt/decode")
    async def jwt_decode(payload: dict):
        from .platform.identities import decode_jwt
        token = payload.get("token", "")
        if not isinstance(token, str) or not token:
            raise HTTPException(400, "provide a 'token' string")
        decoded = decode_jwt(token)
        if decoded is None:
            raise HTTPException(400, "not a well-formed JWT")
        return decoded

    # ----------------------------------------------- matrix / graph / sarif
    @app.get("/api/scans/{scan_id}/matrix")
    async def scan_matrix(scan_id: str):
        detail = scan_detail(scan_id)
        result = detail.get("result") or {}
        return {"scan_id": scan_id, "matrix": result.get("matrix", []),
                "identities": result.get("identities", []),
                "resources": result.get("resources", {})}

    @app.get("/api/scans/{scan_id}/graph")
    async def scan_graph(scan_id: str):
        detail = scan_detail(scan_id)
        result = detail.get("result") or {}
        return {"scan_id": scan_id, "graph": result.get("graph", {"nodes": [], "edges": []})}

    @app.get("/api/scans/{scan_id}/report.sarif")
    async def report_sarif(scan_id: str):
        from .platform.sarif import build_sarif
        scan = store.get(scan_id)
        if not scan:
            raise HTTPException(404, "scan not found")
        result = (scan.to_detail().get("result") or {})
        sarif = build_sarif(result.get("findings", []), target=scan.origin)
        return JSONResponse(sarif, headers={
            "Content-Disposition": f'attachment; filename="boundarylens-{scan_id[:8]}.sarif"'})

    # --------------------------------------------------- baselines / regression
    @app.post("/api/baselines", status_code=201)
    async def create_baseline_api(req: BaselineRequest):
        from .platform.regression import build_baseline
        scan = store.get(req.scan_id)
        if not scan:
            raise HTTPException(404, "scan not found")
        detail = scan.to_detail()
        baseline = build_baseline(detail.get("result") or {}, name=req.name, target=scan.origin)
        row = store.create_baseline(str(__import__("uuid").uuid4()), req.name, scan.target_id,
                                    scan.configuration, req.scan_id, baseline)
        return row

    @app.get("/api/baselines")
    async def list_baselines_api(limit: int = 50):
        return {"baselines": store.list_baselines(min(max(limit, 1), 200))}

    @app.post("/api/regression/compare")
    async def regression_compare(req: RegressionRequest):
        from .platform.regression import compare_to_baseline
        baseline = store.get_baseline(req.baseline_id)
        scan = store.get(req.scan_id)
        if not baseline or not scan:
            raise HTTPException(404, "baseline and scan must exist")
        diff = compare_to_baseline(baseline.data, scan.to_detail().get("result") or {}, fail_on=req.fail_on)
        return {"baseline_id": req.baseline_id, "scan_id": req.scan_id, **diff}

    # ---------------------------------------------------------- comparison
    @app.get("/api/compare")
    async def compare(baseline_scan: str, candidate_scan: str):
        base = store.get(baseline_scan)
        cand = store.get(candidate_scan)
        if not base or not cand:
            raise HTTPException(404, "both scans must exist")
        return _diff(base.to_detail(), cand.to_detail())

    # ---------------------------------------------------------------- export
    @app.get("/api/scans/{scan_id}/report.json")
    async def report_json(scan_id: str):
        scan = store.get(scan_id)
        if not scan:
            raise HTTPException(404, "scan not found")
        report = build_report(scan.to_detail(), manifest.name, manifest.authorization.statement)
        return JSONResponse(report, headers={"Content-Disposition": f'attachment; filename="boundarylens-{scan_id[:8]}.json"'})

    @app.get("/api/scans/{scan_id}/report.html", response_class=HTMLResponse)
    async def report_html(scan_id: str):
        scan = store.get(scan_id)
        if not scan:
            raise HTTPException(404, "scan not found")
        report = build_report(scan.to_detail(), manifest.name, manifest.authorization.statement)
        return HTMLResponse(render_html(report))

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "recovered_interrupted_scans": getattr(app.state, "recovered", 0)}

    _mount_frontend(app, settings)
    return app


def _diff(baseline: dict, candidate: dict) -> dict:
    def index(scan: dict) -> dict[str, dict]:
        return {f["finding_id"]: f for f in (scan.get("result") or {}).get("findings", [])
                if f["confirmation"] == "confirmed"}

    b, c = index(baseline), index(candidate)
    bkeys, ckeys = set(b), set(c)
    return {
        "baseline": {"id": baseline["id"], "configuration": baseline["configuration"], "status": baseline["status"]},
        "candidate": {"id": candidate["id"], "configuration": candidate["configuration"], "status": candidate["status"]},
        "resolved": [b[k] for k in sorted(bkeys - ckeys)],
        "persisting": [c[k] for k in sorted(bkeys & ckeys)],
        "new": [c[k] for k in sorted(ckeys - bkeys)],
    }


def _mount_frontend(app: FastAPI, settings: Settings) -> None:
    dist = Path(settings.frontend_dist)
    if not dist.is_dir():
        @app.get("/")
        async def no_frontend():
            return JSONResponse({"message": "BoundaryLens API is running. Build the frontend "
                                 "(frontend/dist) or use the API at /api/.", "docs": "/docs"})
        return
    assets = dist / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/{full_path:path}", response_class=HTMLResponse)
    async def spa(full_path: str, request: Request):
        if full_path.startswith("api/"):
            raise HTTPException(404, "not found")
        candidate = dist / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(dist / "index.html")


app = create_app()
