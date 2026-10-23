"""Scan lifecycle manager: bounded background execution, live progress, cancellation."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

from .manifest import Manifest, Target
from .runner import ScanOutcome, run_scan, severity_counts
from .storage import Store


class ScanManager:
    def __init__(self, manifest: Manifest, store: Store, max_concurrent_scans: int = 2):
        self.manifest = manifest
        self.store = store
        self._gate = asyncio.Semaphore(max_concurrent_scans)
        self._tasks: dict[str, asyncio.Task] = {}
        self._cancels: dict[str, asyncio.Event] = {}
        self._progress: dict[str, dict] = {}

    def start(self, target: Target) -> str:
        scan_id = str(uuid.uuid4())
        self.store.create(scan_id, target.id, target.configuration, target.origin, kind="manifest")
        cancel = self._register(scan_id)
        task = asyncio.create_task(self._run(scan_id, target, cancel))
        self._track(scan_id, task)
        return scan_id

    def start_autoscan(self, target: Target, *, confidence_threshold: int = 60) -> str:
        scan_id = str(uuid.uuid4())
        self.store.create(scan_id, target.id, target.configuration, target.origin, kind="autoscan")
        cancel = self._register(scan_id)
        task = asyncio.create_task(self._run_autoscan(scan_id, target, cancel, confidence_threshold))
        self._track(scan_id, task)
        return scan_id

    def _register(self, scan_id: str) -> asyncio.Event:
        cancel = asyncio.Event()
        self._cancels[scan_id] = cancel
        self._progress[scan_id] = {"requests_sent": 0, "activity": []}
        return cancel

    def _track(self, scan_id: str, task: asyncio.Task) -> None:
        self._tasks[scan_id] = task
        task.add_done_callback(lambda _t, sid=scan_id: self._cleanup(sid))

    async def _run_autoscan(self, scan_id: str, target: Target, cancel: asyncio.Event,
                            confidence_threshold: int) -> None:
        from .platform.autoscan import run_autoscan
        from .platform.discovery import import_openapi
        from .platform.from_manifest import autoscan_config
        async with self._gate:
            if cancel.is_set():
                self.store.update(scan_id, status="cancelled", error="cancelled before start",
                                  finished_at=datetime.now(timezone.utc))
                return
            self.store.update(scan_id, status="running", started_at=datetime.now(timezone.utc))

            def on_activity(entry: dict):
                prog = self._progress[scan_id]
                prog["requests_sent"] = entry["seq"]
                prog["activity"] = (prog["activity"] + [entry])[-200:]

            try:
                spec = await self._fetch_openapi(target)
                endpoints = import_openapi(spec)
                cfg = autoscan_config(self.manifest, target, endpoints,
                                      confidence_threshold=confidence_threshold)
                result = await run_autoscan(cfg, cancel=cancel, on_activity=on_activity)
            except Exception as exc:
                self.store.update(scan_id, status="failed", error=f"{type(exc).__name__}: {exc}",
                                  finished_at=datetime.now(timezone.utc))
                return
            self.store.update(scan_id, status=result.status, error=result.error,
                              requests_sent=result.requests_sent,
                              finished_at=datetime.now(timezone.utc),
                              result=self._autoscan_payload(result))

    async def _fetch_openapi(self, target: Target) -> str:
        from .client import ScanContext, TargetClient
        ctx = ScanContext(limits=self.manifest.limits)
        client = TargetClient(ctx, target.origin, "discovery")
        try:
            ex = await client.request("GET", "/openapi.json", purpose="discovery:openapi")
            if ex.status != 200 or not ex.body:
                raise RuntimeError(f"could not fetch {target.origin}/openapi.json (HTTP {ex.status})")
            return ex.text
        finally:
            await client.aclose()

    @staticmethod
    def _autoscan_payload(result) -> dict:
        return {
            "scan_kind": "autoscan",
            "findings": result.findings,
            "severity_counts": severity_counts(result.findings),
            "matrix": result.matrix,
            "graph": result.graph,
            "resources": result.resources,
            "endpoints": result.endpoints,
            "identities": result.identities,
            "activity": result.activity,
            "test_count": result.test_count,
            "limits": result.limits,
            "request_budget": result.request_budget,
            "check_coverage": {}, "workflow": None,
        }

    def _cleanup(self, scan_id: str) -> None:
        self._tasks.pop(scan_id, None)

    async def _run(self, scan_id: str, target: Target, cancel: asyncio.Event) -> None:
        async with self._gate:
            if cancel.is_set():
                self.store.update(scan_id, status="cancelled", error="cancelled before start",
                                  finished_at=datetime.now(timezone.utc))
                return
            self.store.update(scan_id, status="running", started_at=datetime.now(timezone.utc))

            def on_activity(entry: dict):
                prog = self._progress[scan_id]
                prog["requests_sent"] = entry["seq"]
                prog["activity"] = (prog["activity"] + [entry])[-200:]

            try:
                outcome = await run_scan(self.manifest, target, cancel=cancel, on_activity=on_activity)
            except Exception as exc:  # defensive: run_scan handles its own, but never leave a scan hung
                self.store.update(scan_id, status="failed", error=f"{type(exc).__name__}: {exc}",
                                  finished_at=datetime.now(timezone.utc))
                return
            self.store.update(scan_id, status=outcome.status, error=outcome.error,
                              requests_sent=outcome.requests_sent,
                              finished_at=datetime.now(timezone.utc),
                              result=self._result_payload(outcome))

    @staticmethod
    def _result_payload(outcome: ScanOutcome) -> dict:
        return {
            "manifest_name": outcome.manifest_name,
            "authorization_statement": outcome.authorization_statement,
            "findings": outcome.findings,
            "severity_counts": severity_counts(outcome.findings),
            "check_coverage": outcome.check_coverage,
            "workflow": outcome.workflow,
            "activity": outcome.activity,
            "limits": outcome.limits,
            "request_budget": outcome.request_budget,
        }

    def cancel(self, scan_id: str) -> bool:
        event = self._cancels.get(scan_id)
        if event and not event.is_set():
            event.set()
            return True
        return False

    def progress(self, scan_id: str) -> dict:
        return self._progress.get(scan_id, {"requests_sent": 0, "activity": []})

    def is_active(self, scan_id: str) -> bool:
        return scan_id in self._tasks

    async def shutdown(self) -> None:
        for event in self._cancels.values():
            event.set()
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)
