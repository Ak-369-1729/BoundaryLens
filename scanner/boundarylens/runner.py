"""Run a full scan for one target: build identities, execute all checks, collect findings."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

import httpx

from .client import BudgetExhausted, Exchange, ScanCancelled, ScanContext
from .engine import Engine
from .findings import Confirmation, Finding, deduplicate
from .manifest import Manifest, Target


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ScanOutcome:
    target_id: str
    configuration: str
    origin: str
    manifest_name: str
    authorization_statement: str
    status: str                       # completed | cancelled | failed
    started_at: str
    finished_at: str
    requests_sent: int
    request_budget: int
    findings: list[dict]
    check_coverage: dict
    workflow: dict | None
    activity: list[dict]
    error: str | None = None
    limits: dict = field(default_factory=dict)


async def probe_target(ctx: ScanContext, target: Target) -> str | None:
    """Return an error string if the target is unreachable, else None."""
    from .client import TargetClient
    client = TargetClient(ctx, target.origin, "health")
    try:
        ex = await client.request("GET", target.health_path, purpose="health")
        if ex.error:
            return f"target not reachable: {ex.error}"
        if ex.status is None or ex.status >= 500:
            return f"target health check returned HTTP {ex.status}"
        return None
    finally:
        await client.aclose()


async def run_scan(manifest: Manifest, target: Target, *, cancel: asyncio.Event | None = None,
                   transport: httpx.AsyncBaseTransport | None = None,
                   on_activity: Callable[[dict], None] | None = None) -> ScanOutcome:
    activity: list[dict] = []

    def record(ex: Exchange):
        entry = {"seq": len(activity) + 1, "identity": ex.identity, "method": ex.method, "path": ex.path,
                 "purpose": ex.purpose, "status": ex.status, "error": ex.error, "duration_ms": ex.duration_ms,
                 "redirect_blocked": ex.redirect_blocked, "at": _now()}
        activity.append(entry)
        if on_activity:
            on_activity(entry)

    ctx = ScanContext(limits=manifest.limits, cancel=cancel or asyncio.Event(),
                      on_exchange=record, transport=transport)
    started = _now()
    status, error = "completed", None
    findings: list[Finding] = []
    engine = Engine(ctx, manifest, target.origin)

    try:
        health = await probe_target(ctx, target)
        if health:
            raise RuntimeError(health)
        await engine.setup()
        for step in (engine.check_resource_routes, engine.check_anonymous,
                     engine.check_session_lifecycle, engine.check_security_config):
            if ctx.cancel.is_set():
                raise ScanCancelled()
            await step()
        findings = engine.findings
    except ScanCancelled:
        status, error = "cancelled", "scan cancelled before completion"
    except BudgetExhausted:
        status, error = "failed", f"request budget of {manifest.limits.max_requests} exhausted"
    except Exception as exc:  # unreachable target, malformed response, auth failure
        status, error = "failed", f"{type(exc).__name__}: {exc}"
    finally:
        await engine.teardown()

    deduped = deduplicate(findings)
    coverage = {cid: ("assessed" if st == "assessed" else "not_assessed")
                for cid, st in engine.check_status.items()}
    return ScanOutcome(
        target_id=target.id, configuration=target.configuration, origin=target.origin,
        manifest_name=manifest.name, authorization_statement=manifest.authorization.statement,
        status=status, started_at=started, finished_at=_now(),
        requests_sent=ctx.used, request_budget=manifest.limits.max_requests,
        findings=[f.to_dict() for f in deduped],
        check_coverage=coverage, workflow=engine.workflow_result, activity=activity, error=error,
        limits={"concurrency": manifest.limits.concurrency, "timeout_seconds": manifest.limits.timeout_seconds,
                "max_response_bytes": manifest.limits.max_response_bytes, "max_redirects": manifest.limits.max_redirects})


def severity_counts(findings: list[dict]) -> dict:
    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        if f["confirmation"] != Confirmation.not_assessed.value:
            counts[f["severity"]] += 1
    counts["confirmed"] = sum(1 for f in findings if f["confirmation"] == "confirmed")
    counts["observation"] = sum(1 for f in findings if f["confirmation"] == "observation")
    counts["total"] = len(findings)
    return counts
