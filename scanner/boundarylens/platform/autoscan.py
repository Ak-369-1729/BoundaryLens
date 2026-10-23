"""Automated authorization scan: the end-to-end platform pipeline.

Discovery -> identities -> resource extraction -> planner -> bounded execution ->
differential evidence -> findings + authorization matrix + authorization graph.

Reuses the existing scope-bounded TargetClient, request budget, timeouts, response-size
limits, cancellation and redaction from the core scanner.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

import httpx

from ..client import BudgetExhausted, Exchange, ScanCancelled, ScanContext, TargetClient
from ..findings import Confirmation, Finding, Severity, deduplicate
from ..manifest import Limits
from .endpoint import Endpoint, SAFE_METHODS, param_names
from .evidence import analyze_cross_identity
from .identities import IdentityError, PlatformIdentity
from .planner import Planner, TestCase
from .resources import ResourceGraph, extract_resources

# OWASP API Security Top 10 mapping per check kind.
OWASP = {"bola": "API1:2023 Broken Object Level Authorization",
         "bfla": "API5:2023 Broken Function Level Authorization",
         "anon": "API2:2023 Broken Authentication"}
CWE = {"bola": "CWE-639", "bfla": "CWE-285", "anon": "CWE-306"}
CHECK_ID = {"bola": "BL-AUTO-BOLA", "bfla": "BL-AUTO-BFLA", "anon": "BL-AUTO-ANON"}
TITLE = {"bola": "Broken Object Level Authorization",
         "bfla": "Broken Function Level Authorization",
         "anon": "Unauthenticated access to a protected resource"}
_MARKER_LIKE = re.compile(r"^[A-Z]{2,}[-_][A-Z0-9-]{3,}$|@|^\d{4,}$")


@dataclass
class AutoAuth:
    login_method: str = "POST"
    login_path: str = "/api/auth/login"
    username_field: str = "username"
    password_field: str = "password"
    session_cookie: str = "session"
    verify_path: str = "/api/me"
    login_page_markers: list[str] = field(default_factory=lambda: ['type="password"'])


@dataclass
class AutoScanConfig:
    origin: str
    identities: list[PlatformIdentity]
    endpoints: list[Endpoint]
    auth: AutoAuth | None = None
    limits: Limits = field(default_factory=Limits)
    safe_methods: set[str] = field(default_factory=lambda: {"GET", "HEAD"})
    allow_mutation: bool = False
    max_tests: int = 200
    confidence_threshold: int = 60


@dataclass
class MatrixCell:
    identity: str
    resource: str
    operation: str
    status: str                       # PASS | BLOCKED | VIOLATION | NOT_TESTED | UNSAFE | ERROR
    confidence: int = 0
    finding_id: str | None = None
    detail: str = ""


@dataclass
class AutoScanResult:
    status: str
    started_at: str
    finished_at: str
    requests_sent: int
    request_budget: int
    endpoints: list[dict]
    identities: list[dict]
    resources: dict
    findings: list[dict]
    matrix: list[dict]
    graph: dict
    activity: list[dict]
    test_count: int
    error: str | None = None
    limits: dict = field(default_factory=dict)


class AutoScanner:
    def __init__(self, cfg: AutoScanConfig, *, transport: httpx.AsyncBaseTransport | None = None,
                 cancel: asyncio.Event | None = None, on_activity: Callable[[dict], None] | None = None):
        self.cfg = cfg
        self.transport = transport
        self.activity: list[dict] = []
        self._on_activity = on_activity

        def record(ex: Exchange):
            entry = {"seq": len(self.activity) + 1, "identity": ex.identity, "method": ex.method,
                     "path": ex.path, "purpose": ex.purpose, "status": ex.status, "error": ex.error,
                     "duration_ms": ex.duration_ms, "at": _now()}
            self.activity.append(entry)
            if on_activity:
                on_activity(entry)

        self.ctx = ScanContext(limits=cfg.limits, cancel=cancel or asyncio.Event(),
                               on_exchange=record, transport=transport)
        for ident in cfg.identities:
            self.ctx.secrets |= ident.secret_values()
        self.clients: dict[str, TargetClient] = {}
        self.graph = ResourceGraph()
        self.findings: list[Finding] = []
        self.matrix: list[MatrixCell] = []
        self._baseline_cache: dict[str, Exchange] = {}

    # ---- identity clients ---------------------------------------------------
    async def _client_for(self, ident: PlatformIdentity) -> TargetClient:
        client = TargetClient(self.ctx, self.cfg.origin, ident.id)
        if not ident.authenticated:
            return client
        if ident.kind == "login":
            await self._login(client, ident)
        else:
            client._http.headers.update(ident.auth_headers())
        return client

    async def _login(self, client: TargetClient, ident: PlatformIdentity) -> None:
        import os
        auth = self.cfg.auth
        if not auth:
            raise IdentityError(f"identity {ident.id} uses login but no auth config was provided")
        if not ident.username or not ident.password_env:
            raise IdentityError(f"login identity {ident.id} needs username and password_env")
        password = os.environ.get(ident.password_env)
        if not password:
            raise IdentityError(f"{ident.password_env} is not set for identity {ident.id}")
        self.ctx.secrets.add(password)
        ex = await client.request(auth.login_method, auth.login_path, purpose=f"login:{ident.id}",
                                  json_body={auth.username_field: ident.username, auth.password_field: password})
        for sc in ex.header_all("set-cookie"):
            tok = sc.split(";", 1)[0].split("=", 1)
            if len(tok) == 2 and len(tok[1]) >= 4:
                self.ctx.secrets.add(tok[1])
        if ex.status != 200 or not client.cookies.get(auth.session_cookie):
            raise IdentityError(f"login failed for {ident.id}: HTTP {ex.status}")

    async def setup(self) -> None:
        for ident in self.cfg.identities:
            self.clients[ident.id] = await self._client_for(ident)

    async def teardown(self) -> None:
        for c in self.clients.values():
            await c.aclose()

    # ---- resource discovery -------------------------------------------------
    async def discover_resources(self) -> None:
        """Probe each authenticated identity's own collection/profile endpoints for resource ids."""
        probe_eps = [e for e in self.cfg.endpoints
                     if e.method == "GET" and not param_names(e.path)]
        for ident in self.cfg.identities:
            if not ident.authenticated:
                continue
            client = self.clients[ident.id]
            for ep in probe_eps:
                if self.ctx.cancel.is_set():
                    return
                ex = await client.request("GET", ep.path, purpose=f"discover:{ident.id}")
                data = ex.json()
                if data is None or ex.status != 200:
                    continue
                refs = extract_resources(data, identity=ident.id, method="GET", path=ep.path)
                self.graph.add(refs)

    # ---- execution ----------------------------------------------------------
    async def run_tests(self, cases: list[TestCase]) -> None:
        baselines = [c for c in cases if c.kind == "owner-baseline"]
        tests = [c for c in cases if c.kind != "owner-baseline"]
        for case in baselines:
            if self.ctx.cancel.is_set():
                raise ScanCancelled()
            ex = await self._execute(case)
            self._baseline_cache[case.id] = ex
        for case in tests:
            if self.ctx.cancel.is_set():
                raise ScanCancelled()
            await self._run_one(case)

    async def _execute(self, case: TestCase) -> Exchange:
        client = self.clients[case.identity]
        return await client.request(case.method, case.path, purpose=f"{case.kind}:{case.identity}")

    def _looks_like_login(self, ex: Exchange) -> bool:
        if ex.content_type == "application/json":
            return False
        markers = self.cfg.auth.login_page_markers if self.cfg.auth else []
        return any(m in ex.text for m in markers)

    async def _run_one(self, case: TestCase) -> None:
        if case.method not in SAFE_METHODS and not self.cfg.allow_mutation:
            self.matrix.append(MatrixCell(case.identity, _rlabel(case), case.operation, "UNSAFE",
                                          detail="mutating method not executed (safe mode)"))
            return
        try:
            ex = await self._execute(case)
        except (BudgetExhausted, ScanCancelled):
            raise
        except Exception as exc:
            self.matrix.append(MatrixCell(case.identity, _rlabel(case), case.operation, "ERROR", detail=str(exc)))
            return

        baseline = self._baseline_cache.get(case.baseline_id or "")
        b_json = baseline.json() if baseline else None
        b_body = baseline.text if baseline else ""
        b_status = baseline.status if baseline else None
        markers = _owner_markers(b_json) if b_json is not None else []

        result = analyze_cross_identity(
            baseline_status=b_status, baseline_body=b_body, baseline_json=b_json,
            cand_status=ex.status, cand_body=ex.text, cand_json=ex.json(),
            target_markers=markers, target_value=case.resource_value,
            looks_like_login=self._looks_like_login(ex))

        violation = result.confirmed and result.confidence >= self.cfg.confidence_threshold
        finding_id = None
        if violation:
            finding = self._finding(case, ex, result, markers)
            self.findings.append(finding)
            finding_id = finding.finding_id
        status = "VIOLATION" if violation else ("BLOCKED" if ex.status in (401, 403, 404) or not result.confirmed else "BLOCKED")
        self.matrix.append(MatrixCell(case.identity, _rlabel(case), case.operation, status,
                                      confidence=result.confidence, finding_id=finding_id,
                                      detail="; ".join(result.reasons or result.negative_reasons)[:200]))

    def _finding(self, case: TestCase, ex: Exchange, result, markers: list[str]) -> Finding:
        kind = case.kind
        sev = Severity.high
        reasons = "\n".join(f"- {r}" for r in result.reasons)
        owner = case.resource_owner or "the owner"
        if kind == "bola":
            expected = f"{case.identity} must not retrieve {owner}'s {case.resource_type} {case.resource_value}."
            observed = (f"{case.identity} received HTTP {ex.status} containing the target resource's protected data "
                        f"(confidence {result.confidence}%).")
            remediation = "Verify resource ownership server-side before returning the object (owner == caller or caller is an authorized role)."
        elif kind == "bfla":
            expected = f"Role of '{case.identity}' must not access the privileged endpoint {case.template}."
            observed = f"{case.identity} received HTTP {ex.status} with privileged data (confidence {result.confidence}%)."
            remediation = "Enforce a server-side role/function check on this endpoint before returning data."
        else:
            expected = f"Anonymous callers must not access {case.template}."
            observed = f"Anonymous request received HTTP {ex.status} with protected data (confidence {result.confidence}%)."
            remediation = "Require a valid authenticated session for this endpoint."
        boundary = {"bola": "cross-user object access forbidden",
                    "bfla": "privileged function restricted by role",
                    "anon": "authentication required"}[kind]
        return Finding(
            check_id=CHECK_ID[kind], severity=sev, confirmation=Confirmation.confirmed,
            method=case.method, route=case.template, actor_identity=case.identity,
            expected_rule=f"{OWASP[kind]} · {boundary}",
            expected_behavior=expected, observed_behavior=observed,
            severity_rationale=f"Confirmed authorization-boundary violation ({OWASP[kind]}); confidence {result.confidence}%.",
            remediation=remediation,
            limitations="Confirmed against a discovered resource/endpoint; not an exhaustive object enumeration. "
                        "Confidence is a deterministic evidence score, not a probability.",
            evidence={**ex.sanitized(self.ctx.secrets), "differential": result.to_dict(),
                      "confidence": result.confidence, "owasp": OWASP[kind]},
            cwe=CWE[kind], title=TITLE[kind],
            instances=[{"method": case.method, "path": case.path, "status": ex.status,
                        "resource": f"{case.resource_type} {case.resource_value}" if case.resource_value else case.template,
                        "confidence": result.confidence, "reasons": result.reasons,
                        "evidence": ex.sanitized(self.ctx.secrets)}])

    # ---- outputs ------------------------------------------------------------
    def build_graph(self) -> dict:
        nodes: list[dict] = []
        edges: list[dict] = []
        seen_nodes: set[str] = set()

        def node(nid: str, label: str, ntype: str):
            if nid not in seen_nodes:
                nodes.append({"id": nid, "label": label, "type": ntype})
                seen_nodes.add(nid)

        for ident in self.cfg.identities:
            node(f"id:{ident.id}", ident.id, "identity")
        for (rtype, value), owner in self.graph.owners().items():
            rid = f"res:{rtype}:{value}"
            node(rid, f"{rtype} {value}", "resource")
            node(f"id:{owner}", owner, "identity")
            edges.append({"source": f"id:{owner}", "target": rid, "kind": "owns", "violation": False})
        for cell in self.matrix:
            if cell.status == "VIOLATION":
                rid = f"res:{cell.resource}".replace(" ", ":")
                node(rid, cell.resource, "resource")
                edges.append({"source": f"id:{cell.identity}", "target": rid, "kind": "violation",
                              "violation": True, "confidence": cell.confidence})
        return {"nodes": nodes, "edges": edges}

    def result(self, status: str, started: str, error: str | None) -> AutoScanResult:
        deduped = deduplicate(self.findings)
        return AutoScanResult(
            status=status, started_at=started, finished_at=_now(),
            requests_sent=self.ctx.used, request_budget=self.cfg.limits.max_requests,
            endpoints=[e.to_dict() for e in self.cfg.endpoints],
            identities=[i.public_dict() for i in self.cfg.identities],
            resources={**self.graph.summary(), "items": self.graph.to_list()},
            findings=[f.to_dict() for f in deduped],
            matrix=[vars(c) for c in self.matrix],
            graph=self.build_graph(),
            activity=self.activity, test_count=len(self.matrix),
            error=error,
            limits={"concurrency": self.cfg.limits.concurrency, "timeout_seconds": self.cfg.limits.timeout_seconds,
                    "max_response_bytes": self.cfg.limits.max_response_bytes,
                    "safe_methods": sorted(self.cfg.safe_methods), "allow_mutation": self.cfg.allow_mutation,
                    "confidence_threshold": self.cfg.confidence_threshold})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rlabel(case: TestCase) -> str:
    if case.resource_value:
        # Disambiguate distinct endpoints that address the same object (e.g. the object
        # itself vs. a sub-collection like /attachments), so matrix cells never collide.
        suffix = _endpoint_suffix(case.template)
        base = f"{case.resource_type}:{case.resource_value}"
        return f"{base}{suffix}" if suffix else base
    return case.template


def _endpoint_suffix(template: str) -> str:
    """Return the path portion after the (single) {param}, e.g. '/attachments', else ''."""
    import re as _re
    parts = _re.split(r"\{[^}]+\}", template, maxsplit=1)
    tail = parts[1] if len(parts) == 2 else ""
    return tail.rstrip("/")


def _owner_markers(baseline_json) -> list[str]:
    """Unique-looking string values from the owner's response, usable as cross-user markers."""
    out: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, str) and _MARKER_LIKE.search(v):
                    out.append(v)
                elif isinstance(v, (dict, list)):
                    walk(v)
                elif isinstance(v, int) and v > 999:
                    out.append(str(v))
        elif isinstance(node, list):
            for i in node[:20]:
                walk(i)

    walk(baseline_json)
    return sorted(set(out))[:20]


async def run_autoscan(cfg: AutoScanConfig, *, transport: httpx.AsyncBaseTransport | None = None,
                       cancel: asyncio.Event | None = None,
                       on_activity: Callable[[dict], None] | None = None) -> AutoScanResult:
    scanner = AutoScanner(cfg, transport=transport, cancel=cancel, on_activity=on_activity)
    started = _now()
    status, error = "completed", None
    try:
        await scanner.setup()
        await scanner.discover_resources()
        planner = Planner(cfg.endpoints, cfg.identities, scanner.graph,
                          safe_methods=cfg.safe_methods, allow_mutation=cfg.allow_mutation,
                          max_tests=cfg.max_tests)
        cases = planner.plan()
        await scanner.run_tests(cases)
    except ScanCancelled:
        status, error = "cancelled", "scan cancelled before completion"
    except BudgetExhausted:
        status, error = "failed", f"request budget of {cfg.limits.max_requests} exhausted"
    except Exception as exc:
        status, error = "failed", f"{type(exc).__name__}: {exc}"
    finally:
        await scanner.teardown()
    return scanner.result(status, started, error)
