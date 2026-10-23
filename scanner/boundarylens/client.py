"""Scope-restricted, budgeted HTTP client. Every request a scan sends goes through here."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from .manifest import Limits, origin_of
from .redact import SHOWN_RESPONSE_HEADERS, scrub_body, scrub_headers


class ScanCancelled(Exception):
    pass


class BudgetExhausted(Exception):
    pass


class OutOfScope(Exception):
    pass


@dataclass
class Exchange:
    """One logical request (including in-scope redirects) and its bounded response."""

    identity: str
    method: str
    path: str
    purpose: str
    url: str = ""
    status: int | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    truncated: bool = False
    redirects: list[dict] = field(default_factory=list)
    redirect_blocked: str | None = None
    error: str | None = None
    duration_ms: int = 0
    request_headers: list[tuple[str, str]] = field(default_factory=list)
    request_json: Any = None

    @property
    def content_type(self) -> str:
        return self.header("content-type").split(";")[0].strip().lower()

    def header(self, name: str) -> str:
        return next((v for k, v in self.headers if k.lower() == name), "")

    def header_all(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k.lower() == name]

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        if "json" not in self.content_type or self.truncated:
            return None
        try:
            return json.loads(self.body)
        except ValueError:
            return None

    def sanitized(self, secrets) -> dict:
        """Evidence form of this exchange. Contains no cookie, password or token values."""
        req_body = None
        if self.request_json is not None:
            req_body = scrub_body(json.dumps(self.request_json), "application/json", secrets)
        return {
            "request": {
                "identity": self.identity,
                "method": self.method,
                "url": self.url,
                "headers": scrub_headers(self.request_headers, secrets, only=("cookie", "content-type", "accept")),
                "body": req_body,
            },
            "response": None if self.status is None else {
                "status": self.status,
                "headers": scrub_headers(self.headers, secrets, only=SHOWN_RESPONSE_HEADERS),
                "body_excerpt": scrub_body(self.text, self.content_type, secrets),
                "truncated": self.truncated,
                "redirects": self.redirects,
                "redirect_blocked": self.redirect_blocked,
            },
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


@dataclass
class ScanContext:
    limits: Limits
    cancel: asyncio.Event = field(default_factory=asyncio.Event)
    on_exchange: Callable[[Exchange], None] | None = None
    transport: httpx.AsyncBaseTransport | None = None
    secrets: set[str] = field(default_factory=set)
    used: int = 0

    def __post_init__(self):
        self.semaphore = asyncio.Semaphore(self.limits.concurrency)

    def reserve(self) -> None:
        if self.cancel.is_set():
            raise ScanCancelled()
        if self.used >= self.limits.max_requests:
            raise BudgetExhausted()
        self.used += 1


class TargetClient:
    """HTTP session for one identity against one target origin."""

    def __init__(self, ctx: ScanContext, origin: str, identity: str):
        self.ctx = ctx
        self.origin = origin_of(origin)
        self.identity = identity
        self._http = httpx.AsyncClient(
            base_url=origin,
            follow_redirects=False,
            timeout=httpx.Timeout(ctx.limits.timeout_seconds),
            transport=ctx.transport,
            headers={"User-Agent": "BoundaryLens/1.0 (authorized local scan)", "Accept": "application/json, text/html;q=0.8"},
            trust_env=False,
        )

    @property
    def cookies(self) -> httpx.Cookies:
        return self._http.cookies

    def in_scope(self, url: str) -> bool:
        parts = urlsplit(url)
        return parts.scheme in ("http", "https") and origin_of(url) == self.origin

    async def request(self, method: str, path: str, *, purpose: str, json_body: Any = None,
                      cookies: dict[str, str] | None = None) -> Exchange:
        if not path.startswith("/"):
            raise OutOfScope(f"path must be absolute: {path!r}")
        url = urljoin(self.origin + "/", path.lstrip("/"))
        if not self.in_scope(url):
            raise OutOfScope(url)
        ex = Exchange(identity=self.identity, method=method, path=path, purpose=purpose, url=url, request_json=json_body)
        started = time.monotonic()
        try:
            await self._send_chain(ex, method, url, json_body, cookies)
        finally:
            ex.duration_ms = int((time.monotonic() - started) * 1000)
            if self.ctx.on_exchange and (ex.status is not None or ex.error):
                self.ctx.on_exchange(ex)
        return ex

    async def _send_chain(self, ex: Exchange, method: str, url: str, json_body: Any,
                          cookies: dict[str, str] | None = None) -> None:
        for hop in range(self.ctx.limits.max_redirects + 1):
            self.ctx.reserve()
            try:
                async with self.ctx.semaphore:
                    req = self._http.build_request(method, url, json=json_body, cookies=cookies)
                    ex.request_headers = list(req.headers.items())
                    resp = await self._http.send(req, stream=True)
                    try:
                        body, truncated = await self._read_bounded(resp)
                    finally:
                        await resp.aclose()
            except httpx.TimeoutException:
                ex.error = "timeout"
                return
            except httpx.TransportError as exc:
                ex.error = f"transport error: {type(exc).__name__}"
                return
            ex.url, ex.status, ex.headers, ex.body, ex.truncated = url, resp.status_code, list(resp.headers.items()), body, truncated
            location = resp.headers.get("location")
            if resp.status_code not in (301, 302, 303, 307, 308) or not location:
                return
            nxt = urljoin(url, location)
            ex.redirects.append({"status": resp.status_code, "location": urlsplit(nxt).path or "/"})
            if not self.in_scope(nxt):
                ex.redirect_blocked = f"redirect to {origin_of(nxt)} is outside the configured origin and was not followed"
                return
            if hop == self.ctx.limits.max_redirects:
                ex.redirect_blocked = "redirect limit reached"
                return
            if resp.status_code == 303 or (resp.status_code in (301, 302) and method != "GET"):
                method, json_body = "GET", None
            url = nxt

    async def _read_bounded(self, resp: httpx.Response) -> tuple[bytes, bool]:
        limit = self.ctx.limits.max_response_bytes
        chunks, size = [], 0
        async for chunk in resp.aiter_bytes():
            chunks.append(chunk)
            size += len(chunk)
            if size > limit:
                return b"".join(chunks)[:limit], True
        return b"".join(chunks), False

    async def aclose(self) -> None:
        await self._http.aclose()
