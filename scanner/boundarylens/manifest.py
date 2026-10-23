"""Declarative scan manifest: scope, identities, resources, routes and expected access."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_ENV = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")
SAFE_METHODS = {"GET", "HEAD"}
ALLOW_TOKENS = re.compile(r"^(public|authenticated|owner|role:[a-z0-9_-]+)$")


class ManifestError(ValueError):
    pass


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Target(Strict):
    id: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    label: str
    origin: str
    configuration: str = ""
    local_demo: bool = False
    health_path: str = "/"

    @field_validator("origin")
    @classmethod
    def _origin(cls, v: str) -> str:
        parts = urlsplit(v)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("origin must be http(s)://host[:port]")
        if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username or parts.password:
            raise ValueError("origin must not include a path, query, fragment or credentials")
        return origin_of(v)


class Limits(Strict):
    max_requests: int = Field(150, ge=10, le=1000)
    concurrency: int = Field(4, ge=1, le=8)
    timeout_seconds: float = Field(5, gt=0, le=30)
    max_response_bytes: int = Field(262144, ge=1024, le=2_000_000)
    max_redirects: int = Field(3, ge=0, le=5)


class Endpoint(Strict):
    method: str = "POST"
    path: str


class LoginEndpoint(Endpoint):
    username_field: str = "username"
    password_field: str = "password"


class Authentication(Strict):
    login: LoginEndpoint
    logout: Endpoint
    session_cookie: str
    verify_path: str
    login_page_paths: list[str] = []
    login_page_markers: list[str] = []


class Identity(Strict):
    id: str = Field(pattern=r"^[a-z0-9_-]{1,32}$")
    role: str
    username: str | None = None
    password_env: str | None = None

    @model_validator(mode="after")
    def _creds(self):
        if self.role != "anonymous" and not (self.username and self.password_env):
            raise ValueError(f"identity {self.id}: username and password_env are required")
        return self

    @property
    def authenticated(self) -> bool:
        return self.role != "anonymous"


class Resource(Strict):
    id: str
    owner: str | None = None
    owner_role: str | None = None
    value: str | None = None
    markers: list[str] = Field(min_length=1)


class Route(Strict):
    id: str
    method: str = "GET"
    path: str
    resources: list[str] = []
    allow: list[str] = Field(min_length=1)
    safe: bool = True
    owner_field: str | None = None
    compare_fields: list[str] = []

    @field_validator("method")
    @classmethod
    def _method(cls, v: str) -> str:
        return v.upper()

    @field_validator("allow")
    @classmethod
    def _allow(cls, v: list[str]) -> list[str]:
        for token in v:
            if not ALLOW_TOKENS.match(token):
                raise ValueError(f"unknown access rule {token!r}")
        return v

    @property
    def executable(self) -> bool:
        """Only declared-safe, read-only methods are ever sent by checks."""
        return self.safe and self.method in SAFE_METHODS

    @property
    def is_public(self) -> bool:
        return "public" in self.allow

    @property
    def allowed_roles(self) -> set[str]:
        return {a.split(":", 1)[1] for a in self.allow if a.startswith("role:")}


class Compare(Strict):
    ignore_fields: list[str] = []


class WorkflowStep(Strict):
    id: str
    action: Literal["login", "request", "logout"]
    label: str
    route: str | None = None
    resource: str | None = None
    expect_resource: str | None = None
    after_logout: bool = False


class Workflow(Strict):
    id: str
    identity: str
    steps: list[WorkflowStep]


class Observations(Strict):
    html_path: str = "/"
    api_route: str | None = None
    api_identity: str | None = None


class Authorization(Strict):
    statement: str


class Manifest(Strict):
    version: Literal[1]
    name: str
    authorization: Authorization
    targets: list[Target] = Field(min_length=1)
    limits: Limits = Limits()
    authentication: Authentication
    identities: list[Identity]
    resources: list[Resource] = []
    routes: list[Route]
    compare: Compare = Compare()
    workflow: Workflow | None = None
    observations: Observations = Observations()

    @model_validator(mode="after")
    def _refs(self):
        ids = {i.id for i in self.identities}
        if "anonymous" not in ids:
            raise ValueError("an 'anonymous' identity is required")
        res = {r.id for r in self.resources}
        routes = {r.id for r in self.routes}
        for r in self.resources:
            if r.owner and r.owner not in ids:
                raise ValueError(f"resource {r.id}: unknown owner {r.owner}")
        for route in self.routes:
            for rid in route.resources:
                if rid not in res:
                    raise ValueError(f"route {route.id}: unknown resource {rid}")
            if "{resource}" in route.path and not route.resources:
                raise ValueError(f"route {route.id}: path has {{resource}} but no resources")
        if self.workflow:
            if self.workflow.identity not in ids:
                raise ValueError("workflow identity is unknown")
            for step in self.workflow.steps:
                if step.route and step.route not in routes:
                    raise ValueError(f"workflow step {step.id}: unknown route")
                for rid in (step.resource, step.expect_resource):
                    if rid and rid not in res:
                        raise ValueError(f"workflow step {step.id}: unknown resource {rid}")
        if len({t.id for t in self.targets}) != len(self.targets):
            raise ValueError("duplicate target id")
        return self

    # lookups
    def identity(self, iid: str) -> Identity:
        return next(i for i in self.identities if i.id == iid)

    def resource(self, rid: str) -> Resource:
        return next(r for r in self.resources if r.id == rid)

    def route(self, rid: str) -> Route:
        return next(r for r in self.routes if r.id == rid)

    def target(self, tid: str) -> Target | None:
        return next((t for t in self.targets if t.id == tid), None)

    def all_markers(self) -> dict[str, str]:
        """marker -> resource id"""
        return {m: r.id for r in self.resources for m in r.markers}


def expected_allowed(route: Route, identity: Identity, resource: Resource | None) -> bool:
    """Evaluate the manifest's declared access rule. This is the policy oracle."""
    for rule in route.allow:
        if rule == "public":
            return True
        if rule == "authenticated" and identity.authenticated:
            return True
        if rule == "owner" and resource is not None and resource.owner == identity.id:
            return True
        if rule.startswith("role:") and identity.role == rule.split(":", 1)[1]:
            return True
    return False


def describe_rule(route: Route) -> str:
    words = {"public": "anyone", "authenticated": "any signed-in identity", "owner": "the resource owner"}

    def phrase(a: str) -> str:
        return words[a] if a in words else f"role '{a.split(':', 1)[1]}'"

    return " or ".join(phrase(a) for a in route.allow)


def origin_of(url: str) -> str:
    p = urlsplit(url)
    port = p.port or (443 if p.scheme == "https" else 80)
    host = p.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    return f"{p.scheme}://{host}:{port}"


def host_permitted(origin: str, extra_hosts: set[str]) -> bool:
    """Loopback addresses are allowed; anything else must be explicitly configured."""
    host = (urlsplit(origin).hostname or "").lower()
    if host == "localhost" or host in extra_hosts:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _interpolate(text: str) -> str:
    return _ENV.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), text)


def load_manifest(path: str | Path, extra_hosts: set[str] | None = None) -> Manifest:
    try:
        raw = yaml.safe_load(_interpolate(Path(path).read_text()))
        manifest = Manifest.model_validate(raw)
    except (OSError, yaml.YAMLError, ValueError) as exc:
        raise ManifestError(f"invalid manifest {path}: {exc}") from exc
    for target in manifest.targets:
        if not host_permitted(target.origin, extra_hosts or set()):
            raise ManifestError(
                f"target {target.id}: host of {target.origin} is not loopback and not listed in BL_ALLOWED_HOSTS")
    return manifest
