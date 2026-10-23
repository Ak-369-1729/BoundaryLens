"""boundarylens.yaml project configuration -> AutoScanConfig.

Secrets are never stored here: identities reference environment variable names only.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from ..manifest import Limits, host_permitted, origin_of
from .autoscan import AutoAuth, AutoScanConfig
from .identities import PlatformIdentity

_ENV = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")


class ConfigError(ValueError):
    pass


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TargetCfg(_Strict):
    base_url: str
    health_path: str = "/"


class AuthCfg(_Strict):
    login_method: str = "POST"
    login_path: str = "/api/auth/login"
    username_field: str = "username"
    password_field: str = "password"
    session_cookie: str = "session"
    verify_path: str = "/api/me"
    login_page_markers: list[str] = Field(default_factory=lambda: ['type="password"'])


class DiscoveryCfg(_Strict):
    openapi: str | None = None
    openapi_url: str | None = None
    postman: str | None = None
    har: str | None = None


class IdentityCfg(_Strict):
    role: str = "user"
    kind: str = "anonymous"
    token_env: str | None = None
    cookie_env: str | None = None
    cookie_name: str = "session"
    apikey_env: str | None = None
    apikey_header: str = "X-API-Key"
    header_envs: dict[str, str] = Field(default_factory=dict)
    username: str | None = None
    password_env: str | None = None


class ScanCfg(_Strict):
    request_budget: int = 200
    concurrency: int = 4
    timeout_seconds: float = 5
    max_response_bytes: int = 262144
    max_redirects: int = 3
    safe_methods: list[str] = Field(default_factory=lambda: ["GET", "HEAD"])
    allow_mutation: bool = False
    max_tests: int = 200
    confidence_threshold: int = 60


class ReportCfg(_Strict):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    json_report: str | None = Field(default=None, alias="json")
    html: str | None = None
    sarif: str | None = None


class RegressionCfg(_Strict):
    baseline: str | None = None
    fail_on: str = "high"


class ScopeCfg(_Strict):
    allowed_hosts: list[str] = Field(default_factory=list)


class ProjectConfig(_Strict):
    target: TargetCfg
    auth: AuthCfg | None = None
    discovery: DiscoveryCfg = Field(default_factory=DiscoveryCfg)
    identities: dict[str, IdentityCfg]
    scan: ScanCfg = Field(default_factory=ScanCfg)
    report: ReportCfg = Field(default_factory=ReportCfg)
    regression: RegressionCfg = Field(default_factory=RegressionCfg)
    scope: ScopeCfg = Field(default_factory=ScopeCfg)


def _interpolate(text: str) -> str:
    return _ENV.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), text)


def load_project_config(path: str | Path) -> ProjectConfig:
    try:
        raw = yaml.safe_load(_interpolate(Path(path).read_text()))
        return ProjectConfig.model_validate(raw)
    except (OSError, yaml.YAMLError, ValueError) as exc:
        raise ConfigError(f"invalid config {path}: {exc}") from exc


def build_identities(cfg: ProjectConfig) -> list[PlatformIdentity]:
    out = []
    for iid, ic in cfg.identities.items():
        out.append(PlatformIdentity(id=iid, **ic.model_dump()))
    return out


def to_autoscan_config(cfg: ProjectConfig, endpoints) -> AutoScanConfig:
    origin = origin_of(cfg.target.base_url)
    allowed = {h.strip().lower() for h in cfg.scope.allowed_hosts if h.strip()}
    if not host_permitted(origin, allowed):
        raise ConfigError(f"target host of {origin} is not loopback and not listed in scope.allowed_hosts")
    auth = None
    if cfg.auth:
        auth = AutoAuth(**cfg.auth.model_dump())
    limits = Limits(max_requests=cfg.scan.request_budget, concurrency=cfg.scan.concurrency,
                    timeout_seconds=cfg.scan.timeout_seconds, max_response_bytes=cfg.scan.max_response_bytes,
                    max_redirects=cfg.scan.max_redirects)
    return AutoScanConfig(
        origin=origin, identities=build_identities(cfg), endpoints=endpoints, auth=auth, limits=limits,
        safe_methods={m.upper() for m in cfg.scan.safe_methods}, allow_mutation=cfg.scan.allow_mutation,
        max_tests=cfg.scan.max_tests, confidence_threshold=cfg.scan.confidence_threshold)
