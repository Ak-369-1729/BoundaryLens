"""Normalized endpoint model shared by every discovery source.

Every adapter (manifest, OpenAPI, Postman, HAR) produces a list of ``Endpoint`` so the
downstream planner/executor/analyzer never needs to know where an endpoint came from.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Path segments that look like identifiers (numeric, UUID, or opaque id_... tokens).
_NUMERIC = re.compile(r"^\d+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_OPAQUE_ID = re.compile(r"^(?=.*\d)[A-Za-z0-9_-]{6,}$")  # has a digit, 6+ chars: ord_29873, inv_a7Kq2


@dataclass
class Endpoint:
    method: str
    path: str                              # templated, e.g. /api/orders/{id}
    source: str = "manifest"               # manifest | openapi | postman | har
    operation_id: str | None = None
    tags: list[str] = field(default_factory=list)
    path_params: list[str] = field(default_factory=list)
    query_params: list[str] = field(default_factory=list)
    security: list[str] = field(default_factory=list)   # named security requirements, [] = unknown
    requires_auth: bool | None = None       # True/False if known from the spec, else None
    request_body_fields: list[str] = field(default_factory=list)
    response_fields: list[str] = field(default_factory=list)
    summary: str = ""
    raw: dict = field(default_factory=dict)

    def __post_init__(self):
        self.method = self.method.upper()
        if not self.path.startswith("/"):
            self.path = "/" + self.path
        if not self.path_params:
            self.path_params = param_names(self.path)

    @property
    def is_safe(self) -> bool:
        return self.method in SAFE_METHODS

    @property
    def template_key(self) -> tuple[str, str]:
        return (self.method, normalize_template(self.path))

    def to_dict(self) -> dict:
        return {
            "method": self.method, "path": self.path, "source": self.source,
            "operation_id": self.operation_id, "tags": self.tags,
            "path_params": self.path_params, "query_params": self.query_params,
            "security": self.security, "requires_auth": self.requires_auth,
            "summary": self.summary, "response_fields": self.response_fields[:30],
        }


def param_names(path: str) -> list[str]:
    return re.findall(r"\{([^}]+)\}", path)


def normalize_template(path: str) -> str:
    """Collapse parameter names so /x/{id} and /x/{orderId} compare equal."""
    return re.sub(r"\{[^}]+\}", "{param}", path.rstrip("/") or "/")


def looks_like_identifier(segment: str) -> bool:
    return bool(_NUMERIC.match(segment) or _UUID.match(segment) or _OPAQUE_ID.match(segment))


def templatize_path(path: str) -> str:
    """Conservatively replace identifier-looking segments with {id} for HAR inference."""
    parts = path.split("/")
    out = []
    for seg in parts:
        out.append("{id}" if seg and looks_like_identifier(seg) else seg)
    return "/".join(out) or "/"


def path_of(url: str) -> str:
    parts = urlsplit(url)
    return parts.path or "/"


def dedupe_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Merge endpoints that share (method, normalized template); keep the richest record."""
    merged: dict[tuple[str, str], Endpoint] = {}
    for ep in endpoints:
        key = ep.template_key
        if key not in merged:
            merged[key] = ep
            continue
        cur = merged[key]
        # prefer the one with more metadata (security, response fields, operation id)
        if _richness(ep) > _richness(cur):
            merged[key] = ep
        for q in ep.query_params:
            if q not in merged[key].query_params:
                merged[key].query_params.append(q)
    return sorted(merged.values(), key=lambda e: (e.path, e.method))


def _richness(ep: Endpoint) -> int:
    return (len(ep.security) + len(ep.response_fields) + len(ep.tags)
            + (2 if ep.operation_id else 0) + (1 if ep.requires_auth is not None else 0))
