"""Discovery adapters: every source normalizes to boundarylens.platform.endpoint.Endpoint."""

from __future__ import annotations

from ..endpoint import Endpoint, dedupe_endpoints
from .har import import_har
from .openapi import import_openapi
from .postman import import_postman

SOURCES = ("openapi", "postman", "har")


def import_source(kind: str, text: str) -> list[Endpoint]:
    kind = kind.lower()
    if kind in ("openapi", "swagger"):
        return import_openapi(text)
    if kind == "postman":
        return import_postman(text)
    if kind == "har":
        return import_har(text)
    raise ValueError(f"unknown discovery source {kind!r}; expected one of {SOURCES}")


__all__ = ["Endpoint", "dedupe_endpoints", "import_source", "import_openapi", "import_postman", "import_har", "SOURCES"]
