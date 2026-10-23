"""Resource discovery: extract candidate resource identifiers from JSON responses.

Identifiers are associated with the identity that legitimately discovered them, the source
endpoint, the JSON path, an inferred resource type, and a response fingerprint of the
protected fields seen alongside them. Secret-looking values are never extracted.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

# Keys that typically denote a resource identifier.
_ID_KEY = re.compile(r"(^|_)(id|uuid|guid)$", re.I)
_TYPED_ID_KEY = re.compile(r"^([a-zA-Z]+?)(_?id|_?uuid)$", re.I)  # orderId, order_id, invoiceId
# Keys we must never treat as resources (secret material).
_SECRET_KEY = re.compile(r"pass(word|wd)?|secret|token|session|authorization|api[_-]?key|cookie|credential|refresh", re.I)
# Volatile/correlation identifiers that are not application resources.
_VOLATILE_KEY = re.compile(r"^(request|trace|correlation|span|req|txn|transaction|event)[_-]?(id|uuid)$", re.I)
# Value shapes accepted as identifiers.
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SAFE_STR_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$")
# Field names worth recording as "protected" evidence (ownership/PII-ish, non-secret).
_PROTECTED_HINT = re.compile(r"owner|email|name|balance|amount|iban|account|address|phone|ssn|salary|private|confidential|marker|ref", re.I)


@dataclass(frozen=True)
class ResourceRef:
    resource_type: str
    value: str
    identity: str
    source_method: str
    source_path: str
    json_path: str
    protected_fields: tuple[str, ...]
    fingerprint: str

    def to_dict(self) -> dict:
        return {
            "resource_type": self.resource_type, "value": self.value, "identity": self.identity,
            "source": f"{self.source_method} {self.source_path}", "json_path": self.json_path,
            "protected_fields": list(self.protected_fields), "fingerprint": self.fingerprint,
        }


def _is_identifier_value(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value > 0
    if isinstance(value, str):
        return bool(_UUID.match(value) or _SAFE_STR_ID.match(value))
    return False


def _resource_type(key: str, container_hint: str | None) -> str:
    m = _TYPED_ID_KEY.match(key)
    if m and m.group(1).lower() not in ("i",):  # e.g. orderId -> order
        return m.group(1).lower()
    if key.lower() in ("id", "uuid", "guid") and container_hint:
        return container_hint.lower().rstrip("s")
    return (container_hint or "resource").lower().rstrip("s")


def _protected_fields(obj: dict) -> tuple[str, ...]:
    return tuple(sorted(k for k in obj if _PROTECTED_HINT.search(k) and not _SECRET_KEY.search(k)))


def fingerprint(obj: Any) -> str:
    """Structural fingerprint: sorted non-secret keys, stable across volatile values."""
    if isinstance(obj, dict):
        keys = sorted(k for k in obj if not _SECRET_KEY.search(str(k)))
        return hashlib.sha256((",".join(keys)).encode()).hexdigest()[:12]
    return hashlib.sha256(type(obj).__name__.encode()).hexdigest()[:12]


def extract_resources(data: Any, *, identity: str, method: str, path: str,
                      max_refs: int = 50) -> list[ResourceRef]:
    """Walk a JSON structure and collect resource identifiers with context."""
    refs: list[ResourceRef] = []

    def walk(node: Any, json_path: str, container_hint: str | None):
        if len(refs) >= max_refs:
            return
        if isinstance(node, dict):
            prot = _protected_fields(node)
            fp = fingerprint(node)
            for key, value in node.items():
                child_path = f"{json_path}.{key}" if json_path else key
                if _SECRET_KEY.search(str(key)) or _VOLATILE_KEY.match(str(key)):
                    continue  # never extract secret or volatile correlation values
                if (_ID_KEY.search(key) or _TYPED_ID_KEY.match(key)) and _is_identifier_value(value):
                    refs.append(ResourceRef(
                        resource_type=_resource_type(key, container_hint),
                        value=str(value), identity=identity,
                        source_method=method, source_path=path, json_path=child_path,
                        protected_fields=prot, fingerprint=fp))
                if isinstance(value, (dict, list)):
                    walk(value, child_path, key)
        elif isinstance(node, list):
            for i, item in enumerate(node[:20]):
                walk(item, f"{json_path}[{i}]", container_hint)

    walk(data, "", None)
    return refs


class ResourceGraph:
    """All discovered resources, indexed by identity and by resource type."""

    def __init__(self) -> None:
        self.refs: list[ResourceRef] = []

    def add(self, refs: list[ResourceRef]) -> None:
        seen = {(r.identity, r.resource_type, r.value, r.source_path) for r in self.refs}
        for r in refs:
            key = (r.identity, r.resource_type, r.value, r.source_path)
            if key not in seen:
                self.refs.append(r)
                seen.add(key)

    def for_identity(self, identity: str) -> list[ResourceRef]:
        return [r for r in self.refs if r.identity == identity]

    def owners(self) -> dict[tuple[str, str], str]:
        """(resource_type, value) -> discovering identity (first seen)."""
        out: dict[tuple[str, str], str] = {}
        for r in self.refs:
            out.setdefault((r.resource_type, r.value), r.identity)
        return out

    def summary(self) -> dict:
        by_identity: dict[str, int] = {}
        by_type: dict[str, int] = {}
        for r in self.refs:
            by_identity[r.identity] = by_identity.get(r.identity, 0) + 1
            by_type[r.resource_type] = by_type.get(r.resource_type, 0) + 1
        return {"total": len(self.refs), "by_identity": by_identity, "by_type": by_type}

    def to_list(self) -> list[dict]:
        return [r.to_dict() for r in self.refs]
