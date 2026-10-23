"""Authorization test planner.

Turns (endpoints × identities × discovered resources) into a bounded, safe set of test
cases: cross-user BOLA, role/function-level (BFLA), and anonymous-access checks. Mutating
methods are never planned unless explicitly allowed. Budgets prevent combinatorial blow-up.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .endpoint import SAFE_METHODS, Endpoint, param_names
from .identities import PlatformIdentity
from .resources import ResourceGraph, ResourceRef

_ADMIN_HINT = re.compile(r"admin|internal|system|manage|privileg|superuser|root", re.I)
_PRIVILEGED_ROLES = {"admin", "administrator", "root", "superuser", "support", "moderator", "staff"}


@dataclass
class TestCase:
    id: str
    kind: str                       # bola | bfla | anon | owner-baseline
    identity: str                   # the acting identity
    method: str
    path: str                       # concrete path (params filled)
    template: str                   # endpoint template
    expected: str                   # "allow" | "deny"
    reason: str
    resource_type: str | None = None
    resource_value: str | None = None
    resource_owner: str | None = None
    baseline_id: str | None = None  # for bola: the owner-baseline test case id
    operation: str = "READ"

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "identity": self.identity, "method": self.method,
                "path": self.path, "template": self.template, "expected": self.expected,
                "reason": self.reason, "resource_type": self.resource_type,
                "resource_value": self.resource_value, "resource_owner": self.resource_owner,
                "operation": self.operation, "baseline_id": self.baseline_id}


def _operation(method: str) -> str:
    return {"GET": "READ", "HEAD": "READ", "OPTIONS": "READ", "POST": "CREATE",
            "PUT": "UPDATE", "PATCH": "UPDATE", "DELETE": "DELETE"}.get(method.upper(), method.upper())


def endpoint_requires_privilege(ep: Endpoint) -> bool:
    if _ADMIN_HINT.search(ep.path):
        return True
    if any(_ADMIN_HINT.search(t) for t in ep.tags):
        return True
    return False


def fill_path(template: str, value: str) -> str | None:
    params = param_names(template)
    if len(params) != 1:
        return None
    return re.sub(r"\{[^}]+\}", value, template)


class Planner:
    def __init__(self, endpoints: list[Endpoint], identities: list[PlatformIdentity],
                 graph: ResourceGraph, *, safe_methods: set[str] | None = None,
                 allow_mutation: bool = False, max_tests: int = 200):
        self.endpoints = endpoints
        self.identities = identities
        self.graph = graph
        self.safe_methods = {m.upper() for m in (safe_methods or SAFE_METHODS)}
        self.allow_mutation = allow_mutation
        self.max_tests = max_tests
        self._seq = 0

    def _id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}-{self._seq:04d}"

    def _method_allowed(self, method: str) -> bool:
        if method in self.safe_methods and method in SAFE_METHODS:
            return True
        return self.allow_mutation and method in {"PUT", "PATCH", "DELETE", "POST"}

    def plan(self) -> list[TestCase]:
        cases: list[TestCase] = []
        cases += self._plan_bola()
        cases += self._plan_bfla()
        cases += self._plan_anonymous()
        return cases[: self.max_tests]

    # ---- cross-user BOLA ----------------------------------------------------
    def _plan_bola(self) -> list[TestCase]:
        cases: list[TestCase] = []
        owners = self.graph.owners()
        resource_eps = [e for e in self.endpoints
                        if len(param_names(e.path)) == 1 and self._method_allowed(e.method)]
        human_ids = [i for i in self.identities if i.authenticated and i.role not in _PRIVILEGED_ROLES]
        for ep in resource_eps:
            rtype_hint = _type_hint(ep)
            for (rtype, value), owner in owners.items():
                if rtype_hint and rtype_hint != rtype and rtype not in ep.path.lower():
                    continue
                path = fill_path(ep.path, value)
                if not path:
                    continue
                owner_identity = next((i for i in self.identities if i.id == owner), None)
                if not owner_identity:
                    continue
                baseline = TestCase(
                    id=self._id("base"), kind="owner-baseline", identity=owner, method=ep.method,
                    path=path, template=ep.path, expected="allow",
                    reason=f"{owner} legitimately reads their own {rtype} {value}",
                    resource_type=rtype, resource_value=value, resource_owner=owner,
                    operation=_operation(ep.method))
                cases.append(baseline)
                for actor in human_ids:
                    if actor.id == owner:
                        continue
                    cases.append(TestCase(
                        id=self._id("bola"), kind="bola", identity=actor.id, method=ep.method,
                        path=path, template=ep.path, expected="deny",
                        reason=f"{actor.id} must not read {owner}'s {rtype} {value}",
                        resource_type=rtype, resource_value=value, resource_owner=owner,
                        baseline_id=baseline.id, operation=_operation(ep.method)))
        return cases

    # ---- role / function-level (BFLA) --------------------------------------
    def _plan_bfla(self) -> list[TestCase]:
        cases: list[TestCase] = []
        priv_eps = [e for e in self.endpoints
                    if endpoint_requires_privilege(e) and not param_names(e.path) and self._method_allowed(e.method)]
        privileged = next((i for i in self.identities if i.role in _PRIVILEGED_ROLES and i.authenticated), None)
        non_priv = [i for i in self.identities if i.authenticated and i.role not in _PRIVILEGED_ROLES]
        for ep in priv_eps:
            baseline_id = None
            if privileged:
                base = TestCase(
                    id=self._id("base"), kind="owner-baseline", identity=privileged.id, method=ep.method,
                    path=ep.path, template=ep.path, expected="allow",
                    reason=f"{privileged.id} legitimately accesses the privileged endpoint",
                    resource_owner=privileged.id, operation=_operation(ep.method))
                cases.append(base)
                baseline_id = base.id
            for actor in non_priv:
                cases.append(TestCase(
                    id=self._id("bfla"), kind="bfla", identity=actor.id, method=ep.method,
                    path=ep.path, template=ep.path, expected="deny",
                    reason=f"privileged endpoint; role '{actor.role}' must not access it",
                    baseline_id=baseline_id, operation=_operation(ep.method)))
        return cases

    # ---- anonymous access to protected endpoints ---------------------------
    def _plan_anonymous(self) -> list[TestCase]:
        anon = next((i for i in self.identities if not i.authenticated), None)
        if not anon:
            return []
        authed = next((i for i in self.identities if i.authenticated), None)
        cases: list[TestCase] = []
        owners = self.graph.owners()
        for ep in self.endpoints:
            if not self._method_allowed(ep.method):
                continue
            if ep.requires_auth is False and not endpoint_requires_privilege(ep):
                continue  # explicitly public
            params = param_names(ep.path)
            if len(params) > 1:
                continue
            if params:
                hint = _type_hint(ep)
                matches = [(rt, v, o) for (rt, v), o in owners.items()
                           if rt == hint or rt in ep.path.lower()]
                target = (matches or [(rt, v, o) for (rt, v), o in owners.items()])[:1]
                if not target:
                    continue
                rtype, value, owner = target[0]
                path = fill_path(ep.path, value)
                if not path:
                    continue
                base = TestCase(
                    id=self._id("base"), kind="owner-baseline", identity=owner, method=ep.method,
                    path=path, template=ep.path, expected="allow",
                    reason=f"{owner} legitimately reads their own {rtype} {value}",
                    resource_type=rtype, resource_value=value, resource_owner=owner,
                    operation=_operation(ep.method))
                cases.append(base)
                cases.append(TestCase(
                    id=self._id("anon"), kind="anon", identity=anon.id, method=ep.method,
                    path=path, template=ep.path, expected="deny",
                    reason="anonymous caller must not read a protected resource",
                    resource_type=rtype, resource_value=value, resource_owner=owner,
                    baseline_id=base.id, operation=_operation(ep.method)))
            else:
                if ep.requires_auth is None and not endpoint_requires_privilege(ep):
                    continue  # unknown auth + not privileged: skip to avoid false positives
                baseline_id = None
                if authed:
                    base = TestCase(
                        id=self._id("base"), kind="owner-baseline", identity=authed.id, method=ep.method,
                        path=ep.path, template=ep.path, expected="allow",
                        reason=f"{authed.id} legitimately accesses this endpoint",
                        resource_owner=authed.id, operation=_operation(ep.method))
                    cases.append(base)
                    baseline_id = base.id
                cases.append(TestCase(
                    id=self._id("anon"), kind="anon", identity=anon.id, method=ep.method,
                    path=ep.path, template=ep.path, expected="deny",
                    reason="anonymous caller must not access this protected endpoint",
                    baseline_id=baseline_id, operation=_operation(ep.method)))
        return cases


def _type_hint(ep: Endpoint) -> str | None:
    """Guess the resource type an endpoint addresses from its path, e.g. /api/orders/{id} -> order."""
    for seg in reversed(ep.path.split("/")):
        if seg and not seg.startswith("{"):
            return seg.lower().rstrip("s")
    return None
