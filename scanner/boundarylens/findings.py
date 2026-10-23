"""Finding data model, severities, and deduplication."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class Confirmation(str, Enum):
    confirmed = "confirmed"          # evidence proves the boundary was crossed
    observation = "observation"      # hardening note, not a proven access-control failure
    not_assessed = "not_assessed"    # the check could not run


CHECKS = {
    "BL-CROSS-USER": {"title": "Cross-user private-resource access", "cwe": "CWE-639"},
    "BL-ADMIN-READ": {"title": "Non-admin access to an administrator-only operation", "cwe": "CWE-285"},
    "BL-ANON-API": {"title": "Anonymous access to a protected API resource", "cwe": "CWE-306"},
    "BL-SESSION-REUSE": {"title": "Session not invalidated after logout", "cwe": "CWE-613"},
    "BL-SEC-CONFIG": {"title": "Security configuration observation", "cwe": "CWE-693"},
    # Automated-platform checks (generated from discovered endpoints + identities).
    "BL-AUTO-BOLA": {"title": "Broken Object Level Authorization", "cwe": "CWE-639"},
    "BL-AUTO-BFLA": {"title": "Broken Function Level Authorization", "cwe": "CWE-285"},
    "BL-AUTO-ANON": {"title": "Unauthenticated access to a protected resource", "cwe": "CWE-306"},
}


@dataclass
class Finding:
    check_id: str
    severity: Severity
    confirmation: Confirmation
    method: str
    route: str                       # normalized route template, e.g. /api/invoices/{resource}
    actor_identity: str
    expected_rule: str
    expected_behavior: str
    observed_behavior: str
    severity_rationale: str
    remediation: str
    limitations: str
    evidence: dict = field(default_factory=dict)
    instances: list[dict] = field(default_factory=list)
    cwe: str = ""
    title: str = ""

    def __post_init__(self):
        meta = CHECKS.get(self.check_id, {})
        self.title = self.title or meta.get("title", self.check_id)
        self.cwe = self.cwe or meta.get("cwe", "")

    @property
    def dedup_key(self) -> tuple:
        return (self.check_id, self.method, self.route, self.actor_identity, self.expected_rule)

    @property
    def finding_id(self) -> str:
        digest = hashlib.sha256("|".join(map(str, self.dedup_key)).encode()).hexdigest()[:10]
        return f"BL-{digest}"

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "confirmation": self.confirmation.value,
            "method": self.method,
            "route": self.route,
            "actor_identity": self.actor_identity,
            "expected_rule": self.expected_rule,
            "expected_behavior": self.expected_behavior,
            "observed_behavior": self.observed_behavior,
            "severity_rationale": self.severity_rationale,
            "cwe": self.cwe,
            "remediation": self.remediation,
            "limitations": self.limitations,
            "instance_count": len(self.instances) or 1,
            "instances": self.instances,
            "evidence": self.evidence,
        }


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Merge findings with the same boundary; keep each affected instance visible."""
    merged: dict[tuple, Finding] = {}
    for f in findings:
        key = f.dedup_key
        if key in merged:
            existing = merged[key]
            existing.instances.extend(f.instances)
            if f.severity.rank > existing.severity.rank:
                existing.severity, existing.severity_rationale = f.severity, f.severity_rationale
        else:
            merged[key] = f
    ordered = sorted(merged.values(), key=lambda f: (-f.severity.rank, f.check_id, f.route))
    return ordered
