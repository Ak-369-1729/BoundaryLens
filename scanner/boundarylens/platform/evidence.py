"""Evidence-based differential response analysis and deterministic confidence scoring.

A cross-identity authorization test compares a *baseline* response (the owner legitimately
accessing a resource) with a *candidate* response (another identity accessing the same
resource). Confidence is a deterministic 0–100 score with human-readable reasons. There is
no machine learning here; scoring is rule-based for reliability.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Any

from ..normalize import shape, strip_fields

# Strings that indicate an authorization-error / denial body rather than real data.
_DENIAL = re.compile(r"not\s*authori[sz]ed|unauthori[sz]ed|forbidden|access\s*denied|permission|must\s*log\s*in|"
                     r"please\s*sign\s*in|login\s*required|invalid\s*(token|session)|not\s*found", re.I)
VOLATILE = {"request_id", "generated_at", "timestamp", "trace_id", "requestId", "traceId", "iat", "exp"}


@dataclass
class DifferentialResult:
    confirmed: bool
    confidence: int                     # 0–100
    reasons: list[str] = field(default_factory=list)
    negative_reasons: list[str] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"confirmed": self.confirmed, "confidence": self.confidence,
                "reasons": self.reasons, "negative_reasons": self.negative_reasons, "metrics": self.metrics}


def _is_denial_body(text: str, parsed: Any) -> bool:
    if isinstance(parsed, dict):
        for key in ("error", "message", "detail", "code"):
            v = parsed.get(key)
            if isinstance(v, str) and _DENIAL.search(v):
                return True
        if set(parsed.keys()) <= {"error", "message", "detail", "code", "status", "request_id"} and (
                "error" in parsed or "detail" in parsed):
            return True
    return bool(_DENIAL.search(text[:400]))


def _json_similarity(a: Any, b: Any) -> float:
    if a is None or b is None:
        return 0.0
    sa = _flatten(strip_fields(a, VOLATILE))
    sb = _flatten(strip_fields(b, VOLATILE))
    if not sa and not sb:
        return 1.0
    common = sa & sb
    union = sa | sb
    return len(common) / len(union) if union else 0.0


def _flatten(node: Any, prefix: str = "") -> set[str]:
    out: set[str] = set()
    if isinstance(node, dict):
        for k, v in node.items():
            out |= _flatten(v, f"{prefix}.{k}")
    elif isinstance(node, list):
        for item in node[:20]:
            out |= _flatten(item, f"{prefix}[]")
    else:
        out.add(f"{prefix}={node}")
    return out


def _protected_overlap(baseline: Any, candidate: Any) -> list[str]:
    """Non-volatile leaf values present in BOTH responses (shared private data)."""
    if not isinstance(baseline, (dict, list)) or not isinstance(candidate, (dict, list)):
        return []
    b = {kv for kv in _flatten(strip_fields(baseline, VOLATILE)) if "=" in kv and kv.split("=", 1)[1] not in ("", "None", "0")}
    c = _flatten(strip_fields(candidate, VOLATILE))
    return sorted(kv.split("=", 1)[0].lstrip(".") for kv in (b & c))[:12]


def analyze_cross_identity(
    *, baseline_status: int | None, baseline_body: str, baseline_json: Any,
    cand_status: int | None, cand_body: str, cand_json: Any,
    target_markers: list[str], target_value: str | None, looks_like_login: bool,
) -> DifferentialResult:
    """Decide whether the candidate identity improperly received the baseline's resource."""
    reasons: list[str] = []
    negatives: list[str] = []
    metrics: dict = {}
    score = 0

    # Hard negatives: the candidate was correctly denied.
    if cand_status in (401, 403):
        return DifferentialResult(False, 0, [], [f"candidate received HTTP {cand_status} (denied)"],
                                  {"candidate_status": cand_status})
    if looks_like_login:
        return DifferentialResult(False, 0, [], ["candidate received a login page, not resource data"],
                                  {"candidate_status": cand_status})
    if cand_status is None:
        return DifferentialResult(False, 0, [], ["no candidate response (transport error)"], {})
    if not cand_body.strip():
        return DifferentialResult(False, 0, [], ["candidate response body was empty"], {"candidate_status": cand_status})
    if cand_status == 404:
        negatives.append("candidate received HTTP 404")
    if _is_denial_body(cand_body, cand_json):
        return DifferentialResult(False, 0, [], ["candidate body is an authorization-error structure"],
                                  {"candidate_status": cand_status})

    # Positive evidence.
    markers_found = [m for m in target_markers if m in cand_body]
    if markers_found:
        score += 55
        reasons.append(f"target owner marker(s) present in candidate response: {markers_found}")
    if target_value and _value_present(cand_json, cand_body, target_value):
        score += 20
        reasons.append(f"target resource identifier '{target_value}' returned to the candidate")

    overlap = _protected_overlap(baseline_json, cand_json)
    if overlap:
        score += min(20, 5 + 3 * len(overlap))
        reasons.append(f"{len(overlap)} protected field value(s) overlap the owner's response: {overlap[:6]}")

    similarity = _json_similarity(baseline_json, cand_json)
    metrics["json_similarity"] = round(similarity, 3)
    if similarity >= 0.9:
        score += 15
        reasons.append(f"normalized JSON similarity to the owner's response is high ({similarity:.0%})")
    elif similarity >= 0.6:
        score += 8
        reasons.append(f"normalized JSON similarity to the owner's response is moderate ({similarity:.0%})")

    if cand_status == 200 and baseline_status == 200 and shape(strip_fields(baseline_json, VOLATILE)) == shape(
            strip_fields(cand_json, VOLATILE)) and isinstance(cand_json, (dict, list)) and cand_json:
        score += 10
        reasons.append("candidate response has the same JSON structure as the owner's resource")

    metrics.update({"candidate_status": cand_status, "markers_found": markers_found,
                    "protected_overlap": overlap, "body_len": len(cand_body)})

    # Require at least one strong positive (marker, identifier, or overlap) to confirm.
    strong = bool(markers_found) or (target_value and _value_present(cand_json, cand_body, target_value)) or len(overlap) >= 2
    confidence = max(0, min(100, score))
    confirmed = strong and confidence >= 60
    if not strong:
        negatives.append("no owner marker, target identifier, or protected-field overlap found")
    return DifferentialResult(confirmed, confidence, reasons, negatives, metrics)


def _value_present(parsed: Any, text: str, value: str) -> bool:
    if parsed is not None:
        for kv in _flatten(parsed):
            if kv.endswith(f"={value}"):
                return True
    return bool(re.search(rf'[:"\s/]{re.escape(value)}(["\s,}}/]|$)', text))


def body_similarity_ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a[:4000], b[:4000]).ratio()
