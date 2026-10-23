"""Removal of credentials and session material from anything that is stored or displayed."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable

REDACTED = "[REDACTED]"
SENSITIVE_HEADERS = {"cookie", "set-cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token", "x-csrf-token"}
SENSITIVE_KEY = re.compile(r"pass(word|wd)?|secret|token|session|authorization|api[_-]?key|cookie|credential", re.I)
# Inline key/value pairs inside non-JSON text, e.g. password=hunter2 or "token": "abc".
_INLINE = re.compile(
    r"""(?P<key>["']?(?:password|passwd|secret|token|session[_-]?id|api[_-]?key|authorization)["']?\s*[:=]\s*)"""
    r"""(?P<q>["']?)(?P<val>[^"'&\s,;}]+)""", re.I)
_BEARER = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", re.I)
SHOWN_RESPONSE_HEADERS = ("content-type", "content-length", "location", "cache-control", "set-cookie",
                          "x-content-type-options", "content-security-policy", "x-frame-options", "referrer-policy",
                          "strict-transport-security")


def scrub_text(text: str, secrets: Iterable[str] = ()) -> str:
    for secret in sorted({s for s in secrets if s and len(s) >= 4}, key=len, reverse=True):
        text = text.replace(secret, REDACTED)
    text = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    return _INLINE.sub(lambda m: f"{m.group('key')}{m.group('q')}{REDACTED}", text)


def scrub_json(value, secrets: Iterable[str] = ()):
    secrets = list(secrets)
    if isinstance(value, dict):
        return {k: (REDACTED if SENSITIVE_KEY.search(str(k)) and v not in (None, "", [], {}) else scrub_json(v, secrets))
                for k, v in value.items()}
    if isinstance(value, list):
        return [scrub_json(v, secrets) for v in value]
    if isinstance(value, str):
        return scrub_text(value, secrets)
    return value


def redact_cookie_header(value: str) -> str:
    parts = []
    for pair in value.split(";"):
        name = pair.split("=", 1)[0].strip()
        if name:
            parts.append(f"{name}={REDACTED}")
    return "; ".join(parts)


def redact_set_cookie(value: str) -> str:
    """Keep the cookie name and attributes (needed for observations), drop the value."""
    first, _, attrs = value.partition(";")
    name = first.split("=", 1)[0].strip()
    return f"{name}={REDACTED}" + (f";{attrs}" if attrs else "")


def scrub_headers(headers: Iterable[tuple[str, str]], secrets: Iterable[str] = (), only: Iterable[str] | None = None) -> dict[str, str]:
    allowed = {h.lower() for h in only} if only is not None else None
    out: dict[str, str] = {}
    for name, value in headers:
        key = name.lower()
        if allowed is not None and key not in allowed:
            continue
        if key == "cookie":
            clean = redact_cookie_header(value)
        elif key == "set-cookie":
            clean = redact_set_cookie(value)
        elif key in SENSITIVE_HEADERS:
            clean = REDACTED
        else:
            clean = scrub_text(value, secrets)
        out[key] = f"{out[key]}\n{clean}" if key in out else clean
    return out


def scrub_body(body: str, content_type: str, secrets: Iterable[str] = (), limit: int = 2000) -> str:
    """Redact a response or request body and cut it to an excerpt."""
    if "json" in content_type:
        try:
            body = json.dumps(scrub_json(json.loads(body), secrets), indent=2, ensure_ascii=False)
        except ValueError:
            body = scrub_text(body, secrets)
    else:
        body = scrub_text(body, secrets)
    if len(body) > limit:
        body = body[:limit] + f"\n… [truncated, {len(body) - limit} more characters]"
    return body
