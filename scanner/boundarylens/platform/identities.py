"""Generalized identity manager: operator-supplied credentials only.

Supports bearer tokens, cookies, API keys, arbitrary headers, and (reusing the existing
engine) manifest login/session identities. Includes local, signature-free JWT claim decoding
used purely as authorization-modeling metadata.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from dataclasses import dataclass, field
from typing import Literal

AuthKind = Literal["anonymous", "bearer", "cookie", "apikey", "headers", "login"]
JWT_CLAIMS_OF_INTEREST = ("sub", "role", "roles", "scope", "scp", "permissions", "aud", "iss", "exp", "iat", "nbf")


class IdentityError(ValueError):
    pass


@dataclass
class PlatformIdentity:
    """One operator-configured test identity."""

    id: str
    role: str = "user"
    kind: AuthKind = "anonymous"
    # credential material is read from the environment, never stored in config/DB
    token_env: str | None = None
    cookie_env: str | None = None
    cookie_name: str = "session"
    apikey_env: str | None = None
    apikey_header: str = "X-API-Key"
    header_envs: dict[str, str] = field(default_factory=dict)  # header name -> env var
    # login-based (manifest style)
    username: str | None = None
    password_env: str | None = None

    @property
    def authenticated(self) -> bool:
        return self.kind != "anonymous"

    def secret_values(self) -> set[str]:
        """Resolved secret strings, for redaction. Never persisted or returned by the API."""
        out: set[str] = set()
        for env in (self.token_env, self.cookie_env, self.apikey_env, self.password_env):
            if env and os.environ.get(env):
                out.add(os.environ[env])
        for env in self.header_envs.values():
            if os.environ.get(env):
                out.add(os.environ[env])
        return out

    def auth_headers(self) -> dict[str, str]:
        """Build the request headers that authenticate this identity (static kinds)."""
        headers: dict[str, str] = {}
        if self.kind == "bearer":
            headers["Authorization"] = f"Bearer {self._req(self.token_env)}"
        elif self.kind == "apikey":
            headers[self.apikey_header] = self._req(self.apikey_env)
        elif self.kind == "cookie":
            headers["Cookie"] = f"{self.cookie_name}={self._req(self.cookie_env)}"
        elif self.kind == "headers":
            for name, env in self.header_envs.items():
                headers[name] = self._req(env)
        return headers

    def _req(self, env: str | None) -> str:
        if not env:
            raise IdentityError(f"identity {self.id}: missing credential env for kind {self.kind}")
        value = os.environ.get(env)
        if not value:
            raise IdentityError(f"identity {self.id}: environment variable {env} is not set")
        return value

    def jwt_context(self) -> dict | None:
        """Decoded, non-secret JWT claims if this identity carries a bearer JWT."""
        if self.kind != "bearer" or not self.token_env:
            return None
        token = os.environ.get(self.token_env)
        if not token:
            return None
        return decode_jwt(token)

    def public_dict(self) -> dict:
        """Metadata safe to return from the API — no secrets, only the env var *names*."""
        ctx = None
        try:
            ctx = self.jwt_context()
        except Exception:
            ctx = None
        return {
            "id": self.id, "role": self.role, "kind": self.kind,
            "authenticated": self.authenticated,
            "credential_source": self._credential_source(),
            "jwt_context": ctx,
        }

    def _credential_source(self) -> str | None:
        for env in (self.token_env, self.cookie_env, self.apikey_env, self.password_env):
            if env:
                return f"env:{env}"
        if self.header_envs:
            return "env:" + ",".join(self.header_envs.values())
        return None


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def decode_jwt(token: str) -> dict | None:
    """Decode a JWT's header and payload locally. Signature is NOT verified or cracked.

    Returns only non-secret claims of interest plus the algorithm/type, or None if the
    token is not a well-formed JWT.
    """
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    claims = {k: payload[k] for k in JWT_CLAIMS_OF_INTEREST if k in payload}
    return {
        "alg": header.get("alg") if isinstance(header, dict) else None,
        "typ": header.get("typ") if isinstance(header, dict) else None,
        "claims": claims,
        "signature_verified": False,
        "note": "Claims decoded locally for authorization modeling; signature not verified.",
    }


def identity_from_dict(data: dict) -> PlatformIdentity:
    allowed = PlatformIdentity.__dataclass_fields__.keys()
    unknown = set(data) - set(allowed)
    if unknown:
        raise IdentityError(f"unknown identity fields: {sorted(unknown)}")
    return PlatformIdentity(**data)
