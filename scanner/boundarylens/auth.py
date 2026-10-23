"""Resolve configured identities into authenticated clients, server-side."""

from __future__ import annotations

import os

from .client import ScanContext, TargetClient
from .manifest import Authentication, Identity, Manifest


class AuthError(Exception):
    pass


def identity_password(identity: Identity) -> str:
    if not identity.password_env:
        raise AuthError(f"identity {identity.id} has no password_env")
    secret = os.environ.get(identity.password_env)
    if not secret:
        raise AuthError(f"environment variable {identity.password_env} is not set for identity {identity.id}")
    return secret


async def login_client(ctx: ScanContext, origin: str, auth: Authentication, identity: Identity) -> TargetClient:
    """Return a client carrying a fresh session for ``identity`` (anonymous clients carry none)."""
    client = TargetClient(ctx, origin, identity.id)
    if not identity.authenticated:
        return client
    password = identity_password(identity)
    ctx.secrets.add(password)
    body = {auth.login.username_field: identity.username, auth.login.password_field: password}
    ex = await client.request(auth.login.method, auth.login.path, purpose=f"login:{identity.id}", json_body=body)
    for value in ex.header_all("set-cookie"):
        token = value.split(";", 1)[0].split("=", 1)
        if len(token) == 2 and len(token[1]) >= 4:
            ctx.secrets.add(token[1])
    if ex.status != 200:
        await client.aclose()
        raise AuthError(f"login failed for {identity.id}: HTTP {ex.status}")
    if not client.cookies.get(auth.session_cookie):
        await client.aclose()
        raise AuthError(f"login for {identity.id} returned no {auth.session_cookie} cookie")
    return client


async def build_clients(ctx: ScanContext, origin: str, manifest: Manifest) -> dict[str, TargetClient]:
    clients: dict[str, TargetClient] = {}
    try:
        for identity in manifest.identities:
            clients[identity.id] = await login_client(ctx, origin, manifest.authentication, identity)
    except Exception:
        for c in clients.values():
            await c.aclose()
        raise
    return clients
