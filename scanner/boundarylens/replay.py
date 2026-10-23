"""Replay a finding against the local demo only. Credentials resolved server-side; never embedded."""

from __future__ import annotations

import asyncio

from .auth import login_client
from .client import ScanContext
from .manifest import Manifest, Target


async def replay_instance(manifest: Manifest, target: Target, method: str, path: str, identity_id: str) -> dict:
    if not target.local_demo:
        raise ValueError("replay is available for the included local demo only")
    if method.upper() not in ("GET", "HEAD"):
        raise ValueError("replay is limited to safe read methods")
    if not path.startswith("/") or "://" in path:
        raise ValueError("path must be an absolute path on the demo origin")
    identity = manifest.identity(identity_id)
    ctx = ScanContext(limits=manifest.limits)
    client = await login_client(ctx, target.origin, manifest.authentication, identity)
    try:
        ex = await client.request(method.upper(), path, purpose=f"replay:{identity_id}")
    finally:
        await client.aclose()
    return {
        "target_id": target.id,
        "configuration": target.configuration,
        "identity": identity_id,
        "requested": {"method": method.upper(), "path": path},
        "result": ex.sanitized(ctx.secrets),
        "note": "Authentication was resolved server-side from the configured identity. "
                "No credentials or session tokens are included in this output.",
    }
