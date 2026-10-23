"""Build an automated scan from the existing manifest + target.

This reuses the manifest's identities, authentication and limits so the dashboard's
automated scan needs no separate configuration. Endpoints are discovered from the target's
own OpenAPI document (or any imported source).
"""

from __future__ import annotations

from ..manifest import Manifest, Target
from .autoscan import AutoAuth, AutoScanConfig
from .endpoint import Endpoint
from .identities import PlatformIdentity


def identities_from_manifest(manifest: Manifest) -> list[PlatformIdentity]:
    out: list[PlatformIdentity] = []
    for ident in manifest.identities:
        if not ident.authenticated:
            out.append(PlatformIdentity(id=ident.id, role=ident.role, kind="anonymous"))
        else:
            out.append(PlatformIdentity(
                id=ident.id, role=ident.role, kind="login",
                username=ident.username, password_env=ident.password_env))
    return out


def auth_from_manifest(manifest: Manifest) -> AutoAuth:
    a = manifest.authentication
    return AutoAuth(
        login_method=a.login.method, login_path=a.login.path,
        username_field=a.login.username_field, password_field=a.login.password_field,
        session_cookie=a.session_cookie, verify_path=a.verify_path,
        login_page_markers=list(a.login_page_markers) or ['type="password"'])


def autoscan_config(manifest: Manifest, target: Target, endpoints: list[Endpoint],
                    *, confidence_threshold: int = 60, allow_mutation: bool = False) -> AutoScanConfig:
    return AutoScanConfig(
        origin=target.origin,
        identities=identities_from_manifest(manifest),
        endpoints=endpoints,
        auth=auth_from_manifest(manifest),
        limits=manifest.limits,
        safe_methods={"GET", "HEAD"},
        allow_mutation=allow_mutation,
        max_tests=200,
        confidence_threshold=confidence_threshold)
