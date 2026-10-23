"""The authorization checks.

Confirmation rule shared by the access-control checks: a finding is CONFIRMED only
when (a) the manifest expects the identity to be denied, and (b) the response carries
positive evidence that the private resource was actually returned — the seeded marker
for that resource, or ownership fields proving another user's record was served.
A 200 status alone never confirms anything; login pages, generic errors, public data
and empty bodies are explicitly rejected as evidence.
"""

from __future__ import annotations

import os

from .auth import build_clients, identity_password
from .client import Exchange, ScanContext, TargetClient
from .findings import Confirmation, Finding, Severity
from .manifest import Authentication, Manifest, Resource, Route, describe_rule, expected_allowed
from .normalize import compare, get_path


def exposed_markers(ex: Exchange, markers: list[str]) -> list[str]:
    text = ex.text
    return [m for m in markers if m in text]


def looks_like_login_page(ex: Exchange, auth: Authentication) -> bool:
    if ex.content_type == "application/json":
        return False
    text = ex.text
    return any(marker in text for marker in auth.login_page_markers)


def has_real_body(ex: Exchange) -> bool:
    return ex.status == 200 and bool(ex.body.strip()) and not ex.truncated


def _instance(ex: Exchange, ctx: ScanContext, resource: Resource | None = None, markers: list[str] | None = None, extra: dict | None = None) -> dict:
    inst = {
        "method": ex.method,
        "path": ex.path,
        "status": ex.status,
        "resource": resource.id if resource else None,
        "evidence": ex.sanitized(ctx.secrets),
    }
    if markers:
        inst["markers_found"] = markers
    if extra:
        inst.update(extra)
    return inst


class Engine:
    def __init__(self, ctx: ScanContext, manifest: Manifest, origin: str):
        self.ctx = ctx
        self.manifest = manifest
        self.origin = origin
        self.clients: dict[str, TargetClient] = {}
        self.ignore = set(manifest.compare.ignore_fields)
        self.findings: list[Finding] = []
        self.check_status: dict[str, str] = {c: "not_assessed" for c in
                                             ("BL-CROSS-USER", "BL-ADMIN-READ", "BL-ANON-API", "BL-SESSION-REUSE", "BL-SEC-CONFIG")}
        self.workflow_result: dict | None = None

    async def setup(self) -> None:
        self.clients = await build_clients(self.ctx, self.origin, self.manifest)

    async def teardown(self) -> None:
        for c in self.clients.values():
            await c.aclose()

    def client(self, identity: str) -> TargetClient:
        return self.clients[identity]

    # ---------------------------------------------------- shared confirmation
    def confirm_access(self, check_id: str, route: Route, identity_id: str, resource: Resource | None,
                       ex: Exchange, severity: Severity, rationale: str, remediation: str,
                       owner_hint: str | None = None) -> Finding | None:
        """Build a CONFIRMED finding when the response proves a denied identity got private data."""
        identity = self.manifest.identity(identity_id)
        if expected_allowed(route, identity, resource):
            return None  # the manifest permits this access; nothing to confirm
        if looks_like_login_page(ex, self.manifest.authentication) or not has_real_body(ex):
            return None
        markers = exposed_markers(ex, resource.markers) if resource else []
        owner_evidence = None
        if route.owner_field and ex.json() is not None:
            observed_owner = get_path(ex.json(), route.owner_field)
            if observed_owner is not None and observed_owner != identity_id and identity.role != "admin":
                owner_evidence = observed_owner
        if not markers and owner_evidence is None:
            return None  # 200 but no private evidence — not confirmed
        observed = f"HTTP {ex.status}; "
        observed += f"response contains private marker(s) {markers}" if markers else ""
        if owner_evidence:
            observed += (" and " if markers else "") + f"ownership field '{route.owner_field}' = '{owner_evidence}'"
        extra = {}
        if owner_evidence:
            extra["observed_owner"] = owner_evidence
        return Finding(
            check_id=check_id,
            severity=severity,
            confirmation=Confirmation.confirmed,
            method=route.method,
            route=route.path,
            actor_identity=identity_id,
            expected_rule=f"access limited to {describe_rule(route)}" + (f"; owner is {owner_hint}" if owner_hint else ""),
            expected_behavior="Request denied (404/403) with no private resource data.",
            observed_behavior=observed,
            severity_rationale=rationale,
            remediation=remediation,
            limitations="Confirmed against the seeded demo resource named in the manifest. The scanner does not "
                        "enumerate every object; other instances of the same route may share the defect.",
            evidence=ex.sanitized(self.ctx.secrets),
            instances=[_instance(ex, self.ctx, resource, markers, extra)],
        )

    # ------------------------------------------------------------- check 1+2
    async def check_resource_routes(self) -> None:
        """Cross-user access (check 1) and non-admin access to admin-only reads (check 2)."""
        ran_cross = ran_admin = False
        for route in self.manifest.routes:
            if not route.executable or not route.resources:
                continue
            admin_only = route.allowed_roles == {"admin"} and "owner" not in route.allow
            for rid in route.resources:
                resource = self.manifest.resource(rid)
                owner_hint = resource.owner or (f"role:{resource.owner_role}" if resource.owner_role else "unknown")
                for identity in self.manifest.identities:
                    if expected_allowed(route, identity, resource):
                        continue
                    if identity.role == "anonymous":
                        continue  # anonymous belongs to check 3
                    path = route.path.replace("{resource}", resource.value or "")
                    ex = await self.client(identity.id).request(route.method, path, purpose=f"{route.id}:{identity.id}")
                    if admin_only:
                        ran_admin = True
                        f = self.confirm_access(
                            "BL-ADMIN-READ", route, identity.id, resource, ex, Severity.high,
                            "A non-administrator obtained administrator-only data, a privilege-boundary failure.",
                            "Enforce a server-side role check on this operation before returning data; do not rely on the UI hiding it.",
                            owner_hint)
                    else:
                        ran_cross = True
                        f = self.confirm_access(
                            "BL-CROSS-USER", route, identity.id, resource, ex, Severity.high,
                            "One ordinary user read another user's private record — a direct object-level "
                            "authorization failure exposing confidential data.",
                            "Check resource ownership server-side on every read (owner == caller or caller is admin); "
                            "return 404/403 otherwise. Avoid trusting client-supplied object IDs.",
                            owner_hint)
                    if f:
                        self.findings.append(f)
        if ran_cross:
            self.check_status["BL-CROSS-USER"] = "assessed"
        if ran_admin:
            self.check_status["BL-ADMIN-READ"] = "assessed"

    # --------------------------------------------------------------- check 3
    async def check_anonymous(self) -> None:
        anon = next((i for i in self.manifest.identities if i.role == "anonymous"), None)
        if not anon:
            return
        ran = False
        for route in self.manifest.routes:
            if not route.executable or route.is_public:
                continue
            resources = route.resources or [None]
            for rid in resources:
                resource = self.manifest.resource(rid) if rid else None
                if resource and not resource.value:
                    resource = None
                path = route.path.replace("{resource}", resource.value) if resource else route.path
                if "{resource}" in path:
                    continue
                ran = True
                ex = await self.client(anon.id).request(route.method, path, purpose=f"{route.id}:anonymous")
                markers = exposed_markers(ex, resource.markers) if resource else []
                protected = self._protected_without_auth(route, ex, markers)
                if protected:
                    self.findings.append(Finding(
                        check_id="BL-ANON-API",
                        severity=Severity.high if markers else Severity.medium,
                        confirmation=Confirmation.confirmed,
                        method=route.method, route=route.path, actor_identity=anon.id,
                        expected_rule=f"access limited to {describe_rule(route)}",
                        expected_behavior="Unauthenticated request rejected with 401/403 (or redirected to sign-in).",
                        observed_behavior=f"HTTP {ex.status} returned protected data without any session; " + protected,
                        severity_rationale="Protected application data was served to an unauthenticated caller.",
                        remediation="Require a valid session for this route before returning data; ensure new routes "
                                    "inherit the same authentication guard as the rest of the API.",
                        limitations="Confirmed for the seeded resource/route in the manifest; not a full route inventory.",
                        evidence=ex.sanitized(self.ctx.secrets),
                        instances=[_instance(ex, self.ctx, resource, markers)]))
        if ran:
            self.check_status["BL-ANON-API"] = "assessed"

    def _protected_without_auth(self, route: Route, ex: Exchange, markers: list[str]) -> str | None:
        if looks_like_login_page(ex, self.manifest.authentication) or not has_real_body(ex):
            return None
        if ex.content_type != "application/json":
            return None
        if markers:
            return f"response contains private marker(s) {markers}"
        data = ex.json()
        if isinstance(data, dict) and isinstance(data.get("data"), dict):
            inner = data["data"]
            # genuine protected payload, not a public-status style envelope
            if any(k in inner for k in ("invoices", "invoice", "user", "attachments")) and inner:
                return f"JSON payload exposes protected fields {sorted(inner)[:5]}"
        return None

    # --------------------------------------------------------------- check 4
    async def check_session_lifecycle(self) -> None:
        """Dedicated session: login -> use -> logout -> retry. Uses a fresh client so other test sessions are untouched."""
        wf = self.manifest.workflow
        if not wf:
            return
        auth = self.manifest.authentication
        identity = self.manifest.identity(wf.identity)
        probe = TargetClient(self.ctx, self.origin, f"{identity.id}-session-probe")
        steps: list[dict] = []
        finding = None
        try:
            password = identity_password(identity)
            self.ctx.secrets.add(password)
            login = await probe.request(auth.login.method, auth.login.path, purpose="workflow:login",
                                        json_body={auth.login.username_field: identity.username,
                                                   auth.login.password_field: password})
            token = probe.cookies.get(auth.session_cookie)
            if token:
                self.ctx.secrets.add(token)
            steps.append(self._step("login", "Sign in with a dedicated test session", login,
                                    login.status == 200 and bool(token)))
            if login.status != 200 or not token:
                raise RuntimeError("workflow login failed")

            route = self._first_resource_route()
            resource = self.manifest.resource(route.resources[0])
            path = route.path.replace("{resource}", resource.value)
            fetch = await probe.request(route.method, path, purpose="workflow:fetch")
            got = bool(exposed_markers(fetch, resource.markers))
            steps.append(self._step("fetch", "Fetch own resource with the session", fetch, got))

            logout = await probe.request(auth.logout.method, auth.logout.path, purpose="workflow:logout")
            steps.append(self._step("logout", "Sign the session out", logout, logout.status == 200))

            # The logout response clears the client's cookie jar, so replay the captured
            # token explicitly: this tests server-side invalidation, not the browser cookie.
            retry = await probe.request(route.method, path, purpose="workflow:retry-after-logout",
                                        cookies={auth.session_cookie: token})
            still = exposed_markers(retry, resource.markers)
            invalidated = retry.status in (401, 403) or not still
            steps.append(self._step("retry", "Reuse the signed-out session", retry, invalidated,
                                    note="session rejected after logout" if invalidated else "session still valid after logout"))
            self.check_status["BL-SESSION-REUSE"] = "assessed"
            if still and has_real_body(retry):
                finding = Finding(
                    check_id="BL-SESSION-REUSE", severity=Severity.high, confirmation=Confirmation.confirmed,
                    method=route.method, route=route.path, actor_identity=f"{identity.id} (post-logout)",
                    expected_rule="session invalid after logout",
                    expected_behavior="After logout the same session token is rejected (401/403).",
                    observed_behavior=f"After logout the reused session returned HTTP {retry.status} with private "
                                      f"marker(s) {still}, so the server-side session was not invalidated.",
                    severity_rationale="A logged-out session remains usable; a stolen/retained token keeps working, "
                                       "defeating logout.",
                    remediation="Invalidate the server-side session record on logout (delete it from the session store / "
                                "rotate the identifier); do not merely clear the client cookie.",
                    limitations="Exercised with a dedicated throwaway session that does not touch the scanner's other "
                                "test sessions.",
                    evidence=retry.sanitized(self.ctx.secrets),
                    instances=[_instance(retry, self.ctx, resource, still)])
                self.findings.append(finding)
        except Exception as exc:
            steps.append({"id": "error", "label": "Workflow error", "ok": False, "note": str(exc)})
        finally:
            await probe.aclose()
        self.workflow_result = {"id": wf.id, "identity": wf.identity, "steps": steps,
                                "confirmed_finding": finding.finding_id if finding else None}

    def _first_resource_route(self) -> Route:
        for route in self.manifest.routes:
            if route.executable and route.resources and "owner" in route.allow:
                return route
        raise RuntimeError("no owner-scoped resource route for the workflow")

    def _step(self, sid: str, label: str, ex: Exchange, ok: bool, note: str = "") -> dict:
        return {"id": sid, "label": label, "status": ex.status, "ok": ok, "note": note,
                "evidence": ex.sanitized(self.ctx.secrets)}

    # --------------------------------------------------------------- check 5
    async def check_security_config(self) -> None:
        """Header and cookie hygiene. Observations and low-confidence hardening notes only."""
        auth = self.manifest.authentication
        origin_https = self.origin.startswith("https://")
        actor = self.manifest.identity(self._any_authenticated())
        login = await self.client(actor.id).request(
            auth.login.method, auth.login.path, purpose="secconfig:login-cookie",
            json_body={auth.login.username_field: actor.username,
                       auth.login.password_field: os.environ.get(actor.password_env or "", "")})
        observations = []
        set_cookies = login.header_all("set-cookie")
        cookie_line = next((c for c in set_cookies if c.lower().startswith(auth.session_cookie.lower() + "=")), None)
        if cookie_line:
            attrs = cookie_line.lower()
            if "httponly" not in attrs:
                observations.append(("Session cookie is missing HttpOnly", Severity.low,
                                     "Without HttpOnly the session cookie is readable by JavaScript, widening XSS impact.",
                                     "Set HttpOnly on the session cookie."))
            if "samesite" not in attrs:
                observations.append(("Session cookie has no SameSite attribute", Severity.low,
                                     "No SameSite leaves the cookie exposed to cross-site request forgery in some browsers.",
                                     "Set SameSite=Lax (or Strict) on the session cookie."))
            if "secure" not in attrs and origin_https:
                observations.append(("Session cookie is not marked Secure over HTTPS", Severity.low,
                                     "Over HTTPS the Secure flag should be present.", "Add the Secure attribute."))
        probe = await self.client(actor.id).request("GET", auth.verify_path, purpose="secconfig:headers")
        header_checks = [
            ("x-content-type-options", "X-Content-Type-Options", "Responses may be MIME-sniffed by the browser."),
            ("content-security-policy", "Content-Security-Policy", "No CSP; reduced defense-in-depth against injection."),
            ("referrer-policy", "Referrer-Policy", "Referrer may leak to third parties."),
        ]
        for key, name, impact in header_checks:
            if not probe.header(key):
                observations.append((f"Missing response header {name}", Severity.low, impact,
                                     f"Add the {name} response header."))
        note = ("Interpreted for local HTTP development: the Secure attribute and HSTS are not flagged over plain HTTP, "
                "and missing headers are treated as hardening observations, not access-control flaws.")
        for title, sev, rationale, remediation in observations:
            self.findings.append(Finding(
                check_id="BL-SEC-CONFIG", severity=sev, confirmation=Confirmation.observation,
                method="GET", route=title, actor_identity="n/a",
                expected_rule="security hardening best practice",
                expected_behavior="Recommended header/cookie attribute present.",
                observed_behavior=title, severity_rationale=rationale, remediation=remediation,
                limitations=note, evidence={"detail": title},
                instances=[{"observation": title, "severity": sev.value}]))
        self.check_status["BL-SEC-CONFIG"] = "assessed"

    def _any_authenticated(self) -> str:
        return next(i.id for i in self.manifest.identities if i.authenticated)
