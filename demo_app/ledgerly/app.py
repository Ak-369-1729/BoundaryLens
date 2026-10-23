"""Ledgerly: an intentionally vulnerable, fictional expense application.

LEDGERLY_MODE=vulnerable (default) or LEDGERLY_MODE=fixed.

The vulnerable configuration contains four deliberate defects, each marked
with "DEFECT" below. The fixed configuration closes them. Everything else is
identical so the scanner can run one manifest against both.

Do not deploy this application anywhere except a local machine.
"""

import copy
import html
import os
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from . import seed

SESSION_COOKIE = "ledgerly_session"
MODES = ("vulnerable", "fixed")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_app(mode: str | None = None) -> FastAPI:
    mode = (mode or os.environ.get("LEDGERLY_MODE", "vulnerable")).strip().lower()
    if mode not in MODES:
        raise ValueError(f"LEDGERLY_MODE must be one of {MODES}, got {mode!r}")
    fixed = mode == "fixed"
    secure_cookies = os.environ.get("LEDGERLY_SECURE_COOKIES", "false").lower() == "true"

    app = FastAPI(title=f"Ledgerly demo ({mode})", version="1.0.0",
                  description="Fictional expense app for BoundaryLens demonstrations. Local use only.")
    state = {
        "sessions": {},  # token -> username
        "users": copy.deepcopy(seed.USERS),
        "invoices": {inv["id"]: copy.deepcopy(inv) for inv in seed.INVOICES},
    }
    app.state.ledgerly = state
    app.state.mode = mode

    def envelope(data, status: int = 200) -> JSONResponse:
        return JSONResponse({"data": data, "request_id": str(uuid.uuid4()), "generated_at": _now()}, status_code=status)

    def error(status: int, code: str) -> JSONResponse:
        return JSONResponse({"error": code, "request_id": str(uuid.uuid4())}, status_code=status)

    @app.middleware("http")
    async def headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Request-ID"] = str(uuid.uuid4())
        if fixed:
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Referrer-Policy"] = "no-referrer"
            if not request.url.path.startswith(("/docs", "/openapi.json")):
                response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
                response.headers["X-Frame-Options"] = "DENY"
            if request.url.path.startswith("/api/") and not request.url.path.startswith("/api/public/"):
                response.headers["Cache-Control"] = "no-store"
        return response

    def current_user(request: Request) -> dict | None:
        token = request.cookies.get(SESSION_COOKIE)
        username = state["sessions"].get(token) if token else None
        user = state["users"].get(username) if username else None
        if user and user.get("disabled"):
            return None
        return user

    def public_user(user: dict) -> dict:
        return {"username": user["username"], "display_name": user["display_name"], "role": user["role"]}

    def can_read(user: dict, invoice: dict) -> bool:
        return user["role"] == "admin" or invoice["owner"] == user["username"]

    # ---------------------------------------------------------------- auth
    @app.post("/api/auth/login")
    async def login(request: Request):
        try:
            body = await request.json()
        except Exception:
            return error(400, "invalid_json")
        if not isinstance(body, dict):
            return error(400, "invalid_json")
        user = state["users"].get(str(body.get("username", "")))
        if not user or user.get("disabled") or not secrets.compare_digest(str(body.get("password", "")), user["password"]):
            return error(401, "invalid_credentials")
        token = secrets.token_urlsafe(24)
        state["sessions"][token] = user["username"]
        response = envelope({"user": public_user(user)})
        if fixed:
            response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax", secure=secure_cookies, path="/")
        else:
            # Hardening gap (observation only): no HttpOnly / SameSite.
            response.set_cookie(SESSION_COOKIE, token, httponly=False, samesite=None, path="/")
        return response

    @app.post("/api/auth/logout")
    async def logout(request: Request):
        token = request.cookies.get(SESSION_COOKIE)
        if fixed and token:
            state["sessions"].pop(token, None)
        # DEFECT (vulnerable): the server-side session is never revoked; only
        # the browser cookie is cleared, so a copied session token stays valid.
        response = envelope({"logged_out": True})
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    @app.get("/api/me")
    async def me(request: Request):
        user = current_user(request)
        if not user:
            return error(401, "authentication_required")
        return envelope({"user": public_user(user)})

    # ------------------------------------------------------------ invoices
    @app.get("/api/invoices")
    async def list_invoices(request: Request):
        user = current_user(request)
        if not user:
            return error(401, "authentication_required")
        rows = [inv for inv in state["invoices"].values() if can_read(user, inv)]
        return envelope({"invoices": rows, "count": len(rows)})

    @app.get("/api/invoices/{invoice_id}")
    async def get_invoice(invoice_id: str, request: Request):
        user = current_user(request)
        if not user:
            return error(401, "authentication_required")
        invoice = state["invoices"].get(invoice_id)
        if not invoice:
            return error(404, "not_found")
        # DEFECT (vulnerable): authenticated, but ownership is never checked.
        if fixed and not can_read(user, invoice):
            return error(404, "not_found")
        return envelope({"invoice": invoice})

    @app.get("/api/invoices/{invoice_id}/attachments")
    async def get_attachments(invoice_id: str, request: Request):
        user = current_user(request)
        # DEFECT (vulnerable): this route was added without the authentication
        # or ownership checks used elsewhere, so it answers anonymous callers.
        if fixed and not user:
            return error(401, "authentication_required")
        invoice = state["invoices"].get(invoice_id)
        if not invoice:
            return error(404, "not_found")
        if fixed and not can_read(user, invoice):
            return error(404, "not_found")
        return envelope({"invoice_id": invoice_id, "owner": invoice["owner"],
                         "attachments": seed.ATTACHMENTS.get(invoice_id, [])})

    # --------------------------------------------------------------- admin
    @app.get("/api/admin/summary")
    async def admin_summary(request: Request):
        user = current_user(request)
        if not user:
            return error(401, "authentication_required")
        # DEFECT (vulnerable): any signed-in user passes; the role is not checked.
        if fixed and user["role"] != "admin":
            return error(403, "forbidden")
        totals: dict[str, float] = {}
        for inv in state["invoices"].values():
            totals[inv["currency"]] = round(totals.get(inv["currency"], 0) + float(inv["amount"]), 2)
        return envelope({
            "total_invoices": len(state["invoices"]),
            "totals_by_currency": totals,
            "active_users": sum(1 for u in state["users"].values() if not u.get("disabled")),
            "pending_review": [i["number"] for i in state["invoices"].values() if i["status"] == "submitted"],
            "admin_marker": seed.ADMIN_MARKER,
        })

    @app.post("/api/admin/users/{username}/disable")
    async def disable_user(username: str, request: Request):
        """State-changing administrator operation. The scanner manifest marks it unsafe and never calls it."""
        user = current_user(request)
        if not user or user["role"] != "admin":
            return error(403, "forbidden")
        target = state["users"].get(username)
        if not target:
            return error(404, "not_found")
        target["disabled"] = True
        return envelope({"disabled": username})

    # -------------------------------------------------------------- public
    @app.get("/api/public/status")
    async def status():
        return envelope({"service": "ledgerly-demo", "status": "ok", "configuration": mode})

    @app.post("/__demo/reset")
    async def reset(request: Request):
        """Restore seed data and drop all sessions. Only reachable on the local demo network."""
        state["sessions"].clear()
        state["users"] = copy.deepcopy(seed.USERS)
        state["invoices"] = {inv["id"]: copy.deepcopy(inv) for inv in seed.INVOICES}
        return envelope({"reset": True})

    # ---------------------------------------------------------------- HTML
    def page(title: str, body: str) -> HTMLResponse:
        return HTMLResponse(f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{html.escape(title)} · Ledgerly</title>
<style>body{{font-family:system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 16px;background:#111418;color:#e6e8eb}}
a{{color:#7cb7ff}}input,button{{font:inherit;padding:6px 10px;margin:4px 0}}table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #2a2f36;padding:6px;text-align:left}}.banner{{padding:8px 12px;border-radius:6px;background:#2a2f36}}</style>
</head><body><div class="banner">Ledgerly demo · configuration: <strong>{mode}</strong> · fictional data, local use only</div>{body}</body></html>""")

    def login_page() -> HTMLResponse:
        return page("Sign in", """<h1>Sign in</h1>
<form id="f"><label>Username <input name="username" autocomplete="username"></label><br>
<label>Password <input name="password" type="password" autocomplete="current-password"></label><br>
<button>Sign in</button></form><p id="msg"></p>
<script>document.getElementById('f').onsubmit=async e=>{e.preventDefault();const d=new FormData(e.target);
const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({username:d.get('username'),password:d.get('password')})});
if(r.ok){location.href='/'}else{document.getElementById('msg').textContent='Sign-in failed'}}</script>""")

    @app.get("/login", response_class=HTMLResponse)
    async def login_html():
        return login_page()

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        user = current_user(request)
        if not user:
            return login_page()
        rows = "".join(
            f"<tr><td><a href='/app/invoices/{html.escape(i['id'])}'>{html.escape(i['number'])}</a></td>"
            f"<td>{html.escape(i['vendor'])}</td><td>{html.escape(i['amount'])} {html.escape(i['currency'])}</td>"
            f"<td>{html.escape(i['status'])}</td></tr>"
            for i in state["invoices"].values() if can_read(user, i))
        return page("Invoices", f"""<h1>Invoices for {html.escape(user['display_name'])}</h1>
<table><tr><th>Number</th><th>Vendor</th><th>Amount</th><th>Status</th></tr>{rows}</table>
<p><button onclick="fetch('/api/auth/logout',{{method:'POST'}}).then(()=>location.href='/login')">Sign out</button>
· <a href="/docs">API documentation</a></p>""")

    @app.get("/app/invoices/{invoice_id}", response_class=HTMLResponse)
    async def invoice_html(invoice_id: str, request: Request):
        # Both configurations: unauthenticated visitors get the sign-in page with
        # HTTP 200, and unknown/foreign invoices get a "not found" page with 200.
        # These are negative controls: a status-only scanner would misreport them.
        user = current_user(request)
        if not user:
            return login_page()
        invoice = state["invoices"].get(invoice_id)
        if not invoice or not can_read(user, invoice):
            return page("Not found", "<h1>Invoice not found</h1><p>It may have been removed.</p>")
        fields = "".join(f"<tr><th>{html.escape(k)}</th><td>{html.escape(str(v))}</td></tr>" for k, v in invoice.items())
        return page(invoice["number"], f"<h1>{html.escape(invoice['number'])}</h1><table>{fields}</table><p><a href='/'>Back</a></p>")

    return app


app = create_app()
