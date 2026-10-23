# BoundaryLens

**Automated authorization security & regression testing platform for developer-owned web applications.**

BoundaryLens discovers an application's API, models multiple authenticated identities, extracts
candidate resources, automatically generates cross-identity authorization tests, and confirms
broken access control with **evidence-based differential analysis** — then visualizes the
authorization boundaries and gates CI against regressions.

It focuses on the authorization failures that status-code scanners miss: **BOLA/IDOR**, **broken
function-level authorization (BFLA)**, **unauthenticated access**, **session-invalidation**, and
**authorization regressions**. It is intentionally *not* a generic vulnerability scanner — no
XSS/SQLi spraying, no brute force, no exploitation.

This is a course/portfolio project. The approach is not claimed to be novel, commercially proven,
or production-ready. See [Limitations](#limitations) and [Ethical usage](#ethical-usage).

---

## Why BoundaryLens exists

Authorization is application-specific and invisible to signature scanners: a `200 OK` can be a
login page, an empty list, or another user's private record. BoundaryLens answers the question
that matters — *"can identity A reach resource B when it shouldn't?"* — by driving the **same**
requests under different identities and **comparing the responses with evidence**, not status codes.

---

## Features

- **Discovery from multiple sources** → one normalized endpoint model: **OpenAPI 3.x** (JSON/YAML,
  or a live URL), **Postman v2.1**, **HAR** (with conservative path parameterization).
- **Multi-identity manager**: anonymous, user, admin, and custom roles via **bearer token, cookie,
  API key, custom headers, or login/session** — all credentials server-side from env vars only.
- **JWT context analysis**: decodes header/claims **locally, without verifying or cracking** the
  signature, as authorization metadata (no token forging).
- **Automatic resource extraction**: finds resource identifiers (`id`, `orderId`, UUIDs, …) in
  responses and associates them with the discovering identity — never extracting secrets.
- **Automatic cross-identity test generation**: BOLA (A's resource requested by B), BFLA (non-admin
  → privileged endpoint), and anonymous-access tests, bounded and safe-by-default (GET/HEAD only).
- **Differential evidence engine**: deterministic **confidence score (0–100)** with reasons
  (owner marker present, protected-field overlap, JSON similarity, …). A denial body never confirms.
- **Authorization matrix** (Identity × Resource × Operation) and **authorization graph** built from
  real findings.
- **Reports**: JSON, self-contained printable HTML, and **SARIF 2.1.0** (GitHub Code Scanning).
- **Regression baselines + CI gate**: snapshot a clean scan, fail the build when a boundary flips
  from `BLOCKED` to `VIOLATION`.
- **Preserved core**: the original manifest-driven scanner, vulnerable/fixed demo, dashboard,
  redaction, scope/budget/timeout controls, cancellation, persistence, Docker and CI all still work.

---

## Architecture

```
 Discovery sources                      Scanner service (FastAPI, one process)
 ┌───────────────────┐        ┌───────────────────────────────────────────────┐
 │ OpenAPI / Swagger │        │  Endpoint model  ─┐                            │
 │ Postman v2.1      │ ─────▶ │  Identity manager │                            │
 │ HAR               │        │  Resource graph   ├─▶ Test planner             │
 │ BoundaryLens      │        │  (JWT context)    │   (BOLA / BFLA / anon,     │
 │   manifest        │        │                   │    bounded, safe methods)  │
 └───────────────────┘        │                   ▼                            │
                              │   Bounded HTTP engine (scope, budget, timeout, │
 Dashboard (React/TS) ◀─────▶ │   size cap, cancellation, redirect validation) │
   Overview · Auto scan       │                   │                            │
   Matrix · Graph             │                   ▼                            │
   Inventory · Findings       │   Differential analyzer ─▶ Confidence + reasons│
   Regression · Reports       │                   │                            │
                              │                   ▼                            │
                              │   Findings ─▶ Matrix · Graph · JSON/HTML/SARIF │
                              │   Baseline ─▶ Regression ─▶ CI gate            │
                              │   SQLite persistence                           │
                              └─────────────────────┬─────────────────────────┘
                                                    │ in-scope, non-destructive HTTP
                                  ┌─────────────────┴─────────────────┐
                                  ▼                                   ▼
                         Ledgerly VULNERABLE                 Ledgerly FIXED  (demo)
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for module-level detail and
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the safety model.

---

## Quick start

> Requires Docker with the Compose plugin.

```bash
cp .env.example .env            # local, fictional demo values
docker compose up --build
```

Open **http://127.0.0.1:8080** (bound to localhost). Three services start: `demo-vulnerable`,
`demo-fixed`, and `scanner`. Stop with `docker compose down` (`-v` discards the scan database).

### Without Docker

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r scanner/requirements.txt pytest==9.1.1
cd frontend && npm install && npm run build && cd ..
cp .env.example .env
./run_local.sh                  # demo-vulnerable:8081, demo-fixed:8082, scanner:8080
```

---

## Example scan (dashboard)

1. **Automated scan** → pick *Ledgerly (vulnerable)* → acknowledge authorization → **Start**.
   The scanner imports the target's OpenAPI, logs in as each identity, extracts invoice resources,
   and runs cross-identity tests.
2. **Scan detail** shows per-check outcomes and sanitized activity; **Findings** lists confirmed
   BOLA/BFLA/anonymous violations with confidence and evidence.
3. **Authorization matrix** and **Authorization graph** visualize who reached what.
4. Repeat for *Ledgerly (fixed)* — all violations disappear.

### OpenAPI import

The dashboard scan discovers endpoints from the target's own `/openapi.json`. You can also paste an
OpenAPI/Postman/HAR document under **Automated scan → Discovery import** to preview the normalized
endpoints, or import via the API:

```bash
curl -s localhost:8080/api/discovery/import \
  -H 'content-type: application/json' \
  -d "{\"source\":\"openapi\",\"content\":$(jq -Rs . < examples/ledgerly-openapi.json)}"
```

### Multi-identity setup

In the manifest/dashboard, identities authenticate by login (session). For the CLI, configure
identities in `boundarylens.yaml` by **env-var name** (never secret values):

```yaml
identities:
  alice: { role: user,  kind: login,  username: alice, password_env: BL_ALICE_PASSWORD }
  svc:   { role: user,  kind: bearer, token_env: SVC_TOKEN }     # bearer JWT -> claims decoded
  admin: { role: admin, kind: login,  username: admin, password_env: BL_ADMIN_PASSWORD }
```

### Authorization matrix

`Identity × Resource × Operation` with cells `PASS` / `BLOCKED` / `VIOLATION` / `UNSAFE` /
`NOT_TESTED` / `ERROR`. `VIOLATION` cells carry a confidence score and link to the finding.

### Regression testing

```
Dashboard → Regression:  create a baseline from a clean scan,
                         then compare a later scan against it.
Previous:  Bob → Alice's order = BLOCKED
Current:   Bob → Alice's order = VIOLATION   ⇒  NEW AUTHORIZATION REGRESSION
```

### SARIF / CI

```bash
export BL_ALICE_PASSWORD=... BL_BOB_PASSWORD=... BL_ADMIN_PASSWORD=...
# fail the build when a new high-severity regression appears:
python -m boundarylens.cli scan \
  --config boundarylens.yaml \
  --baseline baseline.json \
  --fail-on high \
  --report sarif --out boundarylens.sarif
```

Exit codes: `0` pass · `2` gating regression · `3` scan failed · `4` config error. The committed
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs tests, the frontend build, and an
authorization-regression gate against the demo.

---

## Security / scope model

- Scans run only against **configured origins** (loopback, or hosts in `BL_ALLOWED_HOSTS`); no
  arbitrary browser-entered URLs. Redirects are validated against scope and not followed off-origin.
- **Safe by default**: only `GET`/`HEAD` are executed. Mutating methods discovered in
  OpenAPI/HAR/Postman are **never** run unless explicitly opted in; the manifest's `safe:false`
  routes are never called.
- Bounded **request budget, concurrency, timeouts, response-size cap**, and cancellation.
- **Redaction** everywhere: passwords, cookies, tokens, and auth headers never appear in evidence,
  logs, reports, or exports. Credentials stay server-side and come only from environment variables.

Details in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## Demo

The bundled **Ledgerly** app (fictional expenses) ships in two configurations selected by
`LEDGERLY_MODE`:

| Defect (vulnerable) | Fixed |
|---------------------|-------|
| Any logged-in user reads any invoice (BOLA) | Ownership enforced |
| Any logged-in user reads `/api/admin/summary` (BFLA) | Role enforced |
| Attachments served without auth (anonymous) | Auth + ownership enforced |
| Logout keeps the server session valid | Session invalidated on logout |

All data is deterministic and fictional. Reset a demo with `POST /__demo/reset` (or restart it).

---

## Tests

```bash
PYTHONPATH="$PWD/scanner:$PWD/demo_app" python -m pytest tests -q      # backend + integration
cd frontend && npm run build                                          # frontend build + typecheck
```

Integration tests run the **real** scanner against the **real** demo (both configs) — findings are
not mocked. Coverage includes OpenAPI/Postman/HAR parsing, endpoint normalization, resource
extraction, JWT decoding, planner safety, differential analysis/confidence, SARIF, baseline &
regression, CI thresholds, redaction, scope/redirect restriction, dedup, cancellation, and report
escaping. An optional Playwright smoke test runs with `BL_BROWSER_SMOKE=1`.

---

## Project structure

```
boundarylens/
├── scanner/boundarylens/
│   ├── app.py manager.py runner.py engine.py        # core service + manifest scanner (original)
│   ├── manifest.py client.py auth.py storage.py …   # scope-bounded client, persistence, redaction
│   ├── cli.py                                        # CI entry point (scan + regression gate)
│   └── platform/                                     # the automated platform (new)
│       ├── endpoint.py  discovery/{openapi,postman,har}.py
│       ├── identities.py  resources.py  planner.py  evidence.py
│       ├── autoscan.py  from_manifest.py  config.py
│       ├── regression.py  sarif.py
├── demo_app/ledgerly/        # intentionally vulnerable/fixed demo + deterministic seed
├── frontend/                 # React + TypeScript dashboard (9 views)
├── manifests/ledgerly.yaml   # declarative authorization manifest (original scanner)
├── boundarylens.yaml         # automated-scan / CI config (env-var references only)
├── examples/                 # sample OpenAPI, Postman, HAR
├── docs/                     # ARCHITECTURE, THREAT_MODEL, RESUME, manifest-schema, sample report
├── compose.yaml  .env.example  .github/workflows/ci.yml  LICENSE
```

---

## Limitations

- BoundaryLens tests the authorization **expectations it can derive** (manifest rules, OpenAPI
  security, discovered ownership) — it does not infer an application's complete business policy.
- Confirmations are proven against **discovered** resources/endpoints, not an exhaustive object
  enumeration. The confidence score is a **deterministic evidence score, not a probability**, and
  not CVSS.
- Resource/ownership inference is heuristic and conservative; unusual API shapes may need manifest
  hints. Security-header items are hardening observations, interpreted for local HTTP.
- The demo is intentionally insecure — run it locally only.

---

## Ethical usage

BoundaryLens is for systems you own or are explicitly authorized to test. Every scan requires a
configured origin and an authorization acknowledgment, restricts traffic to that scope, and stays
read-only by default. Do not point it at third-party systems without written permission.

---

## Technical summary

Built an automated authorization-testing platform (Python/FastAPI, React/TypeScript, SQLite) that
discovers an API from OpenAPI/Postman/HAR, drives it under multiple identities, and detects broken
object- and function-level authorization via **evidence-based differential analysis** with a
deterministic confidence score — rather than status codes. Added an authorization matrix/graph,
SARIF output, and a baseline/regression CI gate, all behind strict scope, budget, and redaction
controls. More in [`docs/RESUME.md`](docs/RESUME.md).

--Anwesha Kar#   B o u n d a r y L e n s  
 