# BoundaryLens threat model

## What BoundaryLens is designed to detect

- **Broken Object Level Authorization (BOLA/IDOR)** — one user reading another user's resource.
- **Broken Function Level Authorization (BFLA)** — a non-privileged identity reaching a
  privileged/admin operation.
- **Unauthenticated access** to resources that require a session.
- **Session-invalidation failures** — a logged-out session that still returns protected data
  (manifest scanner workflow).
- **Authorization regressions** — a boundary that was enforced becoming unenforced between scans.

## What it intentionally does NOT detect

No XSS, SQL injection, SSRF payloads, deserialization, brute force, credential stuffing, password
cracking, JWT signature forgery/algorithm-confusion, port scanning, or exploit chaining. It is an
authorization-modeling and verification tool, not a generic vulnerability scanner or exploitation
framework.

## Scanner-abuse considerations

The scanner could be misused to probe systems the operator does not own. Mitigations:

- **Authorization gate.** Every scan requires a configured target origin and an explicit
  authorization acknowledgment (`BL_REQUIRE_ACK`, default on).
- **No arbitrary targets.** Targets come from the manifest/config, not from browser input.
- **Origin allow-listing.** Only loopback hosts are permitted unless a host is explicitly listed in
  `BL_ALLOWED_HOSTS` / `scope.allowed_hosts`. Non-loopback targets are rejected at load time.

## SSRF / scope control

`TargetClient` resolves every request against the configured origin and refuses out-of-scope URLs
(`OutOfScope`). The client runs with `trust_env=False` so ambient proxies are ignored.

## Redirect escape

Redirects are **not** auto-followed by the HTTP layer. Each hop is validated against the configured
origin; an off-origin `Location` is recorded as `redirect_blocked` and not followed. A redirect
limit bounds hops.

## Secret handling

- Credentials are supplied only through **environment variables**; config/manifest files store
  env-var **names**, never values.
- JWTs are decoded **locally**; signatures are never verified or cracked, and only known
  non-secret claims are surfaced.
- `redact.py` scrubs passwords, cookies, `Set-Cookie`, `Authorization`, API keys, and known secret
  values from all evidence, activity logs, reports (JSON/HTML/SARIF), and the API. Resource
  extraction skips secret-looking keys entirely.

## Denial-of-service protections

Per scan: a **request budget** (`max_requests`), **bounded concurrency**, **per-request timeouts**,
and a **response-size cap** (streamed read aborted past the limit). The planner caps the number of
generated tests (`max_tests`) to avoid combinatorial blow-up. Scans are cancellable and stop issuing
requests promptly.

## Destructive-request protections

Only `GET`/`HEAD` are executed by default. Mutating methods (`POST`/`PUT`/`PATCH`/`DELETE`)
discovered in any source are filtered out by the planner and re-checked in the executor, which marks
them `UNSAFE` instead of sending them. The manifest's `safe:false` routes (e.g. an admin
"disable user" endpoint) are never called. Enabling mutation testing is an explicit opt-in
(`allow_mutation`) and is out of scope for the default demo.

## Residual risk

An operator with valid credentials for a system they do not own could still point BoundaryLens at
it by editing the config and allow-list. The tool reduces accidental misuse but cannot replace
authorization to test; see the ethical-usage note in the README.
