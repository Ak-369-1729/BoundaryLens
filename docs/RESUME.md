# BoundaryLens — resume material

Accurate, non-inflated phrasings. This is a personal/course project; do not claim production
deployment, scale, or adoption.

## One-line description

BoundaryLens — an automated authorization-testing platform that detects broken object- and
function-level access control (BOLA/BFLA/IDOR) across multiple identities using evidence-based
differential analysis, with an authorization matrix/graph, SARIF output, and a CI regression gate.

## Two resume bullets

- Built an authorization-testing platform (Python/FastAPI, React/TypeScript, SQLite) that discovers
  an API from OpenAPI/Postman/HAR, exercises it under multiple identities, and confirms broken
  access control via deterministic differential evidence scoring instead of HTTP status codes.
- Added an Identity×Resource×Operation matrix, an authorization-boundary graph, SARIF 2.1.0 output,
  and a baseline/regression CI gate, all behind strict scope, request-budget, and secret-redaction
  controls, with integration tests running the real scanner against a vulnerable/fixed demo.

## Three resume bullets

- Designed a source-agnostic pipeline: OpenAPI 3.x (JSON/YAML), Postman v2.1, and HAR normalize to a
  single endpoint model feeding one planner/executor/analyzer, so new sources are added as adapters.
- Implemented a cross-identity test planner (BOLA/BFLA/anonymous) that extracts resource identifiers
  per identity and generates bounded, safe-by-default (GET/HEAD) tests, with a deterministic
  0–100 confidence engine (owner markers, protected-field overlap, normalized JSON similarity).
- Engineered safety throughout — origin allow-listing, redirect-scope validation, per-request
  timeouts, response-size caps, request budgets, cancellation, and credential redaction — and shipped
  JSON/HTML/SARIF reporting plus a regression baseline that fails CI on new high-severity findings.

## GitHub description

Automated authorization security & regression testing for web apps — detects BOLA/BFLA/IDOR across
identities with evidence-based differential analysis, authorization matrix/graph, SARIF, and a CI
regression gate. Scoped, bounded, non-destructive.

## LinkedIn project description

BoundaryLens is an automated authorization-testing platform I built to catch the access-control
bugs that signature scanners miss. It discovers an API (OpenAPI/Postman/HAR), models multiple
authenticated identities, extracts candidate resources, and automatically generates cross-identity
tests for broken object- and function-level authorization. Instead of trusting HTTP status codes,
it confirms a violation with differential evidence — owner markers, protected-field overlap, and
normalized JSON similarity — and reports a deterministic confidence score with reasons. It
visualizes authorization boundaries as a matrix and graph, exports SARIF for GitHub Code Scanning,
and gates CI on authorization regressions. Built with Python/FastAPI and React/TypeScript, with
strict scope, budget, timeout, and redaction controls and a bundled vulnerable/fixed demo.

## Interview explanation (90 seconds)

"The core idea is that authorization is application-specific and invisible to status codes — a 200
can be a login page or someone else's data. BoundaryLens drives the *same* request under different
identities and compares the responses. First it discovers endpoints from OpenAPI, Postman, or HAR
into one normalized model. Then an identity manager logs in or attaches tokens for each configured
identity — credentials only ever come from environment variables, and if it's a JWT I decode the
claims locally without verifying the signature, purely for role context. While exercising each
identity's own endpoints I extract resource identifiers and record who owns what in a resource
graph. A planner then generates bounded cross-identity tests — Bob requesting Alice's resource,
a normal user hitting an admin endpoint, anonymous hitting a protected one — but only safe GET/HEAD
methods by default. The evidence engine decides each case: it rejects denial bodies and login pages,
then scores owner-marker presence, protected-field overlap, and normalized JSON similarity into a
0–100 confidence with explicit reasons. Confirmed violations become findings, an Identity×Resource×
Operation matrix, and an authorization graph, and I can snapshot a scan as a baseline so CI fails
when a boundary regresses. Everything is scoped to configured origins with request budgets,
timeouts, size caps, and full secret redaction. It's a focused authorization tool — deliberately not
a generic vulnerability or exploitation scanner."
