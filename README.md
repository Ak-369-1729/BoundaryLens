# BoundaryLens

### Automated Authorization Security & Regression Testing Platform

[![CI](https://github.com/Ak-369-1729/BoundaryLens/actions/workflows/ci.yml/badge.svg)](https://github.com/Ak-369-1729/BoundaryLens/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-TypeScript-61DAFB?logo=react&logoColor=black)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Persistence-003B57?logo=sqlite&logoColor=white)
![Tests](https://img.shields.io/badge/tests-55%20passed-success)
![License](https://img.shields.io/badge/license-MIT-green)

> **BoundaryLens does not ask only whether an endpoint returned `200 OK`.  
> It asks whether the identity making that request was actually supposed to receive the resource.**

BoundaryLens is an authorization-security testing platform that discovers an application's API, models multiple authenticated identities, learns candidate resources, generates cross-identity access-control tests, and confirms authorization failures using **evidence-based differential response analysis**.

It is designed specifically for vulnerabilities such as:

- **BOLA / IDOR**
- **Broken Function Level Authorization**
- **Broken Access Control**
- **Unauthenticated Resource Access**
- **Role & Privilege Boundary Violations**
- **Session Invalidation Failures**
- **Authorization Regressions introduced by new code**

Unlike traditional payload-oriented scanners, BoundaryLens is intentionally focused on one difficult question:

> **Can Identity A access Resource B even though the application's authorization model says it should not?**

---

## Why BoundaryLens Exists

Most vulnerability scanners are good at asking questions like:

```text
Does this parameter accept SQL syntax?
Does this page reflect JavaScript?
Is this port exposed?
```

Authorization is different.

Consider:

```http
GET /api/orders/412
Authorization: Bearer <bob-token>
```

The server returns:

```http
HTTP/1.1 200 OK
```

That alone tells us almost nothing.

A `200` response could contain:

```json
{
  "error": "not authorized"
}
```

which may be safe.

Or it could contain:

```json
{
  "id": 412,
  "owner": "alice",
  "email": "alice@example.com",
  "amount": 1499
}
```

which means Bob has just accessed Alice's resource.

BoundaryLens therefore does not treat status codes as vulnerability proof.

Instead, it:

1. establishes a legitimate baseline,
2. replays equivalent access under another identity,
3. compares normalized responses,
4. correlates resource ownership,
5. searches for protected-data overlap,
6. checks authorization expectations,
7. generates an explainable confidence score,
8. reports a vulnerability only when the evidence supports it.

---

# 30-Second Technical Overview

```text
                 ┌───────────────────────────┐
                 │        Target API         │
                 └─────────────┬─────────────┘
                               │
             ┌─────────────────┴─────────────────┐
             │                                   │
       OpenAPI / Swagger                  HAR / Postman
             │                                   │
             └─────────────────┬─────────────────┘
                               ▼
                  Endpoint Discovery Engine
                               │
                               ▼
                     Normalized API Model
                               │
                               ▼
                       Identity Manager
                  ┌────────┬────────┬────────┐
                  │        │        │        │
                Alice     Bob     Admin   Anonymous
                  │        │        │        │
                  └────────┴────┬───┴────────┘
                                ▼
                     Resource Discovery
                                │
                                ▼
                       Resource Graph
                                │
                                ▼
                  Authorization Test Planner
                                │
                                ▼
              Identity × Resource × Operation
                                │
                                ▼
                    Bounded HTTP Executor
                                │
                                ▼
               Differential Evidence Engine
                                │
                   ┌────────────┴────────────┐
                   ▼                         ▼
               Findings              Confidence Score
                   │
        ┌──────────┼───────────┐
        ▼          ▼           ▼
      Matrix      Graph      Reports
                              │
                     JSON / HTML / SARIF
                              │
                              ▼
                    Regression CI Gate
```

---

# What Makes BoundaryLens Different?

## 1. Multi-Identity Authorization Testing

BoundaryLens models multiple identities simultaneously.

For example:

```text
Alice
Bob
Admin
Anonymous
```

Suppose Alice legitimately retrieves:

```http
GET /api/invoices/1001
```

BoundaryLens learns that the resource belongs to Alice.

It can then test:

```text
Alice → Alice Invoice   ✅ baseline
Bob   → Alice Invoice   🔍 authorization test
Anon  → Alice Invoice   🔍 authorization test
Admin → Alice Invoice   🔍 privilege-policy test
```

This converts authorization testing into a structured relationship between:

```text
Identity × Resource × Operation
```

---

## 2. Automatic API Discovery

BoundaryLens can discover application endpoints from:

- **OpenAPI 3.x**
- **Swagger-compatible specifications**
- **Postman Collection v2.1**
- **HAR browser/network captures**
- **BoundaryLens authorization manifests**

All discovery sources are converted into the same normalized internal endpoint representation.

Example:

```text
GET    /api/users/{id}
GET    /api/orders/{orderId}
PATCH  /api/profile/{id}
DELETE /api/orders/{orderId}
GET    /api/admin/summary
```

This allows the authorization engine to operate independently of how an API was discovered.

---

## 3. Automatic Resource Discovery

BoundaryLens inspects JSON responses and extracts candidate resources such as:

```json
{
  "userId": 932,
  "orderId": "ord_29873",
  "invoice_id": 7721
}
```

The scanner can associate these resources with the identity that legitimately discovered them:

```text
Alice
├── User: 932
├── Order: ord_29873
└── Invoice: 7721

Bob
├── User: 614
├── Order: ord_55123
└── Invoice: 9928
```

This resource graph becomes the foundation for cross-identity authorization tests.

Sensitive values such as passwords, bearer tokens, API keys and cookies are excluded/redacted.

---

# Automatic BOLA / IDOR Detection

Consider:

```text
Alice → GET /api/invoices/7721
```

BoundaryLens establishes this as a legitimate baseline.

It can then generate:

```text
Bob → GET /api/invoices/7721
```

If Bob receives Alice's resource, BoundaryLens may produce:

```text
HIGH — Broken Object Level Authorization

Endpoint:
GET /api/invoices/{invoiceId}

Baseline Identity:
Alice

Testing Identity:
Bob

Target Resource:
Invoice 7721

Expected:
Bob should not retrieve Alice's invoice.

Observed:
Bob received a response containing the same resource identifier and
protected fields present in Alice's legitimate response.

Evidence:
✓ Target resource identifier matched
✓ Owner marker matched Alice
✓ Protected fields overlapped
✓ Response structure closely matched baseline
✓ Response was not an authorization-error structure

CWE:
CWE-639

OWASP:
API1 — Broken Object Level Authorization
```

---

# Broken Function Level Authorization

BoundaryLens also evaluates privilege boundaries.

Example:

```text
Normal User
      │
      ▼
GET /api/admin/summary
```

Expected:

```text
403 Forbidden
```

But if the endpoint returns privileged information:

```text
User ────────────► Admin Endpoint
         ❌
```

BoundaryLens can classify the result as a potential:

```text
Broken Function Level Authorization
CWE-285
OWASP API5
```

---

# Evidence-Based Differential Analysis

BoundaryLens intentionally avoids:

```text
HTTP 200 = vulnerable
HTTP 403 = safe
```

Instead, its evidence engine evaluates signals including:

- HTTP status
- normalized JSON structure
- resource identifier overlap
- ownership markers
- protected-field overlap
- response body similarity
- content type
- response length
- redirects
- authorization-error structures
- selected response metadata
- legitimate baseline comparison

The result includes a deterministic:

```text
Confidence: 0–100
```

with human-readable reasons.

For example:

```text
Confidence: 97%

Reasons:
+ target resource ID matched
+ owner marker present
+ protected field overlap detected
+ high normalized JSON similarity
+ no authorization-error structure detected
```

The score is an **evidence score**, not a statistical probability and not CVSS.

---

# Authorization Matrix

BoundaryLens converts scan results into an:

## Identity × Resource × Operation Matrix

Example:

| Identity | Resource | READ | UPDATE | DELETE |
|---|---|---:|---:|---:|
| Alice | Alice Invoice | ✅ PASS | ✅ PASS | — |
| Alice | Bob Invoice | 🟢 BLOCKED | 🟢 BLOCKED | — |
| Bob | Alice Invoice | 🔴 VIOLATION | 🟢 BLOCKED | — |
| Admin | Alice Invoice | ✅ PASS | ✅ PASS | — |
| Anonymous | Alice Invoice | 🟢 BLOCKED | — | — |

Supported states include:

```text
PASS
BLOCKED
VIOLATION
UNSAFE
NOT_TESTED
ERROR
```

The matrix is generated from real scanner results rather than hard-coded demonstration data.

---

# Authorization Boundary Graph

The dashboard also visualizes authorization relationships as a graph.

Expected:

```text
Alice ──────► Alice Invoice

Bob ────────► Bob Invoice

Admin ──────► Alice Invoice
      └─────► Bob Invoice
```

Unexpected access becomes an authorization violation:

```text
Bob ───────────────🔴──────────────► Alice Invoice
```

This makes complex access-control relationships easier to reason about during security reviews.

---

# JWT Authorization Context

When operator-provided authentication uses JWTs, BoundaryLens can decode non-secret authorization metadata locally.

Example:

```json
{
  "sub": "user-123",
  "role": "customer",
  "scope": ["orders:read"],
  "exp": 1792745521
}
```

Supported contextual claims include concepts such as:

```text
sub
role / roles
scope / scp
permissions
aud
iss
exp
iat
```

BoundaryLens does **not** attempt to:

- crack JWT secrets,
- forge tokens,
- brute-force signatures,
- exploit algorithm confusion.

JWT parsing is used to understand authorization context, not attack authentication.

---

# Authorization Regression Testing

Finding a vulnerability once is useful.

Preventing it from returning is better.

BoundaryLens can create an authorization baseline:

```text
Baseline

Bob → Alice Invoice = BLOCKED
Anonymous → Invoice = BLOCKED
User → Admin Summary = BLOCKED
```

After a new application release:

```text
Current

Bob → Alice Invoice = VIOLATION
```

BoundaryLens reports:

```text
NEW AUTHORIZATION REGRESSION

Previous:
BLOCKED

Current:
VIOLATION

Endpoint:
GET /api/invoices/{id}
```

This allows authorization behavior to become part of the development lifecycle rather than a one-time security exercise.

---

# DevSecOps / CI Integration

BoundaryLens includes a GitHub Actions workflow that performs:

```text
Push / Pull Request
        │
        ├── Backend + integration tests
        │
        ├── React production build
        │
        ├── Authorization regression scan
        │
        ├── SARIF generation
        │
        └── GitHub Code Scanning upload
```

The CLI can fail a pipeline when authorization regressions exceed a configured severity threshold.

Example:

```bash
python -m boundarylens.cli scan \
  --config boundarylens.yaml \
  --baseline baseline.json \
  --fail-on high \
  --report sarif \
  --out boundarylens.sarif
```

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | Scan/gate passed |
| `2` | Authorization regression triggered gate |
| `3` | Scan failed |
| `4` | Configuration error |

---

# SARIF Support

BoundaryLens generates **SARIF 2.1.0** reports for integration with security tooling such as GitHub Code Scanning.

Findings can contain:

```text
Rule ID
Title
Severity
Endpoint
HTTP Method
CWE
OWASP Classification
Confidence
Evidence Summary
```

Supported report formats include:

```text
JSON
HTML
SARIF
```

---

# Safe-by-Default Scanner Design

Security tooling should not create another security problem.

BoundaryLens includes explicit safeguards.

### Scope enforcement

Scans operate only against configured origins.

Redirects are checked before following them and cannot silently escape the authorized target scope.

### Read-only defaults

Automatic testing prioritizes:

```text
GET
HEAD
```

Mutating operations are not automatically executed merely because they appeared in OpenAPI, HAR or Postman traffic.

Routes explicitly marked:

```text
safe: false
```

remain protected from automatic execution.

### Resource controls

The HTTP execution layer includes:

- request budgets,
- concurrency limits,
- request timeouts,
- response-size limits,
- cancellation support,
- redirect validation.

### Secret handling

BoundaryLens redacts:

```text
Passwords
Authorization headers
Bearer tokens
Cookies
API keys
Session secrets
```

from evidence, logs and exported reports.

Credentials are supplied server-side through environment variables.

---

# Bundled Vulnerable vs Fixed Demo

BoundaryLens ships with a fictional application called **Ledgerly** in two modes.

```text
Ledgerly Vulnerable
        │
        ▼
   BoundaryLens
        │
        ▼
Authorization violations 🔴
```

and:

```text
Ledgerly Fixed
        │
        ▼
   BoundaryLens
        │
        ▼
Boundaries enforced 🟢
```

The demo contains controlled examples of:

| Vulnerable behaviour | Fixed behaviour |
|---|---|
| User can access another user's invoice | Resource ownership enforced |
| User can access admin functionality | Role enforcement |
| Protected attachment accessible anonymously | Authentication + ownership enforced |
| Logout leaves server-side session valid | Session invalidated |

The application contains fictional deterministic data and exists only for local testing.

---

# Tech Stack

| Layer | Technology |
|---|---|
| Scanner Backend | Python 3.12 |
| API Framework | FastAPI |
| Data Models / Validation | Pydantic |
| Persistence | SQLite / SQLAlchemy |
| Frontend | React |
| Language | TypeScript |
| Build Tool | Vite |
| HTTP Testing | Python async HTTP stack |
| Containers | Docker + Docker Compose |
| CI/CD | GitHub Actions |
| Security Reporting | JSON / HTML / SARIF 2.1.0 |
| Testing | Pytest |
| API Discovery | OpenAPI / Postman / HAR |

---

# Quick Start

## Requirements

The easiest way to run BoundaryLens is with:

```text
Docker Desktop
Docker Compose
```

Clone the repository:

```bash
git clone https://github.com/Ak-369-1729/BoundaryLens.git
cd BoundaryLens
```

Create your local environment file.

### Windows PowerShell

```powershell
Copy-Item .env.example .env
```

### Linux / macOS

```bash
cp .env.example .env
```

Start everything:

```bash
docker compose up --build
```

Open:

```text
http://127.0.0.1:8080
```

Docker starts:

```text
boundarylens scanner
Ledgerly vulnerable demo
Ledgerly fixed demo
```

Stop:

```bash
docker compose down
```

To reset the local BoundaryLens database as well:

```bash
docker compose down -v
```

---

# Demo Workflow

After opening:

```text
http://127.0.0.1:8080
```

choose:

```text
Automated Scan
        ↓
Ledgerly Vulnerable
        ↓
Authorization acknowledgement
        ↓
Start Scan
```

BoundaryLens then performs a workflow similar to:

```text
Import API definition
        ↓
Discover endpoints
        ↓
Authenticate identities
        ↓
Establish legitimate baselines
        ↓
Extract candidate resources
        ↓
Create ownership relationships
        ↓
Generate cross-identity tests
        ↓
Execute bounded requests
        ↓
Perform differential analysis
        ↓
Generate findings
        ↓
Build Matrix + Graph
        ↓
Generate reports
```

Then repeat against:

```text
Ledgerly Fixed
```

to verify that the corrected authorization implementation removes the findings.

---

# Dashboard

BoundaryLens includes dedicated views for:

### Overview

High-level scan statistics and security posture.

### Automated Scan

Discovery-driven authorization testing.

### Inventory

Discovered endpoints and application resources.

### Findings

Confirmed authorization violations and supporting evidence.

### Finding Detail

Full vulnerability explanation, evidence and remediation context.

### Authorization Matrix

Identity × Resource × Operation relationships.

### Authorization Graph

Visual access-control relationships.

### Baseline

Create authorization snapshots for later regression comparisons.

### Regression

Identify authorization boundaries that changed between scans.

---

# Configuration

BoundaryLens supports configuration through:

```text
boundarylens.yaml
```

Example concept:

```yaml
target:
  base_url: http://127.0.0.1:8081

identities:
  alice:
    role: user
    kind: login
    username: alice
    password_env: BL_ALICE_PASSWORD

  bob:
    role: user
    kind: login
    username: bob
    password_env: BL_BOB_PASSWORD

  admin:
    role: admin
    kind: login
    username: admin
    password_env: BL_ADMIN_PASSWORD

scan:
  request_budget: 200
  concurrency: 5
  timeout_seconds: 5
```

Actual credentials are intentionally referenced through environment variables rather than committed into configuration files.

---

# Testing

Run the backend and integration test suite:

```bash
PYTHONPATH="$PWD/scanner:$PWD/demo_app" python -m pytest tests -q
```

Current verified result:

```text
55 passed
1 skipped
```

The tests cover major behavior including:

- OpenAPI discovery
- Postman discovery
- HAR discovery
- endpoint normalization
- resource extraction
- JWT context parsing
- cross-identity planning
- scanner safety rules
- differential analysis
- confidence scoring
- SARIF generation
- baseline creation
- regression detection
- CLI gate thresholds
- scope restrictions
- redirect restrictions
- cancellation
- finding detection
- redaction
- vulnerable/fixed integration scans

The integration suite exercises the scanner against the real bundled demo rather than simply mocking findings.

Build the frontend:

```bash
cd frontend
npm install
npm run build
```

---

# Repository Structure

```text
BoundaryLens/
│
├── scanner/
│   └── boundarylens/
│       ├── app.py
│       ├── client.py
│       ├── engine.py
│       ├── findings.py
│       ├── manager.py
│       ├── reporting.py
│       ├── storage.py
│       │
│       └── platform/
│           ├── autoscan.py
│           ├── endpoint.py
│           ├── evidence.py
│           ├── identities.py
│           ├── planner.py
│           ├── regression.py
│           ├── resources.py
│           ├── sarif.py
│           │
│           └── discovery/
│               ├── openapi.py
│               ├── postman.py
│               └── har.py
│
├── frontend/
│   └── src/
│       ├── views/
│       │   ├── Overview.tsx
│       │   ├── AutoScan.tsx
│       │   ├── Inventory.tsx
│       │   ├── Findings.tsx
│       │   ├── Matrix.tsx
│       │   ├── Graph.tsx
│       │   ├── Baseline.tsx
│       │   └── Regression.tsx
│       └── ...
│
├── demo_app/
│   └── ledgerly/
│
├── manifests/
│   └── ledgerly.yaml
│
├── examples/
│   ├── ledgerly-openapi.json
│   ├── ledgerly.postman_collection.json
│   └── ledgerly-traffic.har
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── THREAT_MODEL.md
│   ├── RESUME.md
│   └── sample-report/
│
├── tests/
│
├── .github/
│   └── workflows/
│       └── ci.yml
│
├── boundarylens.yaml
├── compose.yaml
├── .env.example
├── LICENSE
└── README.md
```

---

# Engineering Decisions

Several design decisions were intentional.

### Authorization over vulnerability breadth

BoundaryLens does not attempt to become another:

```text
XSS + SQLi + port scanner + directory brute-forcer + everything scanner
```

Its scope is deliberately narrow:

> **authorization security testing**

This allows the scanner to model identities, ownership and privilege relationships in greater depth.

---

### Evidence over status codes

Authorization failures require contextual evidence.

BoundaryLens therefore compares legitimate and unauthorized executions rather than simply mapping:

```text
200 → vulnerable
403 → safe
```

---

### Deterministic explainability over opaque classification

Confidence scores are derived from observable evidence.

The scanner can explain why a finding was generated.

---

### Safe execution over maximum request coverage

Automatically executing every endpoint discovered from an API specification would be dangerous.

BoundaryLens therefore prioritizes safe read-only testing and explicitly controls mutation behavior.

---

### Regression testing over one-time scanning

Authorization behavior should be continuously verified.

The baseline/regression engine allows access-control expectations to become part of CI/CD.

---

# Documentation

More detailed engineering documentation is available in:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — internal architecture and data flow
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — scanner threat model and safeguards
- [`docs/RESUME.md`](docs/RESUME.md) — technically accurate project presentation
- [`docs/manifest-schema.md`](docs/manifest-schema.md) — authorization manifest format
- [`docs/sample-report/`](docs/sample-report/) — example scanner reports

---

# Current Limitations

BoundaryLens is a portfolio/course security engineering project rather than a commercial DAST platform.

Important limitations include:

- application-specific business rules cannot always be inferred automatically,
- resource ownership inference is necessarily heuristic,
- authorization coverage depends on discovered endpoints and resources,
- unusual API designs may require manifest hints,
- confidence scores represent deterministic evidence strength rather than probabilities,
- automatic mutation testing is intentionally restricted,
- the bundled intentionally vulnerable application should only be run locally.

These limitations are deliberate and documented rather than hidden behind unrealistic product claims.

---

# Ethical Usage

BoundaryLens is designed only for:

```text
✓ applications you own
✓ local development environments
✓ intentionally vulnerable labs
✓ systems you have explicit authorization to test
```

Do not use BoundaryLens against third-party systems without permission.

The scanner includes technical safeguards, but authorization from the system owner remains mandatory.

---

# Project Summary

**BoundaryLens is an automated authorization-testing platform built with Python/FastAPI and React/TypeScript that discovers APIs from OpenAPI, Postman and HAR; models multiple authenticated identities; extracts resource ownership relationships; generates bounded cross-identity authorization tests; and detects BOLA/BFLA failures through evidence-based differential response analysis.**

It additionally provides:

```text
Authorization Matrix
Authorization Graph
JWT authorization context
JSON / HTML / SARIF reporting
Regression baselines
GitHub Actions CI gating
Scope enforcement
Secret redaction
Request budgets
Safe-by-default execution
```

---

# Resume Version

> **BoundaryLens — Authorization Security & Regression Testing Platform**  
> Built a FastAPI + React security platform that discovers API endpoints and resources from OpenAPI/Postman/HAR, models multiple user and role identities, and automatically generates cross-identity authorization tests for BOLA/IDOR and BFLA. Implemented evidence-based differential response analysis, authorization matrix/graph visualization, SARIF reporting, strict scanner guardrails, and CI/CD regression gating.

---

# Author

**Anwesha Kar**

Computer Science & Engineering  
Chandigarh University

GitHub: [@Ak-369-1729](https://github.com/Ak-369-1729)

---

# License

BoundaryLens is released under the **MIT License**.

The bundled Ledgerly demo application is intentionally vulnerable and must not be deployed publicly.

---

<p align="center">
  <strong>BoundaryLens</strong><br/>
  Test the boundary — not just the endpoint.
</p>
