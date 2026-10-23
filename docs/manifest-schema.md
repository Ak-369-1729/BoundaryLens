# Scan manifest schema

The manifest is the **declared authorization policy**. BoundaryLens does not infer an
application's business rules; it tests the rules written here. One manifest is run against
every configured target (e.g. the vulnerable and fixed demo configurations).

The file is YAML. `${VAR:-default}` placeholders are substituted from the environment at load
time (used for origins and nothing secret). Unknown keys are rejected.

## Top level

| Key | Required | Meaning |
|-----|----------|---------|
| `version` | yes | Must be `1`. |
| `name` | yes | Human label for the manifest. |
| `authorization.statement` | yes | Explicit authorization/scope acknowledgment shown in the UI and reports. |
| `targets` | yes | One or more targets to scan (see below). |
| `limits` | no | Request budget and safety bounds. |
| `authentication` | yes | How to log in/out and recognize a login page. |
| `identities` | yes | The test identities; an `anonymous` identity is required. |
| `resources` | no | Seeded resources with private markers used as evidence. |
| `routes` | yes | Routes with their declared access rules. |
| `compare.ignore_fields` | no | Volatile JSON fields ignored when comparing responses. |
| `workflow` | no | A scripted session lifecycle (login → … → logout → retry). |
| `observations` | no | Paths used for the security-configuration check. |

## targets[]

| Key | Meaning |
|-----|---------|
| `id` | Stable id (`[a-z0-9-]`). |
| `label` | Display label. |
| `origin` | `scheme://host[:port]` only — no path/query/credentials. Must be loopback, or the host must be listed in `BL_ALLOWED_HOSTS`. |
| `configuration` | Free label, e.g. `vulnerable` / `fixed`. |
| `local_demo` | `true` enables local replay for findings on this target. |
| `health_path` | Path probed before scanning to detect an unreachable target. |

## limits

`max_requests` (budget), `concurrency`, `timeout_seconds`, `max_response_bytes`,
`max_redirects`. The scanner never exceeds these; exceeding the budget fails the scan.

## authentication

```yaml
login:  {method: POST, path: /api/auth/login, username_field: username, password_field: password}
logout: {method: POST, path: /api/auth/logout}
session_cookie: ledgerly_session   # cookie that must appear after login
verify_path: /api/me               # used to confirm a session and read headers
login_page_paths: [/login]
login_page_markers: ['type="password"']  # strings that mark an HTML login page
```

## identities[]

```yaml
- {id: anonymous, role: anonymous}
- {id: alice, role: user, username: alice, password_env: BL_ALICE_PASSWORD}
```

Passwords are **never** stored in the manifest; only the name of the environment variable that
holds them (`password_env`). The scanner resolves them server-side.

## resources[]

```yaml
- {id: alice-invoice-1, owner: alice, value: inv_a7Kq2LmZ9x,
   markers: [BLM-ALICE-INV-7F3A, BLM-ALICE-ATT-7F3A]}
- {id: admin-summary, owner_role: admin, markers: [BLM-ADMIN-SUMMARY-91C2]}
```

`markers` are unique strings seeded into the resource's private fields. Their presence in a
response is the positive evidence that confirms a denied identity actually received the private
data. `value` is substituted into a route's `{resource}` placeholder.

## routes[]

```yaml
- id: invoice-detail
  method: GET
  path: /api/invoices/{resource}
  resources: [alice-invoice-1, bob-invoice-1]
  allow: [owner, "role:admin"]          # access rule (the oracle)
  owner_field: data.invoice.owner       # dotted path to the ownership field in the JSON
  compare_fields: [data.invoice.id, data.invoice.owner]
  safe: true                            # false => never executed by checks
```

**Allow tokens:** `public`, `authenticated`, `owner`, `role:<name>`. A request is *expected to be
allowed* when any token matches the identity/resource. Everything else is expected to be denied.

Only routes with `safe: true` **and** a read method (`GET`/`HEAD`) are ever executed. A route
such as `admin-disable-user` is declared `safe: false` so the scanner documents it but never
calls it (no destructive admin operations).

## workflow

```yaml
workflow:
  id: session-lifecycle
  identity: alice
  steps:
    - {id: login,  action: login}
    - {id: fetch,  action: request, route: invoice-detail, resource: alice-invoice-1}
    - {id: logout, action: logout}
    - {id: retry,  action: request, route: invoice-detail, resource: alice-invoice-1, after_logout: true}
```

The workflow runs with a **dedicated throwaway session** so it never invalidates the other test
sessions. The `retry` step replays the captured token after logout to test server-side session
invalidation.
