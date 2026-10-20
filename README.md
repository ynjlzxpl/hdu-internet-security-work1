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
Bandit:   No issues identified.  (0 medium, 0 high; 501 lines scanned)
pip-audit: No known vulnerabilities found (12 dependencies audited)
```

Pipeline run and artifacts:
[Actions → CI](https://github.com/ynjlzxpl/hdu-internet-security-work1/actions/workflows/ci.yml)

<!-- CI screenshots will be added after the first successful run. -->

## 8. CVE analysis with Vulhub

> Status: to be completed in the next stage of the laboratory work.
> The selected environment, reproduction steps, root-cause analysis, fix, and
> regression evidence will be added here once the vulnerable service has been
> run and verified.

Planned content (required by the assignment):

1. Selected CVE (ID + description) and why it was chosen.
2. Reproduction sequence with commands/HTTP requests and screenshots.
3. Root-cause analysis in our own words.
4. Applied fix (Dockerfile / docker-compose.yml / source) and why it works.
5. Proof that the exploit no longer works, plus regression testing.
6. The fixed configuration files, attached under `vulhub-fix/`.

## 9. Repository

* Public repository: <https://github.com/ynjlzxpl/hdu-internet-security-work1>
* Last successful pipeline: see the Actions tab link above.
