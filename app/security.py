"""Password hashing, JWT handling, output escaping and login throttling."""
import secrets
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import current_app, g, jsonify, request
from markupsafe import escape

from .extensions import db
from .models import User

BCRYPT_ROUNDS = 12
AUTH_SCHEME = "Bearer"

# A valid bcrypt hash used to equalise response time when the username does
# not exist, so login timing does not reveal whether an account is registered.
DUMMY_HASH = bcrypt.hashpw(
    secrets.token_urlsafe(16).encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
).decode("ascii")


def hash_password(password: str) -> str:
    """Return a bcrypt hash (with per-password salt) for ``password``."""
    raw = password.encode("utf-8")
    if len(raw) > 72:
        raise ValueError("Password must be at most 72 bytes")
    return bcrypt.hashpw(raw, bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time bcrypt comparison; malformed input never raises."""
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"), password_hash.encode("ascii")
        )
    except (ValueError, TypeError):
        return False


def issue_token(user_id: int) -> str:
    """Sign a short-lived JWT access token for ``user_id``."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iss": current_app.config["JWT_ISSUER"],
        "iat": now,
        "exp": now + timedelta(seconds=current_app.config["JWT_EXPIRES_SECONDS"]),
    }
    return jwt.encode(
        payload,
        current_app.config["JWT_SECRET"],
        algorithm=current_app.config["JWT_ALGORITHM"],
    )


def decode_token(token: str) -> dict:
    """Verify signature, issuer, algorithm and required claims of a JWT.

    The algorithm allow-list is explicit, which rejects ``alg=none`` and
    algorithm-confusion tokens.
    """
    return jwt.decode(
        token,
        current_app.config["JWT_SECRET"],
        algorithms=[current_app.config["JWT_ALGORITHM"]],
        issuer=current_app.config["JWT_ISSUER"],
        options={"require": ["sub", "iss", "iat", "exp"]},
    )


def _unauthorized(message: str):
    response = jsonify({"error": "unauthorized", "message": message})
    response.status_code = 401
    response.headers["WWW-Authenticate"] = 'Bearer realm="api"'
    return response


def jwt_required(view):
    """Decorator implementing authentication middleware for protected routes."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return _unauthorized("A Bearer token is required.")

        try:
            payload = decode_token(token.strip())
        except jwt.ExpiredSignatureError:
            return _unauthorized("The access token has expired.")
        except jwt.InvalidTokenError:
            return _unauthorized("The access token is invalid.")

        try:
            user_id = int(payload["sub"])
        except (TypeError, ValueError):
            return _unauthorized("The access token is invalid.")

        user = db.session.get(User, user_id)
        if user is None:
            return _unauthorized("The access token is invalid.")

        g.current_user = user
        return view(*args, **kwargs)

    return wrapped


def sanitize(value: str) -> str:
    """Escape HTML-significant characters before including data in a response.

    Output escaping keeps stored notes intact while ensuring that any client
    which renders the value as HTML cannot execute injected markup.
    """
    return str(escape(value))


class LoginRateLimiter:
    """Small in-memory brute-force guard (best effort, per process).

    A real deployment would use a shared store such as Redis so the limit is
    enforced consistently across workers.
    """

    def __init__(self, max_failures: int = 5, window_seconds: int = 60):
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self._failures = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float):
        entries = self._failures.get(key)
        if entries is None:
            return None
        while entries and now - entries[0] > self.window_seconds:
            entries.popleft()
        if not entries:
            self._failures.pop(key, None)
            return None
        return entries

    def is_blocked(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            entries = self._prune(key, now)
            return entries is not None and len(entries) >= self.max_failures

    def register_failure(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            entries = self._prune(key, now)
            if entries is None:
                entries = deque()
                self._failures[key] = entries
            entries.append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)

    def reset_all(self) -> None:
        with self._lock:
            self._failures.clear()


login_limiter = LoginRateLimiter()


def register_security_headers(app):
    @app.after_request
    def _set_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
        )
        if request.path.startswith("/auth/"):
            response.headers["Cache-Control"] = "no-store"
        return response
