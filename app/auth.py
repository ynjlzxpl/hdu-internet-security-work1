"""Authentication endpoints."""
import re

from flask import Blueprint, current_app, jsonify, request

from .extensions import db
from .models import User
from .security import DUMMY_HASH, issue_token, login_limiter, verify_password

bp = Blueprint("auth", __name__, url_prefix="/auth")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_BYTES = 72  # bcrypt's input limit


def _error(code: str, message: str, status: int):
    return jsonify({"error": code, "message": message}), status


@bp.post("/login")
def login():
    """Authenticate a user and return a JWT access token."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _error(
            "invalid_request", "Request body must be a JSON object.", 400
        )

    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return _error(
            "invalid_request",
            "Both 'username' and 'password' must be strings.",
            400,
        )

    username = username.strip()
    if (
        not USERNAME_RE.fullmatch(username)
        or not MIN_PASSWORD_LENGTH <= len(password)
        or len(password.encode("utf-8")) > MAX_PASSWORD_BYTES
    ):
        return _error(
            "invalid_request", "Username or password has an invalid format.", 400
        )

    limiter_key = f"{request.remote_addr or 'unknown'}|{username}"
    if login_limiter.is_blocked(limiter_key):
        response = jsonify(
            {
                "error": "too_many_attempts",
                "message": "Too many failed login attempts. Try again later.",
            }
        )
        response.status_code = 429
        response.headers["Retry-After"] = str(login_limiter.window_seconds)
        return response

    user = db.session.execute(
        db.select(User).where(User.username == username)
    ).scalar_one_or_none()

    if user is None:
        # Burn approximately the same time as a real bcrypt check so the
        # response does not disclose whether the account exists.
        verify_password(password, DUMMY_HASH)
        login_limiter.register_failure(limiter_key)
        return _error(
            "invalid_credentials", "Invalid username or password.", 401
        )

    if not verify_password(password, user.password_hash):
        login_limiter.register_failure(limiter_key)
        return _error(
            "invalid_credentials", "Invalid username or password.", 401
        )

    login_limiter.reset(limiter_key)
    token = issue_token(user.id)
    return jsonify(
        {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": current_app.config["JWT_EXPIRES_SECONDS"],
        }
    )
