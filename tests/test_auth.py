from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.extensions import db
from app.models import User


def _login(client, username="alice", password="AlicePass123!"):
    return client.post(
        "/auth/login", json={"username": username, "password": password}
    )


def test_login_returns_valid_jwt(client, app):
    response = _login(client)

    assert response.status_code == 200
    body = response.get_json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 3600

    payload = jwt.decode(
        body["access_token"],
        app.config["JWT_SECRET"],
        algorithms=["HS256"],
        issuer=app.config["JWT_ISSUER"],
    )
    user = db.session.execute(
        db.select(User).where(User.username == "alice")
    ).scalar_one()
    assert payload["sub"] == str(user.id)
    assert payload["exp"] > payload["iat"]


def test_login_sets_no_store_header(client):
    response = _login(client)
    assert response.headers["Cache-Control"] == "no-store"


def test_login_wrong_password_is_rejected(client):
    response = _login(client, password="WrongPass123!")
    assert response.status_code == 401
    assert response.get_json()["error"] == "invalid_credentials"
    assert "access_token" not in response.get_json()


def test_login_unknown_user_has_same_message_as_wrong_password(client):
    unknown = _login(client, username="nobody")
    wrong = _login(client, password="WrongPass123!")

    assert unknown.status_code == wrong.status_code == 401
    assert unknown.get_json()["message"] == wrong.get_json()["message"]


def test_login_rejects_malformed_requests(client):
    assert client.post("/auth/login", data="not-json").status_code == 400
    assert client.post("/auth/login", json=[]).status_code == 400
    assert client.post("/auth/login", json={"username": "alice"}).status_code == 400
    assert (
        client.post(
            "/auth/login", json={"username": "alice", "password": 123}
        ).status_code
        == 400
    )
    assert _login(client, username="a").status_code == 400
    assert _login(client, password="short").status_code == 400


def test_protected_endpoints_reject_missing_token(client):
    for path in ("/api/data", "/api/data/1", "/api/users/me"):
        response = client.get(path)
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"].startswith("Bearer")


def test_protected_endpoint_rejects_non_bearer_scheme(client):
    response = client.get(
        "/api/data", headers={"Authorization": "Basic YWxpY2U6cGFzcw=="}
    )
    assert response.status_code == 401


def test_tampered_signature_is_rejected(client):
    token = _login(client).get_json()["access_token"]
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")

    response = client.get(
        "/api/data", headers={"Authorization": f"Bearer {tampered}"}
    )
    assert response.status_code == 401


def test_expired_token_is_rejected(client, app):
    user = db.session.execute(
        db.select(User).where(User.username == "alice")
    ).scalar_one()
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": str(user.id),
            "iss": app.config["JWT_ISSUER"],
            "iat": now - timedelta(minutes=10),
            "exp": now - timedelta(minutes=5),
        },
        app.config["JWT_SECRET"],
        algorithm="HS256",
    )

    response = client.get(
        "/api/data", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401
    assert "expired" in response.get_json()["message"].lower()


def test_alg_none_token_is_rejected(client):
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": "1",
            "iss": "secure-notes-api",
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        key="",
        algorithm="none",
    )

    response = client.get(
        "/api/data", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401


def test_token_for_deleted_user_is_rejected(client, app):
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": "999999",
            "iss": app.config["JWT_ISSUER"],
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        app.config["JWT_SECRET"],
        algorithm="HS256",
    )

    response = client.get(
        "/api/data", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401


def test_password_is_stored_as_bcrypt_hash(app):
    user = db.session.execute(
        db.select(User).where(User.username == "alice")
    ).scalar_one()

    assert user.password_hash != "AlicePass123!"
    assert user.password_hash.startswith(("$2a$", "$2b$", "$2y$"))
    assert bcrypt.checkpw(
        b"AlicePass123!", user.password_hash.encode("ascii")
    )


def test_login_is_rate_limited_after_repeated_failures(client):
    for _ in range(5):
        response = _login(client, password="WrongPass123!")
        assert response.status_code == 401

    blocked = _login(client, password="AlicePass123!")
    assert blocked.status_code == 429
    assert blocked.headers["Retry-After"] == "60"


def test_sql_injection_login_payload_cannot_authenticate(client):
    for username in (
        "alice' OR '1'='1",
        "alice'--",
        "admin' OR 1=1 --",
        "' OR '1'='1' --",
    ):
        response = _login(client, username=username, password="Whatever123!")
        assert response.status_code in (400, 401)
        assert "access_token" not in response.get_json()
