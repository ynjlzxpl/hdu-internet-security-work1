import pytest
from sqlalchemy.pool import StaticPool

from app import create_app
from app.extensions import db
from app.models import Note, User
from app.security import hash_password, login_limiter

TEST_JWT_SECRET = "test-only-jwt-secret-never-used-in-production"
ALICE_PASSWORD = "AlicePass123!"
BOB_PASSWORD = "BobPass123!"


@pytest.fixture()
def app():
    application = create_app(
        {
            "TESTING": True,
            "APP_ENV": "testing",
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "SQLALCHEMY_ENGINE_OPTIONS": {
                "connect_args": {"check_same_thread": False},
                "poolclass": StaticPool,
            },
            "JWT_SECRET": TEST_JWT_SECRET,
            "JWT_EXPIRES_SECONDS": 3600,
        }
    )

    with application.app_context():
        alice = User(
            username="alice", password_hash=hash_password(ALICE_PASSWORD)
        )
        bob = User(username="bob", password_hash=hash_password(BOB_PASSWORD))
        db.session.add_all([alice, bob])
        db.session.commit()

        db.session.add_all(
            [
                Note(
                    title="Alice note",
                    content="Alice private data",
                    owner_id=alice.id,
                ),
                Note(
                    title="Bob note",
                    content="Bob private data",
                    owner_id=bob.id,
                ),
            ]
        )
        db.session.commit()

        yield application

        db.session.remove()
        db.drop_all()
        db.engine.dispose()


@pytest.fixture(autouse=True)
def _reset_login_limiter():
    login_limiter.reset_all()
    yield
    login_limiter.reset_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def auth_headers(client):
    response = client.post(
        "/auth/login",
        json={"username": "alice", "password": ALICE_PASSWORD},
    )
    assert response.status_code == 200
    token = response.get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def bob_auth_headers(client):
    response = client.post(
        "/auth/login",
        json={"username": "bob", "password": BOB_PASSWORD},
    )
    assert response.status_code == 200
    token = response.get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
