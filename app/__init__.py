"""Secure Notes API - application factory."""
import os
import secrets

from flask import Flask, jsonify

from .extensions import db


def create_app(test_config=None):
    """Create and configure the Flask application.

    Configuration is read from environment variables so that no secret is
    hard-coded in the repository. ``test_config`` lets the test-suite override
    values (in-memory database, deterministic JWT secret, ...).
    """
    app = Flask(__name__, instance_relative_config=True)

    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///app.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        JWT_SECRET=os.environ.get("JWT_SECRET"),
        JWT_ALGORITHM="HS256",
        JWT_ISSUER="secure-notes-api",
        JWT_EXPIRES_SECONDS=int(os.environ.get("JWT_EXPIRES_SECONDS", "3600")),
        MAX_CONTENT_LENGTH=16 * 1024,  # reject request bodies larger than 16 KiB
        APP_ENV=os.environ.get("APP_ENV", "development"),
    )

    if test_config:
        app.config.update(test_config)

    if not app.config["JWT_SECRET"]:
        if app.config["APP_ENV"] == "production":
            raise RuntimeError(
                "JWT_SECRET must be configured when APP_ENV=production"
            )
        # Development convenience: an ephemeral secret protects nothing across
        # restarts but avoids shipping a hard-coded secret in the repository.
        app.config["JWT_SECRET"] = secrets.token_hex(32)
        app.logger.warning(
            "JWT_SECRET is not set; generated an ephemeral development secret. "
            "Set JWT_SECRET before running more than one worker."
        )

    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)

    from .api import bp as api_bp
    from .auth import bp as auth_bp
    from .cli import register_cli
    from .errors import register_error_handlers
    from .security import register_security_headers

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    register_cli(app)
    register_error_handlers(app)
    register_security_headers(app)

    @app.get("/health")
    def health():
        """Unauthenticated liveness probe."""
        return jsonify({"status": "ok"})

    # Educational project: create tables on startup. A production deployment
    # should use migrations (Flask-Migrate/Alembic) instead.
    with app.app_context():
        db.create_all()

    return app
