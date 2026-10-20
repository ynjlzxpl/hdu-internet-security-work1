"""Command-line helpers."""
import os
import secrets

import click
from flask.cli import with_appcontext

from .extensions import db
from .models import Note, User
from .security import hash_password


def register_cli(app):
    @app.cli.command("seed-demo")
    @with_appcontext
    def seed_demo():
        """Create two demo users and some notes (idempotent)."""
        password = os.environ.get("DEMO_PASSWORD")
        generated = password is None
        if generated:
            password = secrets.token_urlsafe(12)

        if len(password.encode("utf-8")) > 72:
            raise click.ClickException(
                "DEMO_PASSWORD must be at most 72 bytes (bcrypt limit)."
            )

        created = False
        users = {}
        for username in ("alice", "bob"):
            existing = db.session.execute(
                db.select(User).where(User.username == username)
            ).scalar_one_or_none()
            if existing is not None:
                users[username] = existing
                continue
            user = User(
                username=username, password_hash=hash_password(password)
            )
            db.session.add(user)
            users[username] = user
            created = True

        db.session.flush()

        alice_notes = db.session.execute(
            db.select(Note).where(Note.owner_id == users["alice"].id)
        ).scalars().first()
        if alice_notes is None:
            db.session.add_all(
                [
                    Note(
                        title="Welcome to Secure Notes",
                        content="This note belongs to alice.",
                        owner_id=users["alice"].id,
                    ),
                    Note(
                        title="Shopping list",
                        content="Coffee, tea, and a secure API.",
                        owner_id=users["alice"].id,
                    ),
                ]
            )
            db.session.add(
                Note(
                    title="Bob's private note",
                    content="This note must never be visible to alice.",
                    owner_id=users["bob"].id,
                )
            )
            created = True

        db.session.commit()

        if not created:
            click.echo("Demo data already exists; nothing to do.")
            return

        click.echo("Demo users created: alice, bob")
        if generated:
            click.echo(f"Generated demo password: {password}")
        else:
            click.echo("Demo password taken from DEMO_PASSWORD.")
