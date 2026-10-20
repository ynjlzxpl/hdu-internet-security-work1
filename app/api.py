"""Protected data endpoints."""
from flask import Blueprint, g, jsonify, request
from sqlalchemy import or_, select

from .extensions import db
from .models import Note
from .security import jwt_required, sanitize

bp = Blueprint("api", __name__, url_prefix="/api")

MAX_TITLE_LENGTH = 120
MAX_CONTENT_LENGTH = 5000
MAX_SEARCH_LENGTH = 100


def _error(code: str, message: str, status: int):
    return jsonify({"error": code, "message": message}), status


def _note_json(note: Note) -> dict:
    """Serialise a note, escaping every user-controlled string.

    Escaping happens on output (not on input), so the stored data remains
    intact and the response is safe for clients that embed it in HTML.
    """
    return {
        "id": note.id,
        "title": sanitize(note.title),
        "content": sanitize(note.content),
        "created_at": note.created_at.isoformat() if note.created_at else None,
    }


@bp.get("/data")
@jwt_required
def list_data():
    """Return notes owned by the authenticated user.

    The owner filter is mandatory: an authenticated user can never read
    another user's notes, which prevents horizontal privilege escalation.
    """
    search = request.args.get("search", "", type=str)[:MAX_SEARCH_LENGTH]

    stmt = select(Note).where(Note.owner_id == g.current_user.id)
    if search:
        # The value is bound as a query parameter by SQLAlchemy; it is never
        # concatenated into the SQL text.
        pattern = f"%{search}%"
        stmt = stmt.where(
            or_(Note.title.ilike(pattern), Note.content.ilike(pattern))
        )

    notes = db.session.execute(stmt.order_by(Note.id.desc())).scalars().all()
    return jsonify({"count": len(notes), "notes": [_note_json(n) for n in notes]})


@bp.get("/data/<int:note_id>")
@jwt_required
def get_note(note_id: int):
    """Return one note owned by the authenticated user.

    A note that exists but belongs to someone else is reported as 404 so the
    endpoint does not leak the existence of other users' records.
    """
    note = db.session.execute(
        select(Note).where(
            Note.id == note_id, Note.owner_id == g.current_user.id
        )
    ).scalar_one_or_none()
    if note is None:
        return _error("not_found", "Note not found.", 404)
    return jsonify({"note": _note_json(note)})


@bp.post("/data")
@jwt_required
def create_note():
    """Create a note for the authenticated user."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _error(
            "invalid_request", "Request body must be a JSON object.", 400
        )

    title = data.get("title")
    content = data.get("content")
    if not isinstance(title, str) or not isinstance(content, str):
        return _error(
            "invalid_request",
            "Both 'title' and 'content' must be strings.",
            400,
        )

    title = title.strip()
    if not 1 <= len(title) <= MAX_TITLE_LENGTH:
        return _error(
            "invalid_request",
            f"'title' must contain between 1 and {MAX_TITLE_LENGTH} characters.",
            400,
        )
    if not 1 <= len(content) <= MAX_CONTENT_LENGTH:
        return _error(
            "invalid_request",
            f"'content' must contain between 1 and {MAX_CONTENT_LENGTH} characters.",
            400,
        )

    note = Note(title=title, content=content, owner_id=g.current_user.id)
    db.session.add(note)
    db.session.commit()
    return jsonify({"note": _note_json(note)}), 201


@bp.get("/users/me")
@jwt_required
def get_me():
    """Return the profile of the authenticated user."""
    user = g.current_user
    return jsonify(
        {
            "user": {
                "id": user.id,
                "username": sanitize(user.username),
                "created_at": (
                    user.created_at.isoformat() if user.created_at else None
                ),
            }
        }
    )
