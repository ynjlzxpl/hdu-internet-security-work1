from app.extensions import db
from app.models import Note, User


def _user_id(username):
    return db.session.execute(
        db.select(User).where(User.username == username)
    ).scalar_one().id


def test_list_data_returns_only_own_notes(client, auth_headers):
    response = client.get("/api/data", headers=auth_headers)

    assert response.status_code == 200
    body = response.get_json()
    titles = [note["title"] for note in body["notes"]]
    assert "Alice note" in titles
    assert "Bob note" not in titles
    assert "Bob private data" not in response.get_data(as_text=True)


def test_get_note_by_id_checks_ownership(client, auth_headers):
    bob_note = db.session.execute(
        db.select(Note).where(Note.title == "Bob note")
    ).scalar_one()

    response = client.get(f"/api/data/{bob_note.id}", headers=auth_headers)
    assert response.status_code == 404


def test_get_own_note(client, auth_headers):
    note = db.session.execute(
        db.select(Note).where(Note.title == "Alice note")
    ).scalar_one()

    response = client.get(f"/api/data/{note.id}", headers=auth_headers)
    assert response.status_code == 200
    assert response.get_json()["note"]["title"] == "Alice note"


def test_create_note_and_read_it_back(client, auth_headers):
    response = client.post(
        "/api/data",
        headers=auth_headers,
        json={"title": "New note", "content": "Fresh content"},
    )

    assert response.status_code == 201
    created = response.get_json()["note"]
    assert created["title"] == "New note"

    listing = client.get("/api/data", headers=auth_headers).get_json()
    assert any(note["id"] == created["id"] for note in listing["notes"])


def test_create_note_validation(client, auth_headers):
    cases = [
        {"title": "", "content": "x"},
        {"title": "   ", "content": "x"},
        {"title": "x" * 121, "content": "x"},
        {"title": "ok", "content": ""},
        {"title": "ok", "content": "x" * 5001},
        {"title": 123, "content": "x"},
        {"title": "ok", "content": ["not", "a", "string"]},
        {"title": "ok"},
    ]
    for payload in cases:
        response = client.post("/api/data", headers=auth_headers, json=payload)
        assert response.status_code == 400, payload


def test_create_note_requires_json_object(client, auth_headers):
    response = client.post(
        "/api/data", headers=auth_headers, data="title=x", content_type="text/plain"
    )
    assert response.status_code == 400


def test_search_only_returns_own_notes(client, auth_headers):
    client.post(
        "/api/data",
        headers=auth_headers,
        json={"title": "Needle", "content": "A searchable note"},
    )

    response = client.get("/api/data?search=Needle", headers=auth_headers)
    notes = response.get_json()["notes"]
    assert len(notes) == 1
    assert notes[0]["title"] == "Needle"


def test_sql_injection_in_search_does_not_bypass_owner_filter(
    client, auth_headers
):
    # If the search value were concatenated into SQL, this payload would
    # either break the query or return every row. With bound parameters it is
    # simply a literal string that matches nothing.
    payload = "%' OR 1=1 --"
    response = client.get(
        "/api/data", headers=auth_headers, query_string={"search": payload}
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["count"] == 0
    assert "Bob private data" not in response.get_data(as_text=True)


def test_wildcard_search_cannot_escape_owner_filter(client, auth_headers):
    response = client.get(
        "/api/data", headers=auth_headers, query_string={"search": "%"}
    )
    body = response.get_json()
    assert body["count"] >= 1
    assert all("Bob" not in note["content"] for note in body["notes"])


def test_xss_payload_is_escaped_in_responses(client, auth_headers):
    payload_title = "<script>alert('xss')</script>"
    payload_content = '" onmouseover="alert(1)" <img src=x onerror=alert(1)>'

    created = client.post(
        "/api/data",
        headers=auth_headers,
        json={"title": payload_title, "content": payload_content},
    )

    assert created.status_code == 201
    raw = created.get_data(as_text=True)
    assert "<script>" not in raw
    assert "<img" not in raw
    assert "&lt;script&gt;" in raw
    assert "onerror" in raw  # text is preserved, but its markup is inert

    note = created.get_json()["note"]
    assert note["title"].startswith("&lt;script&gt;")

    listing_raw = client.get("/api/data", headers=auth_headers).get_data(
        as_text=True
    )
    assert "<script>" not in listing_raw
    assert "&lt;script&gt;" in listing_raw


def test_users_me_returns_authenticated_profile(client, auth_headers):
    response = client.get("/api/users/me", headers=auth_headers)
    assert response.status_code == 200
    assert response.get_json()["user"]["username"] == "alice"


def test_health_is_public(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_security_headers_are_present(client):
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]


def test_oversized_request_body_is_rejected(client, auth_headers):
    response = client.post(
        "/api/data",
        headers=auth_headers,
        json={"title": "big", "content": "A" * 20000},
    )
    assert response.status_code == 413
    assert response.is_json


def test_unknown_route_returns_json_404(client):
    response = client.get("/api/does-not-exist")
    assert response.status_code == 404
    assert response.is_json


def test_method_not_allowed_returns_json_405(client):
    response = client.post("/health")
    assert response.status_code == 405
    assert response.is_json


def test_user_ids_are_isolated_between_tokens(client, bob_auth_headers):
    """A second user's token must not see the first user's notes."""
    response = client.get("/api/data", headers=bob_auth_headers)
    assert response.status_code == 200
    body = response.get_json()
    assert body["count"] == 1
    assert body["notes"][0]["title"] == "Bob note"
