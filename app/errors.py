"""Consistent JSON error responses (no HTML error pages, no stack traces)."""
from flask import jsonify
from werkzeug.exceptions import HTTPException


def register_error_handlers(app):
    @app.errorhandler(HTTPException)
    def handle_http_exception(error):
        response = jsonify(
            {
                "error": error.name.lower().replace(" ", "_"),
                "message": error.description,
            }
        )
        response.status_code = error.code
        return response

    @app.errorhandler(Exception)
    def handle_unexpected_exception(error):
        # Log the full exception server-side; never return details to clients.
        app.logger.exception("Unhandled exception: %s", type(error).__name__)
        return (
            jsonify(
                {
                    "error": "internal_server_error",
                    "message": "An internal server error occurred.",
                }
            ),
            500,
        )
