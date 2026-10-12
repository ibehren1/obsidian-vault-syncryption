"""The OpenAPI schema, which the plugin's API types and `docs/api.md` are generated from.

FastAPI's default for a request that fails validation is `422 HTTPValidationError`, but
this app answers `400 bad_request` with the error envelope (`errors.py`, docs/protocol.md
section 1). `install_openapi` corrects that, so both generated artefacts describe what the
server really returns.
"""

from typing import Any

from fastapi import FastAPI

ERROR_SCHEMA: dict[str, Any] = {
    "title": "Error",
    "type": "object",
    "description": (
        "Every error response. `error` is a stable machine code, and `message` never "
        "contains plaintext, keys or tokens. The codes are listed in protocol.md 1."
    ),
    "properties": {
        "error": {"type": "string", "title": "Error"},
        "message": {"type": "string", "title": "Message"},
        "details": {"type": "object", "title": "Details"},
    },
    "required": ["error", "message", "details"],
}

BAD_REQUEST: dict[str, Any] = {
    "description": "A body or parameter that fails validation: `bad_request`.",
    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
}


def patch(schema: dict[str, Any]) -> dict[str, Any]:
    """Replace FastAPI's validation response with the one the app sends. Idempotent, since
    FastAPI hands out the same cached schema object every time."""
    for operations in schema.get("paths", {}).values():
        for operation in operations.values():
            responses = operation.get("responses", {})
            if responses.pop("422", None) is not None:
                responses["400"] = dict(BAD_REQUEST)
    schemas = schema.setdefault("components", {}).setdefault("schemas", {})
    schemas.pop("HTTPValidationError", None)
    schemas.pop("ValidationError", None)
    schemas["Error"] = ERROR_SCHEMA
    return schema


def install_openapi(app: FastAPI) -> None:
    build = app.openapi

    def openapi() -> dict[str, Any]:
        return patch(build())

    app.openapi = openapi  # type: ignore[method-assign]
