"""Error responses: `{"error", "message", "details"}` (docs/protocol.md 1)."""

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


class ApiError(Exception):
    def __init__(
        self,
        status: int,
        error: str,
        message: str,
        details: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.error = error
        self.message = message
        self.details = details or {}
        self.headers = headers


def bad_request(message: str) -> ApiError:
    return ApiError(400, "bad_request", message)


def forbidden(message: str = "You don't have access to this vault.") -> ApiError:
    return ApiError(403, "forbidden", message)


def _contact(admin_contact: str) -> dict[str, Any]:
    return {"adminContact": admin_contact} if admin_contact else {}


def user_disabled(admin_contact: str = "") -> ApiError:
    message = "This account was disabled by the server administrator."
    return ApiError(403, "user_disabled", message, _contact(admin_contact))


def vault_disabled(admin_contact: str = "") -> ApiError:
    message = "This vault was disabled by the server administrator."
    return ApiError(403, "vault_disabled", message, _contact(admin_contact))


MAINTENANCE_RETRY = 60


def maintenance(admin_contact: str, note: str | None, since: str) -> ApiError:
    """Every `/api/v1` request while the admin has maintenance on (protocol.md 14.1)."""
    return ApiError(
        503,
        "maintenance",
        "The server is in maintenance, so sync is paused. "
        "It resumes by itself when maintenance ends.",
        {"adminContact": admin_contact or None, "note": note, "since": since},
        headers={"Retry-After": str(MAINTENANCE_RETRY)},
    )


def not_found(message: str = "Not found.") -> ApiError:
    return ApiError(404, "not_found", message)


def too_large(message: str) -> ApiError:
    return ApiError(413, "too_large", message)


def error_response(err: ApiError) -> JSONResponse:
    body = {"error": err.error, "message": err.message, "details": err.details}
    return JSONResponse(body, status_code=err.status, headers=err.headers)


_HTTP_CODES = {401: "unauthenticated", 403: "forbidden", 404: "not_found", 413: "too_large"}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def api_error(_: Request, exc: ApiError) -> JSONResponse:
        return error_response(exc)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Only locations and messages: the input may contain the shared secret.
        fields = [
            {"loc": [str(p) for p in e.get("loc", ())], "msg": e.get("msg", "")}
            for e in exc.errors()
        ]
        return error_response(ApiError(400, "bad_request", "Invalid request.", {"fields": fields}))

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _HTTP_CODES.get(exc.status_code, "bad_request")
        message = exc.detail if isinstance(exc.detail, str) else "Request failed."
        return error_response(ApiError(exc.status_code, code, message, headers=exc.headers))
