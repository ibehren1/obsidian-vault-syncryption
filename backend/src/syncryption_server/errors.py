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


def not_found(message: str = "Not found.") -> ApiError:
    return ApiError(404, "not_found", message)


def too_large(message: str) -> ApiError:
    return ApiError(413, "too_large", message)


def _response(err: ApiError) -> JSONResponse:
    body = {"error": err.error, "message": err.message, "details": err.details}
    return JSONResponse(body, status_code=err.status, headers=err.headers)


_HTTP_CODES = {401: "unauthenticated", 403: "forbidden", 404: "not_found", 413: "too_large"}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def api_error(_: Request, exc: ApiError) -> JSONResponse:
        return _response(exc)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Only locations and messages: the input may contain the shared secret.
        fields = [
            {"loc": [str(p) for p in e.get("loc", ())], "msg": e.get("msg", "")}
            for e in exc.errors()
        ]
        return _response(ApiError(400, "bad_request", "Invalid request.", {"fields": fields}))

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _HTTP_CODES.get(exc.status_code, "bad_request")
        message = exc.detail if isinstance(exc.detail, str) else "Request failed."
        return _response(ApiError(exc.status_code, code, message, headers=exc.headers))
