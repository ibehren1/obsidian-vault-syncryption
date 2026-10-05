"""FastAPI application factory and process-wide routes."""

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from syncryption_server import __version__, auth, blobs, devices, locks, sync, vaults
from syncryption_server.config import Settings, load_settings
from syncryption_server.db import Database
from syncryption_server.errors import install_error_handlers, too_large
from syncryption_server.state import AppState
from syncryption_server.storage import BlobStore, LocalBlobStore, S3BlobStore

VERSION_HEADER = "X-Syncryption-Version"
GC_INTERVAL = 3600
# Request bodies other than blob uploads: the largest is a keyring upload (1 MiB, base64).
MAX_BODY_SIZE = 2 * 1024 * 1024

log = logging.getLogger(__name__)


class BodyLimit:
    """Reject request bodies over `limit` bytes with 413 before they are read whole. Blob
    uploads are left to their route, which streams them against the blob size."""

    def __init__(self, app: ASGIApp, limit: int):
        self.app = app
        self.limit = limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or (scope["method"] == "PUT" and "/blobs/" in scope["path"]):
            await self.app(scope, receive, send)
            return
        length = dict(scope["headers"]).get(b"content-length", b"")
        if length.isdigit() and int(length) > self.limit:
            await self._reject(scope, receive, send)
            return
        # Without a usable length (chunked uploads), read up to the limit, then replay.
        messages: list[Message] = []
        size = 0
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] != "http.request":
                break
            size += len(message.get("body", b""))
            if size > self.limit:
                await self._reject(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        async def replay() -> Message:
            return messages.pop(0) if messages else await receive()

        await self.app(scope, replay, send)

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        err = too_large("The request body is too large.")
        body = {"error": err.error, "message": err.message, "details": err.details}
        await JSONResponse(body, status_code=err.status)(scope, receive, send)


def make_blob_store(settings: Settings) -> BlobStore:
    if settings.s3 is not None:
        return S3BlobStore(settings.s3)
    return LocalBlobStore(settings.data_dir)


async def _gc_loop(state: AppState) -> None:
    while True:
        await asyncio.sleep(GC_INTERVAL)
        try:
            deleted = await blobs.collect_garbage(state)
            if deleted:
                log.info("garbage collection deleted %d unreferenced blobs", deleted)
        except Exception:
            log.exception("blob garbage collection failed")


def create_app(
    settings: Settings | None = None,
    store: BlobStore | None = None,
    clock: Callable[[], float] | None = None,
) -> FastAPI:
    """Build the app. With no arguments, settings come from the environment."""
    settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        db = Database(settings.db_path)
        db.migrate()
        blob_store = store or make_blob_store(settings)
        await blob_store.start()
        state = AppState(settings=settings, db=db, store=blob_store)
        if clock is not None:
            state.clock = clock
        app.state.ctx = state
        gc = asyncio.create_task(_gc_loop(state))
        try:
            yield
        finally:
            gc.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await gc
            await blob_store.close()
            db.close()

    app = FastAPI(title="Vault Syncryption", version=__version__, lifespan=lifespan)
    install_error_handlers(app)
    app.add_middleware(BodyLimit, limit=MAX_BODY_SIZE)

    @app.middleware("http")
    async def add_version_header(request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers[VERSION_HEADER] = __version__
        return response

    @app.get("/health")
    async def health(request: Request) -> JSONResponse:
        state: AppState = request.app.state.ctx
        try:
            state.db.ping()
            await state.store.ping()
        except Exception:
            log.exception("health check failed")
            return JSONResponse({"status": "unavailable", "version": __version__}, status_code=503)
        return JSONResponse({"status": "ok", "version": __version__})

    for module in (auth, devices, vaults, blobs, sync, locks):
        app.include_router(module.router)
    return app
