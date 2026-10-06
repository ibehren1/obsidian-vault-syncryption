"""FastAPI application factory and process-wide routes."""

import asyncio
import contextlib
import html
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from syncryption_server import (
    PROTOCOL_VERSION,
    __version__,
    admin,
    auth,
    blobs,
    devices,
    locks,
    sync,
    vaults,
)
from syncryption_server.config import Settings, load_settings
from syncryption_server.db import Database, OldDataError
from syncryption_server.encoding import rfc3339
from syncryption_server.errors import error_response, install_error_handlers, too_large
from syncryption_server.state import AppState, load_maintenance
from syncryption_server.storage import BlobStore, LocalBlobStore, S3BlobStore

VERSION_HEADER = "X-Syncryption-Version"
PROTOCOL_HEADER = "X-Syncryption-Protocol"
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


def home_page(state: AppState, origin: str) -> HTMLResponse:
    """The page at `/`, for people who open the server's URL in a browser. It names no
    secret: the shared secret comes from the administrator."""
    contact = state.settings.admin_contact
    m = state.maintenance
    if m is None:
        status = '<p class="notice">Status: ok</p>'
    else:
        status = (
            '<p class="notice error">Status: maintenance since '
            f"{html.escape(rfc3339(m.since))}. Sync is paused until maintenance ends.</p>"
        )
        if m.message:
            status += f"<p>Message from the administrator: {html.escape(m.message)}</p>"
    body = (
        f"<h1>Vault Syncryption server {html.escape(__version__)}</h1>"
        "<p>Self-hosted, end-to-end encrypted sync for Obsidian. Notes are encrypted on "
        "your devices; this server stores only ciphertext.</p>"
        f"{status}"
        "<h2>Connecting</h2><ol>"
        "<li>Install the Vault Syncryption plugin in Obsidian.</li>"
        f"<li>Enter this server's URL (<code>{html.escape(origin)}</code>), a username and "
        "a vault name, and create an encryption key.</li>"
        "<li>Creating a new vault needs the server's shared secret: ask the server "
        "administrator for it. A device joining an existing vault doesn't need it; a device "
        "that already syncs the vault approves it.</li></ol>"
        "<p>Administrator: "
        + (html.escape(contact) if contact else "contact the person who runs this server.")
        + "</p>"
    )
    return admin.html_page(body, title="Vault Syncryption")


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
        try:
            db.migrate()
        except OldDataError as e:
            db.close()
            log.error("%s", e)
            raise
        blob_store = store or make_blob_store(settings)
        await blob_store.start()
        state = AppState(settings=settings, db=db, store=blob_store)
        state.maintenance = load_maintenance(db)
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
        # Maintenance pauses the sync API only: `/`, `/health` and `/admin` keep working.
        state: AppState | None = getattr(request.app.state, "ctx", None)
        path = request.url.path
        err = state.maintenance_error() if state is not None else None
        if err is not None and (path == "/api/v1" or path.startswith("/api/v1/")):
            response: Response = error_response(err)
        else:
            response = await call_next(request)
        # On every response, errors included: the plugin checks the protocol first.
        response.headers[VERSION_HEADER] = __version__
        response.headers[PROTOCOL_HEADER] = str(PROTOCOL_VERSION)
        return response

    @app.get("/health")
    async def health(request: Request) -> JSONResponse:
        state: AppState = request.app.state.ctx
        m = state.maintenance
        body = {
            "status": "ok" if m is None else "maintenance",
            "version": __version__,
            "protocol": PROTOCOL_VERSION,
            "maintenance": None if m is None else {"since": rfc3339(m.since), "message": m.message},
            "adminContact": state.settings.admin_contact or None,
        }
        try:
            state.db.ping()
            await state.store.ping()
        except Exception:
            log.exception("health check failed")
            return JSONResponse({**body, "status": "unavailable"}, status_code=503)
        # Still 200 in maintenance: the container is healthy, only sync is paused.
        return JSONResponse(body)

    @app.get("/", include_in_schema=False)
    async def home(request: Request) -> HTMLResponse:
        state: AppState = request.app.state.ctx
        return home_page(state, auth.request_origin(request, state))

    for module in (auth, devices, vaults, blobs, sync, locks, admin):
        app.include_router(module.router)
    return app
