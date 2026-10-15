"""FastAPI application factory and process-wide routes."""

import asyncio
import contextlib
import html
import json
import logging
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from prometheus_client import CONTENT_TYPE_PLAIN_0_0_4
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from syncryption_server import (
    PROTOCOL_VERSION,
    __version__,
    admin,
    auth,
    blobs,
    devices,
    locks,
    metrics,
    retention,
    sync,
    vaults,
)
from syncryption_server.config import DEMO_QUOTA, DEMO_TTL, Settings, load_settings
from syncryption_server.db import Database, OldDataError
from syncryption_server.encoding import rfc3339
from syncryption_server.errors import (
    error_response,
    forbidden,
    install_error_handlers,
    too_large,
)
from syncryption_server.openapi import install_openapi
from syncryption_server.state import AppState, load_maintenance
from syncryption_server.storage import BlobStore, LocalBlobStore, S3BlobStore

STATIC_DIR = Path(__file__).parent / "static"
# Served at the root so browsers find them and the pages can link them: the logo, the
# favicon and the icon iOS uses when a page is added to the home screen.
ICONS = {
    "/favicon.ico": "image/vnd.microsoft.icon",
    "/icon-32.png": "image/png",
    "/icon-128.png": "image/png",
    "/icon-256.png": "image/png",
}
ICON_CACHE = "public, max-age=86400"

# The groups of the API, in the order the reference (docs/api.md) lists them.
TAGS = [
    {"name": "auth", "description": "Logging in, and joining the server with a new key."},
    {
        "name": "devices",
        "description": "The encryption keys of a vault: list, approve, policy, lock and remove.",
    },
    {"name": "vaults", "description": "Opening or creating a vault, its keyring and recovery."},
    {"name": "blobs", "description": "The encrypted chunks files are stored as."},
    {
        "name": "sync",
        "description": "Committing revisions, history, the change feed and the long-poll.",
    },
    {"name": "locks", "description": "Soft lease locks on the file someone is editing."},
]

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


async def health_report(state: AppState) -> tuple[dict[str, object], int]:
    """The `/health` body and status code."""
    m = state.maintenance
    body: dict[str, object] = {
        "status": "ok" if m is None else "maintenance",
        "version": __version__,
        "protocol": PROTOCOL_VERSION,
        "maintenance": None if m is None else {"since": rfc3339(m.since), "message": m.message},
        "adminContact": state.settings.admin_contact or None,
    }
    try:
        await state.db.run(state.db.ping)
        await state.store.ping()
    except Exception:
        log.exception("health check failed")
        return {**body, "status": "unavailable"}, 503
    # Still 200 in maintenance: the container is healthy, only sync is paused.
    return body, 200


def home_page(state: AppState, origin: str, health: dict[str, object]) -> HTMLResponse:
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
        admin.brand("Vault Syncryption server", __version__)
        + "<p>Self-hosted, end-to-end encrypted sync for Obsidian. Notes are encrypted on "
        "your devices; this server stores only ciphertext.</p>"
        f"{status}"
        + (
            '<p class="notice error">Demo server: accounts and their data are deleted '
            f"{DEMO_TTL // 3600} hours after sign-up, and each vault is limited to "
            f"{DEMO_QUOTA // 2**20} MB.</p>"
            if state.settings.demo_mode
            else ""
        )
        + "<h2>Connecting</h2><ol>"
        "<li>Install the Vault Syncryption plugin in Obsidian.</li>"
        f"<li>Enter this server's URL (<code>{html.escape(origin)}</code>), a username and "
        "a vault name, and create an encryption key.</li>"
        "<li>Creating a new vault needs the server's shared secret: ask the server "
        "administrator for it. A device joining an existing vault doesn't need it; a device "
        "that already syncs the vault approves it.</li></ol>"
        "<p>Administrator: "
        + (html.escape(contact) if contact else "contact the person who runs this server.")
        + "</p>"
        "<h2>Health</h2>"
        "<p><code>GET /health</code> returns the server's status as JSON. Right now:</p>"
        f"<pre><code>{html.escape(json.dumps(health, indent=2))}</code></pre>"
    )
    return admin.html_page(body, title="Vault Syncryption")


def make_blob_store(settings: Settings, s3_metrics: metrics.S3Metrics | None = None) -> BlobStore:
    if settings.blob_s3 is not None:
        return S3BlobStore(settings.blob_s3, s3_metrics)
    return LocalBlobStore(settings.data_dir)


async def _gc_loop(state: AppState) -> None:
    while True:
        await asyncio.sleep(GC_INTERVAL)
        await gc_pass(state)


async def gc_pass(state: AppState) -> None:
    """One hourly cleanup: on a demo server expired users first, then expired challenges,
    sessions and pending keys, then old revisions, then unreferenced blobs. A failing task
    doesn't stop the others."""
    m = state.metrics
    if state.settings.demo_mode:
        m.gc_runs.labels("demo").inc()
        try:
            purged = await admin.purge_demo_users(state)
            if purged:
                log.info("demo mode purged %d users", purged)
        except Exception:
            m.gc_failures.labels("demo").inc()
            log.exception("purging demo users failed")
        m.gc_last_run.labels("demo").set(time.time())
    m.gc_runs.labels("expired").inc()
    try:
        # Also done at each login and key listing, but challenge-only traffic does neither.
        await state.db.run(lambda: auth.sweep_expired(state))
    except Exception:
        m.gc_failures.labels("expired").inc()
        log.exception("sweeping expired logins failed")
    m.gc_last_run.labels("expired").set(time.time())
    m.gc_runs.labels("retention").inc()
    try:
        pruned = await retention.prune(state)
        m.pruned.inc(pruned)
        if pruned:
            log.info("retention pruned %d old revisions", pruned)
    except Exception:
        m.gc_failures.labels("retention").inc()
        log.exception("history retention failed")
    m.gc_last_run.labels("retention").set(time.time())
    m.gc_runs.labels("blobs").inc()
    try:
        # Blobs a prune freed are usually older than GC_GRACE, so they go in this pass.
        deleted = await blobs.collect_garbage(state)
        m.gc_deleted.inc(deleted)
        if deleted:
            log.info("garbage collection deleted %d unreferenced blobs", deleted)
    except Exception:
        m.gc_failures.labels("blobs").inc()
        log.exception("blob garbage collection failed")
    m.gc_last_run.labels("blobs").set(time.time())


def create_app(
    settings: Settings | None = None,
    store: BlobStore | None = None,
    clock: Callable[[], float] | None = None,
) -> FastAPI:
    """Build the app. With no arguments, settings come from the environment."""
    settings = settings or load_settings()
    app_metrics = metrics.Metrics(
        settings.data_dir,
        s3=settings.blob_s3 is not None,
        litestream=settings.litestream_metrics,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        db = Database(settings.db_path)
        try:
            await db.run(db.migrate)
        except OldDataError as e:
            await asyncio.to_thread(db.close)
            log.error("%s", e)
            raise
        blob_store = store or make_blob_store(settings, app_metrics.s3)
        await blob_store.start()
        state = AppState(settings=settings, db=db, store=blob_store, metrics=app_metrics)
        state.maintenance = await db.run(lambda: load_maintenance(db))
        if clock is not None:
            state.clock = clock
        app.state.ctx = state
        tasks = [
            asyncio.create_task(_gc_loop(state)),
            asyncio.create_task(metrics.watch_loop_lag(app_metrics)),
        ]
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            await blob_store.close()
            await asyncio.to_thread(db.close)

    app = FastAPI(
        title="Vault Syncryption", version=__version__, lifespan=lifespan, openapi_tags=TAGS
    )
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

    # Added last, so it is outermost and counts the maintenance 503 and the 413 too. Also with
    # DISABLE_METRICS, which removes only `/metrics`: the admin page shows the same numbers.
    app.add_middleware(metrics.RequestMetrics, metrics=app_metrics)

    @app.get("/health")
    async def health(request: Request) -> JSONResponse:
        """`200` with `{status, version, protocol, maintenance, adminContact}` once the
        database and the blob store answer, `503` with `"status": "unavailable"` otherwise.
        Needs no token, and stays `200` during maintenance, which only pauses `/api/v1`."""
        body, status = await health_report(request.app.state.ctx)
        return JSONResponse(body, status_code=status)

    if not settings.disable_metrics:

        @app.get(
            "/metrics",
            response_class=Response,
            responses={200: {"content": {CONTENT_TYPE_PLAIN_0_0_4: {}}}},
        )
        async def prometheus(request: Request) -> Response:
            """Prometheus metrics in the text exposition format. Needs no token, but answers
            only clients in `METRICS_ALLOWED_IPS` (empty: loopback and private ranges); others
            get `403 forbidden`. Only counts: requests by route template and status, users,
            vaults, keys by status, files, revisions, blobs and their bytes, active locks,
            open long-polls, cleanup runs, wrong shared secrets and admin tokens, and process
            metrics. No label names a user, vault, device or path. `DISABLE_METRICS=TRUE`
            removes the endpoint (`404`)."""
            state: AppState = request.app.state.ctx
            if not auth.ip_in(auth.client_ip(request, state), state.settings.metrics_allowed):
                return error_response(
                    forbidden("/metrics answers only the addresses in METRICS_ALLOWED_IPS.")
                )
            body = await metrics.render(state)
            return Response(body, media_type=CONTENT_TYPE_PLAIN_0_0_4)

    def add_icon_route(path: str, media_type: str) -> None:
        file = STATIC_DIR / path.lstrip("/")

        @app.get(path, include_in_schema=False, name=f"icon{path}")
        async def icon() -> FileResponse:
            return FileResponse(file, media_type=media_type, headers={"Cache-Control": ICON_CACHE})

    for icon_path, icon_type in ICONS.items():
        add_icon_route(icon_path, icon_type)

    @app.get("/", include_in_schema=False)
    async def home(request: Request) -> HTMLResponse:
        state: AppState = request.app.state.ctx
        report, _ = await health_report(state)
        return home_page(state, auth.request_origin(request, state), report)

    for module in (auth, devices, vaults, blobs, sync, locks, admin):
        app.include_router(module.router)
    install_openapi(app)
    return app
