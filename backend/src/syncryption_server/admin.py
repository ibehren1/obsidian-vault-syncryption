"""The admin page and API (protocol.md 14).

Everything needs `ADMIN_TOKEN`: as `Authorization: Bearer <token>`, or entered once in the
login form, which starts a browser session (an HttpOnly cookie, plus a CSRF token in every
form). The Vaults tab lists users, their vaults with stored sizes, and under each vault its
devices (one encryption key each). Users and vaults can be disabled (no access, data kept),
enabled again, and purged once disabled. Purging a vault also deletes its devices. Each vault
has a grace period for its remote-only devices (remote-only.md 5) and an optional storage
quota (protocol.md 12).
On a demo server (`DEMO_MODE`), the page and the GET API are public and every action is
refused, and users are purged a day after they join.
Maintenance mode pauses the whole sync API until it is turned off (protocol.md 14.1). The
Performance tab polls the server's metrics and shows them as rates (protocol.md 14.2).
"""

import base64
import hashlib
import hmac
import html
import logging
import secrets
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import parse_qs, urlsplit

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from syncryption_server import PROTOCOL_VERSION, __version__, metrics
from syncryption_server.auth import REMOTE_ONLY_GRACE, client_ip, limit_key, request_origin
from syncryption_server.config import DEMO_QUOTA, DEMO_TTL, MAX_NOTE, note_problem
from syncryption_server.encoding import rfc3339
from syncryption_server.errors import ApiError, bad_request, not_found
from syncryption_server.retention import DELETED_DAYS, KEEP_DAYS, KEEP_VERSIONS, OLD_EPOCH_DAYS
from syncryption_server.sshkeys import fingerprint, parse_public_key
from syncryption_server.state import AppState, Maintenance, get_state

log = logging.getLogger(__name__)

COOKIE = "syncryption_admin"
SESSION_TTL = 12 * 3600
# Wrong tokens per client address. Right tokens don't count, so scripts aren't limited.
FAILURE_LIMIT = (5, 900)

State = Annotated[AppState, Depends(get_state)]
Kind = Literal["users", "vaults"]
Action = Literal["disable", "enable", "purge"]

router = APIRouter(prefix="/admin", include_in_schema=False)

PERFORMANCE_JS = (Path(__file__).parent / "static" / "admin-performance.js").read_bytes()
ACTIVITY_JS = (Path(__file__).parent / "static" / "admin-activity.js").read_bytes()
# The Performance tab's choices, in seconds; 0 pauses.
INTERVALS = (1, 2, 5, 10, 30, 60, 0)
DEFAULT_INTERVAL = 5


# remote-only.md 5: the grace period of a vault's remote-only devices, in seconds.
MIN_GRACE = 3600
MAX_GRACE = 365 * 24 * 3600
# protocol.md 12: a vault's storage quota in bytes; the form takes whole GB (2**30 bytes).
GB = 1024**3
MAX_QUOTA = 2**50


class AdminError(Exception):
    """An action that can't be done. `code` picks the message shown on the page."""

    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code = code
        self.status = status


MESSAGES = {
    "disabled": "Disabled. Its devices can no longer sync; the data is kept.",
    "enabled": "Enabled again.",
    "purged": "Purged. The data is deleted, and so are its devices' encryption keys.",
    "logged_out": "Logged out.",
    "not_found": "It no longer exists.",
    "not_disabled": "Disable it before purging.",
    "confirm": "The name you typed doesn't match. Nothing was deleted.",
    "csrf": "The form expired. Try again.",
    "maintenance_on": "Maintenance started. Sync is paused on every device.",
    "maintenance_off": "Maintenance ended. Devices resume syncing by themselves.",
    "bad_message": f"The message must be one line of at most {MAX_NOTE} characters.",
    "grace_set": "Grace period saved. Remote-only devices get it at their next login.",
    "bad_grace": f"The grace period is a whole number of hours from 1 to {MAX_GRACE // 3600}, "
    f"or empty for the default ({REMOTE_ONLY_GRACE // 3600} hours).",
    "quota_set": "Storage quota saved. It applies to the next upload.",
    "bad_quota": f"The quota is a whole number of GB from 1 to {MAX_QUOTA // GB}, "
    "or empty for no quota.",
    "demo": "This is a demo server: the admin page is read-only.",
}
# Codes that aren't errors, shown in green.
SUCCESS = (
    "disabled",
    "enabled",
    "purged",
    "logged_out",
    "maintenance_on",
    "maintenance_off",
    "grace_set",
    "quota_set",
)


# Authentication


@dataclass(frozen=True)
class Admin:
    # The browser session's CSRF token; None for Bearer requests, which need none.
    csrf: str | None
    session_hash: str | None = None
    # A demo server's visitor: sees everything, changes nothing.
    read_only: bool = False


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def check_token(request: Request, state: AppState, token: str) -> bool:
    """Compare in constant time; wrong tokens are rate-limited per client address."""
    key = f"admin-ip:{limit_key(client_ip(request, state))}"
    if state.limiter.full(key, *FAILURE_LIMIT):
        state.limiter.check(key, *FAILURE_LIMIT)  # raises 429 with Retry-After
    expected = state.settings.admin_token
    if expected and hmac.compare_digest(token.encode(), expected.encode()):
        return True
    log.warning("admin: wrong token from %s", client_ip(request, state))
    state.metrics.admin_token_failures.inc()
    state.limiter.check(key, *FAILURE_LIMIT)
    return False


def _bearer(request: Request) -> str | None:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token.strip() else None


async def _admin(request: Request, state: AppState) -> Admin | None:
    """The Bearer token, else the session cookie. None when neither is valid."""
    if state.settings.demo_mode:
        return Admin(csrf=None, read_only=True)
    token = _bearer(request)
    if token is not None:
        return Admin(csrf=None) if check_token(request, state, token) else None
    cookie = request.cookies.get(COOKIE)
    if not cookie:
        return None
    row = await state.db.read(
        lambda: state.db.one(
            "SELECT csrf FROM admin_sessions WHERE token_hash = ? AND expires_at >= ?",
            _hash(cookie),
            state.now(),
        )
    )
    return Admin(csrf=row["csrf"], session_hash=_hash(cookie)) if row else None


async def api_admin(request: Request, state: State) -> Admin:
    """The JSON API takes only the Bearer token: no cookie, so no CSRF to worry about."""
    if state.settings.demo_mode:
        return Admin(csrf=None, read_only=True)
    token = _bearer(request)
    if token is None or not check_token(request, state, token):
        raise ApiError(401, "unauthenticated", "Send the admin token as a Bearer token.")
    return Admin(csrf=None)


ApiAdmin = Annotated[Admin, Depends(api_admin)]


# Data


def overview(state: AppState) -> list[dict]:
    users = state.db.all("SELECT * FROM users ORDER BY username")
    vaults = state.db.all(
        "SELECT v.id, v.user_id, v.name, v.created_at, v.disabled_at, v.remote_only_grace, "
        "v.blob_bytes AS size, v.blob_quota, "
        "(SELECT COUNT(*) FROM files f JOIN revisions r ON r.vault_id = f.vault_id "
        "AND r.rev = f.head_rev WHERE f.vault_id = v.id AND r.deleted = 0) AS files, "
        "(SELECT COUNT(*) FROM revisions r WHERE r.vault_id = v.id) AS revisions, "
        "(SELECT MAX(created_at) FROM revisions r WHERE r.vault_id = v.id) AS last_change "
        "FROM vaults v ORDER BY v.name"
    )
    devices = state.db.all("SELECT * FROM devices ORDER BY created_at, rowid")

    def time(t: int | None) -> str | None:
        return rfc3339(t) if t is not None else None

    def device(d: sqlite3.Row) -> dict:
        return {
            "id": d["id"],
            "name": d["name"],
            "fingerprint": fingerprint(parse_public_key(d["public_key"])),
            "status": d["status"],
            "createdAt": time(d["created_at"]),
            "lastSeenAt": time(d["last_seen_at"]),
            "remoteOnly": bool(d["remote_only"]),
            "locked": bool(d["locked"]),
        }

    out = []
    for u in users:
        mine = [d for d in devices if d["user_id"] == u["id"]]
        seen = [d["last_seen_at"] for d in mine if d["last_seen_at"] is not None]
        out.append(
            {
                "id": u["id"],
                "username": u["username"],
                "createdAt": time(u["created_at"]),
                "lastSeenAt": time(max(seen) if seen else None),
                "disabled": u["disabled_at"] is not None,
                "vaults": [
                    {
                        "id": v["id"],
                        "name": v["name"],
                        "size": v["size"],
                        "files": v["files"],
                        "revisions": v["revisions"],
                        "createdAt": time(v["created_at"]),
                        "lastChangeAt": time(v["last_change"]),
                        "disabled": v["disabled_at"] is not None,
                        # null: the default, REMOTE_ONLY_GRACE
                        "remoteOnlyGrace": v["remote_only_grace"],
                        # null: no quota
                        "quota": v["blob_quota"],
                        "devices": [device(d) for d in mine if d["vault_id"] == v["id"]],
                    }
                    for v in vaults
                    if v["user_id"] == u["id"]
                ],
                # Keys that registered to create a vault and haven't yet (swept after 24 h).
                "creating": [
                    {"vaultName": d["vault_name"], "device": device(d)}
                    for d in mine
                    if d["vault_id"] is None
                ],
            }
        )
    return out


# Actions


def _row(state: AppState, kind: Kind, item_id: str) -> sqlite3.Row:
    if kind == "users":
        row = state.db.one(
            "SELECT id, username AS name, disabled_at FROM users WHERE id = ?", item_id
        )
    else:
        row = state.db.one(
            "SELECT v.id, v.name, v.user_id, v.disabled_at, u.username FROM vaults v "
            "JOIN users u ON u.id = v.user_id WHERE v.id = ?",
            item_id,
        )
    if row is None:
        raise AdminError("not_found", 404)
    return row


def _vault_ids(state: AppState, kind: Kind, item_id: str) -> list[str]:
    if kind == "vaults":
        return [item_id]
    return [r["id"] for r in state.db.all("SELECT id FROM vaults WHERE user_id = ?", item_id)]


async def _purge_vault(state: AppState, user_id: str, vault_id: str) -> None:
    """Delete the vault's data and all its devices (their keys can then join anew)."""
    # Blobs first: if the store fails, the rows stay and the purge can be run again.
    prefix = f"blobs/{user_id}/{vault_id}/"
    keys = [key async for key in state.store.iter_keys(prefix)]
    for key in keys:
        await state.store.delete(key)

    def forget() -> None:
        with state.db.transaction() as db:
            for table in ("locks", "revision_blobs", "revisions", "files", "blobs", "keyrings"):
                db.execute(f"DELETE FROM {table} WHERE vault_id = ?", (vault_id,))  # noqa: S608
            _delete_devices(db, "vault_id = ?", vault_id)
            db.execute("DELETE FROM vaults WHERE id = ?", (vault_id,))

    await state.db.run(forget)


def _delete_devices(db: sqlite3.Connection, where: str, value: str) -> None:
    """Delete devices, their sessions (ON DELETE CASCADE) and their open challenges."""
    db.execute(
        "DELETE FROM challenges WHERE public_key IN "  # noqa: S608
        f"(SELECT public_key FROM devices WHERE {where})",
        (value,),
    )
    db.execute(f"DELETE FROM devices WHERE {where}", (value,))  # noqa: S608


async def act(state: AppState, kind: Kind, item_id: str, action: Action, confirm: str) -> str:
    """Run `action` and return the message code. Raises AdminError."""
    _refuse_on_demo(state)
    row = await state.db.read(lambda: _row(state, kind, item_id))
    label = f"user {row['name']}" if kind == "users" else f"vault {row['username']}/{row['name']}"
    table = "users" if kind == "users" else "vaults"
    if action in ("disable", "enable"):
        value = state.now() if action == "disable" else None

        def switch() -> list[str]:
            with state.db.transaction() as db:
                db.execute(f"UPDATE {table} SET disabled_at = ? WHERE id = ?", (value, item_id))  # noqa: S608
            return _vault_ids(state, kind, item_id)

        # Wake the long-polls, so devices see the change now rather than at their timeout.
        for vault_id in await state.db.run(switch):
            await state.notifier.notify(vault_id)
        log.info("admin: %sd %s", action, label)
        return f"{action}d"

    if row["disabled_at"] is None:
        raise AdminError("not_disabled", 409)
    if confirm != row["name"]:
        raise AdminError("confirm")
    if kind == "vaults":
        await _purge_vault(state, row["user_id"], item_id)
    else:
        await purge_user(state, item_id, row["name"])
    log.info("admin: purged %s", label)
    return "purged"


async def purge_user(state: AppState, user_id: str, username: str) -> None:
    """Delete the user, their vaults' data and all their devices."""
    for vault_id in await state.db.read(lambda: _vault_ids(state, "users", user_id)):
        await _purge_vault(state, user_id, vault_id)

    def forget() -> None:
        with state.db.transaction() as db:
            # Keys that were creating a vault, the only devices left.
            _delete_devices(db, "user_id = ?", user_id)
            db.execute("DELETE FROM challenges WHERE username = ?", (username,))
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))

    await state.db.run(forget)


async def purge_demo_users(state: AppState) -> int:
    """On a demo server, purge the users who joined DEMO_TTL ago or earlier. Returns how many."""
    before = state.now() - DEMO_TTL
    users = await state.db.read(
        lambda: state.db.all("SELECT id, username FROM users WHERE created_at <= ?", before)
    )
    for user in users:
        user_id = user["id"]

        def disable(user_id: str = user_id) -> list[str]:
            with state.db.transaction() as db:
                db.execute("UPDATE users SET disabled_at = ? WHERE id = ?", (state.now(), user_id))
            return _vault_ids(state, "users", user_id)

        # Disabled first, so the woken long-polls answer that rather than fail mid-purge.
        for vault_id in await state.db.run(disable):
            await state.notifier.notify(vault_id)
        await purge_user(state, user_id, user["username"])
    return len(users)


def _refuse_on_demo(state: AppState) -> None:
    if state.settings.demo_mode:
        raise AdminError("demo", 403)


async def set_grace(state: AppState, vault_id: str, seconds: int | None) -> str:
    """Set a vault's grace period for remote-only devices, None for the default."""
    _refuse_on_demo(state)
    if seconds is not None and not MIN_GRACE <= seconds <= MAX_GRACE:
        raise AdminError("bad_grace")
    row = await state.db.read(lambda: _row(state, "vaults", vault_id))

    def store() -> None:
        with state.db.transaction() as db:
            db.execute("UPDATE vaults SET remote_only_grace = ? WHERE id = ?", (seconds, vault_id))

    await state.db.run(store)
    log.info("admin: set the grace period of vault %s/%s", row["username"], row["name"])
    return "grace_set"


async def set_quota(state: AppState, vault_id: str, quota: int | None) -> str:
    """Set a vault's storage quota in bytes, None for no quota."""
    _refuse_on_demo(state)
    if quota is not None and not 1 <= quota <= MAX_QUOTA:
        raise AdminError("bad_quota")
    row = await state.db.read(lambda: _row(state, "vaults", vault_id))

    def store() -> None:
        with state.db.transaction() as db:
            db.execute("UPDATE vaults SET blob_quota = ? WHERE id = ?", (quota, vault_id))

    await state.db.run(store)
    log.info("admin: set the storage quota of vault %s/%s", row["username"], row["name"])
    return "quota_set"


async def set_maintenance(state: AppState, on: bool, message: str | None = None) -> str:
    """Turn maintenance on (or update its message) or off. Returns the message code."""
    _refuse_on_demo(state)
    if not on:

        def clear() -> None:
            with state.db.transaction() as db:
                db.execute("DELETE FROM maintenance")

        await state.db.run(clear)
        if state.maintenance is not None:
            log.info("admin: maintenance off")
        state.maintenance = None
        return "maintenance_off"
    message = (message or "").strip() or None
    if message is not None and note_problem(message):
        raise AdminError("bad_message")
    since = state.maintenance.since if state.maintenance else state.now()

    def store() -> None:
        with state.db.transaction() as db:
            db.execute(
                "INSERT OR REPLACE INTO maintenance (id, since, message) VALUES (1, ?, ?)",
                (since, message),
            )

    await state.db.run(store)
    state.maintenance = Maintenance(since, message)
    # Wake every long-poll: each answers with the maintenance 503.
    await state.notifier.notify_all()
    log.info("admin: maintenance on")
    return "maintenance_on"


def status(state: AppState) -> dict:
    m = state.maintenance
    return {
        "version": __version__,
        "protocol": PROTOCOL_VERSION,
        "maintenance": None if m is None else {"since": rfc3339(m.since), "message": m.message},
        "adminContact": state.settings.admin_contact or None,
    }


# JSON API


def _api_error(e: AdminError) -> ApiError:
    if e.status == 404:
        return not_found()
    if e.status == 403:
        return ApiError(403, e.code, MESSAGES[e.code])
    return bad_request(MESSAGES[e.code])


class PurgeRequest(BaseModel):
    confirm: str = Field(max_length=64, description="The username or vault name, to confirm.")


@router.get("/api/users")
async def api_users(admin: ApiAdmin, state: State) -> dict:
    return {"users": await state.db.read(lambda: overview(state))}


class MaintenanceRequest(BaseModel):
    message: str | None = Field(None, max_length=MAX_NOTE, description="Shown to users.")


@router.get("/api/performance")
async def api_performance(admin: ApiAdmin, state: State) -> dict:
    return await metrics.snapshot(state)


@router.get("/api/activity")
async def api_activity(admin: ApiAdmin, state: State) -> dict:
    return await metrics.activity(state)


@router.get("/api/status")
async def api_status(admin: ApiAdmin, state: State) -> dict:
    return status(state)


@router.post("/api/maintenance/{switch}", status_code=204)
async def api_maintenance(
    switch: Literal["on", "off"],
    admin: ApiAdmin,
    state: State,
    body: MaintenanceRequest | None = None,
) -> Response:
    try:
        await set_maintenance(state, switch == "on", body.message if body else None)
    except AdminError as e:
        raise _api_error(e) from e
    return Response(status_code=204)


class GraceRequest(BaseModel):
    graceSeconds: int | None = Field(
        description=f"{MIN_GRACE} to {MAX_GRACE}, or null for the default ({REMOTE_ONLY_GRACE})."
    )


@router.post("/api/vaults/{vault_id}/grace", status_code=204)
async def api_grace(vault_id: str, body: GraceRequest, admin: ApiAdmin, state: State) -> Response:
    try:
        await set_grace(state, vault_id, body.graceSeconds)
    except AdminError as e:
        raise _api_error(e) from e
    return Response(status_code=204)


class QuotaRequest(BaseModel):
    quotaBytes: int | None = Field(
        description=f"1 to {MAX_QUOTA} bytes of stored blobs, or null for no quota."
    )


@router.post("/api/vaults/{vault_id}/quota", status_code=204)
async def api_quota(vault_id: str, body: QuotaRequest, admin: ApiAdmin, state: State) -> Response:
    try:
        await set_quota(state, vault_id, body.quotaBytes)
    except AdminError as e:
        raise _api_error(e) from e
    return Response(status_code=204)


@router.post("/api/{kind}/{item_id}/{action}", status_code=204)
async def api_action(
    kind: Kind,
    item_id: str,
    action: Action,
    admin: ApiAdmin,
    state: State,
    body: PurgeRequest | None = None,
) -> Response:
    try:
        await act(state, kind, item_id, action, body.confirm if body else "")
    except AdminError as e:
        if e.status == 404:
            raise not_found() from e
        raise ApiError(e.status, e.code, MESSAGES[e.code]) from e
    return Response(status_code=204)


# HTML


STYLE = """
body {
  font: 15px/1.45 system-ui, sans-serif;
  margin: 2rem auto;
  max-width: 64rem;
  padding: 0 1rem;
  color: #222;
}
h1 { font-size: 1.4rem; }
h2 { font-size: 1.1rem; margin: 0; }
section {
  border: 1px solid #d3ddcf;
  border-radius: 6px;
  padding: 1rem;
  margin: 1rem 0;
  background: #f5f8f3;
}
section.disabled { background: #f8f1f1; border-color: #e3caca; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0; }
th, td {
  text-align: left;
  padding: .25rem .5rem;
  border-bottom: 1px solid #eee;
  vertical-align: top;
}
td.num, th.num { text-align: right; }
pre { background: #f6f6f6; border: 1px solid #ddd; border-radius: 6px; padding: .75rem; }
.muted { color: #777; }
.tag { font-size: .8rem; padding: 0 .4rem; border-radius: 4px; background: #c33; color: #fff; }
form.inline { display: inline; }
button { cursor: pointer; }
button.danger { color: #fff; background: #c33; border: 1px solid #a22; }
.notice {
  padding: .5rem 1rem;
  border-radius: 6px;
  background: #eef5ee;
  border: 1px solid #9c9;
}
.notice.error { background: #f8eeee; border-color: #c99; }
header { display: flex; justify-content: space-between; align-items: center; }
.brand { display: flex; align-items: center; gap: 1rem; }
.brand h1 { margin: .5rem 0; }
.brand .ver { color: #777; font-size: .95rem; font-weight: 400; }
.top { display: flex; align-items: center; gap: 1rem; }
nav.tabs { display: flex; gap: .25rem; }
nav.tabs a {
  padding: .25rem .75rem;
  border: 1px solid #2d2f31;
  border-radius: 6px;
  color: #2d2f31;
  text-decoration: none;
}
nav.tabs a.on { background: #2d2f31; color: #fff; }
h3 { font-size: 1rem; margin: 0; }
section.vault {
  margin: .75rem 0 0;
  padding: .75rem;
  background: #fff;
  border-left: 4px solid #9fb89a;
}
section.vault.disabled { background: #fbf5f5; border-color: #e3caca; border-left-color: #d49a9a; }
section.vault.creating { background: #fffcf4; border-left-color: #e2c27a; }
section.vault th { border-bottom: 2px solid #9fb89a; }
/* The Performance tab's cards, in the logo's colour. */
section.stripe { background: #fff; border-color: #d5d7d9; border-left: 4px solid #2d2f31; }
section.stripe th { border-bottom: 2px solid #2d2f31; }
section.vault p { margin: .25rem 0; }
.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1rem;
  margin: 1rem 0;
}
.cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr)); gap: 0 1rem; }
.stats { display: flex; flex-wrap: wrap; gap: .5rem 2rem; margin: .5rem 0; }
.stat .label { color: #777; margin-right: .5rem; }
.spark { display: inline-block; vertical-align: middle; margin-left: .5rem; }
.spark svg { display: block; }
section.stripe td:first-child { width: 100%; }
section.stripe td.num { white-space: nowrap; }
td.trend { padding-top: .35rem; }
td.trend .spark { margin: 0; }
"""
# The CSP allows this one stylesheet by its hash, so no other inline style can apply.
STYLE_HASH = "sha256-" + base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode()


def _size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def _when(value: str | None) -> str:
    return html.escape(value.replace("T", " ").replace("Z", " UTC")) if value else "never"


ICON_LINKS = (
    '<link rel="icon" href="/favicon.ico" sizes="any">'
    '<link rel="icon" type="image/png" href="/icon-32.png" sizes="32x32">'
    '<link rel="apple-touch-icon" href="/icon-256.png">'
)


def brand(title: str, version: str | None = None) -> str:
    """The logo and page title, shared by `/` and `/admin`."""
    ver = f' <span class="ver">{html.escape(version)}</span>' if version else ""
    return (
        '<div class="brand"><img src="/icon-128.png" width="64" height="64" alt="">'
        f"<h1>{html.escape(title)}{ver}</h1></div>"
    )


def html_page(
    body: str, status: int = 200, title: str = "Vault Syncryption admin", script: str | None = None
) -> HTMLResponse:
    """A page with the admin style and strict headers. Also used for the `/` page. Pages run
    no scripts, except `script`, a same-origin path, which may then fetch from this origin."""
    if script is not None:
        body += f'<script src="{html.escape(script)}"></script>'
    scripts = "script-src 'self'; connect-src 'self'; " if script is not None else ""
    doc = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{html.escape(title)}</title>{ICON_LINKS}<style>{STYLE}</style></head>"
        f"<body>{body}</body></html>"
    )
    return HTMLResponse(
        doc,
        status_code=status,
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": f"default-src 'none'; img-src 'self'; {scripts}"
            f"style-src '{STYLE_HASH}'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            "Referrer-Policy": "no-referrer",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
        },
    )


def _login_page(message: str | None = None, status: int = 200, error: bool = True) -> HTMLResponse:
    kind = "notice error" if error else "notice"
    notice = f'<p class="{kind}">{html.escape(message)}</p>' if message else ""
    return html_page(
        brand("Vault Syncryption admin") + f"{notice}"
        '<form method="post" action="/admin/login">'
        '<p><label>Admin token<br><input type="password" name="token" size="48" '
        'autocomplete="current-password" required autofocus></label></p>'
        "<p><button>Log in</button></p></form>"
        '<p class="muted">The token is the server\'s ADMIN_TOKEN environment variable.</p>',
        status,
    )


def _button(admin: Admin, kind: Kind, item: dict, action: Action, name: str) -> str:
    csrf = f'<input type="hidden" name="csrf" value="{html.escape(admin.csrf or "")}">'
    target = f"/admin/{kind}/{html.escape(item['id'])}/{action}"
    if action == "purge":
        return (
            f'<form class="inline" method="post" action="{target}">{csrf}'
            f'<input name="confirm" placeholder="type {html.escape(name)} to purge" size="22" '
            'required autocomplete="off"> <button class="danger">Purge</button></form>'
        )
    label = "Disable" if action == "disable" else "Enable"
    form = f'<form class="inline" method="post" action="{target}">'
    return f"{form}{csrf}<button>{label}</button></form>"


def _actions(admin: Admin, kind: Kind, item: dict, name: str) -> str:
    if admin.read_only:
        return ""
    if not item["disabled"]:
        return _button(admin, kind, item, "disable", name)
    return (
        _button(admin, kind, item, "enable", name) + " " + _button(admin, kind, item, "purge", name)
    )


def _grace_form(admin: Admin, vault: dict) -> str:
    """The vault's grace period in hours; empty means the default."""
    grace = vault["remoteOnlyGrace"]
    value = str(grace // 3600) if grace is not None else ""
    if admin.read_only:
        return f"{value or REMOTE_ONLY_GRACE // 3600} h"
    csrf = (
        f'<input type="hidden" name="csrf" value="{html.escape(admin.csrf)}">' if admin.csrf else ""
    )
    target = f"/admin/vaults/{html.escape(vault['id'])}/grace"
    return (
        f'<form class="inline" method="post" action="{target}">{csrf}'
        f'<input name="hours" size="4" inputmode="numeric" value="{value}" '
        f'placeholder="{REMOTE_ONLY_GRACE // 3600}" aria-label="Grace period in hours"> h '
        "<button>Save</button></form>"
    )


def _quota_form(admin: Admin, vault: dict) -> str:
    """The vault's storage quota in whole GB; empty means no quota."""
    quota = vault["quota"]
    if admin.read_only:
        return _size(quota) if quota is not None else "none"
    # A quota set through the API in bytes shows rounded up to whole GB.
    value = str(-(-quota // GB)) if quota is not None else ""
    csrf = (
        f'<input type="hidden" name="csrf" value="{html.escape(admin.csrf)}">' if admin.csrf else ""
    )
    target = f"/admin/vaults/{html.escape(vault['id'])}/quota"
    return (
        f'<form class="inline" method="post" action="{target}">{csrf}'
        f'<input name="gb" size="6" inputmode="numeric" value="{value}" '
        'placeholder="none" aria-label="Storage quota in GB"> GB '
        "<button>Save</button></form>"
    )


def _maintenance_section(admin: Admin, state: AppState) -> str:
    csrf = f'<input type="hidden" name="csrf" value="{html.escape(admin.csrf or "")}">'
    m = state.maintenance
    if admin.read_only:
        since = f"on since {_when(rfc3339(m.since))}" if m else "off"
        return f'<section><h2>Maintenance</h2><p class="muted">{since}.</p></section>'
    if m is None:
        return (
            "<section><h2>Maintenance</h2>"
            '<p class="muted">Off. Starting it pauses sync on every device until you end it; '
            "this page, / and /health keep working.</p>"
            f'<form method="post" action="/admin/maintenance/on">{csrf}'
            f'<input name="message" maxlength="{MAX_NOTE}" size="60" autocomplete="off" '
            'placeholder="optional message for users, e.g. back at 18:00 UTC"> '
            "<button>Start maintenance</button></form></section>"
        )
    note = f" Message: {html.escape(m.message)}" if m.message else " No message."
    return (
        '<section class="disabled"><h2>Maintenance <span class="tag">on</span></h2>'
        f"<p>Sync is paused since {_when(rfc3339(m.since))}.{note}</p>"
        f'<form method="post" action="/admin/maintenance/off">{csrf}'
        "<button>End maintenance</button></form></section>"
    )


def _header(admin: Admin, tab: str) -> str:
    """The logo, the tabs and the logout button."""
    logout = (
        '<form method="post" action="/admin/logout">'
        f'<input type="hidden" name="csrf" value="{html.escape(admin.csrf)}">'
        "<button>Log out</button></form>"
        if admin.csrf
        else ""
    )
    links = "".join(
        f'<a href="{href}"{' class="on"' if name == tab else ""}>{label}</a>'
        for name, label, href in (
            ("vaults", "Vaults", "/admin"),
            ("performance", "Performance", "/admin?tab=performance"),
            ("activity", "Activity", "/admin?tab=activity"),
        )
    )
    return (
        f"<header>{brand('Vault Syncryption admin', __version__)}"
        f'<div class="top"><nav class="tabs">{links}</nav>{logout}</div></header>'
    )


def _keys(devices: list[dict]) -> str:
    """A vault's encryption keys, one device each."""
    if not devices:
        return '<p class="muted">No keys.</p>'
    rows = [
        "<table><tr><th>Device</th><th>Key</th><th>Status</th>"
        "<th>Joined</th><th>Last seen</th></tr>"
    ]
    for d in devices:
        rows.append(
            f"<tr><td>{html.escape(d['name'])}</td>"
            f'<td class="muted">{html.escape(d["fingerprint"])}</td>'
            f"<td>{html.escape(d['status'])}"
            f"{' <span class="muted">remote-only</span>' if d['remoteOnly'] else ''}"
            f"{' <span class="muted">locked</span>' if d['locked'] else ''}</td>"
            f"<td>{_when(d['createdAt'])}</td><td>{_when(d['lastSeenAt'])}</td></tr>"
        )
    rows.append("</table>")
    return "".join(rows)


def _vault_card(admin: Admin, v: dict) -> str:
    tag = ' <span class="tag">disabled</span>' if v["disabled"] else ""
    return (
        f'<section class="vault{" disabled" if v["disabled"] else ""}">'
        f"<header><h3>{html.escape(v['name'])}{tag}</h3>"
        f"<div>{_actions(admin, 'vaults', v, v['name'])}</div></header>"
        f'<p class="muted">{_size(v["size"])} stored · {v["files"]:,} files · '
        f"{v['revisions']:,} versions · created {_when(v['createdAt'])} · "
        f"last change {_when(v['lastChangeAt'])}</p>"
        f"<div>Remote-only grace {_grace_form(admin, v)}</div>"
        f"<div>Storage quota {_quota_form(admin, v)}</div>"
        f"{_keys(v['devices'])}</section>"
    )


def _dashboard(
    admin: Admin, state: AppState, users: list[dict], message: str | None, error: bool
) -> HTMLResponse:
    total = sum(v["size"] for u in users for v in u["vaults"])
    parts = [_header(admin, "vaults")]
    if message:
        parts.append(f'<p class="notice{" error" if error else ""}">{html.escape(message)}</p>')
    parts.append(_maintenance_section(admin, state))
    if state.settings.demo_mode:
        kept = (
            "Demo server: this page is read-only. Only the current version of each file is "
            f"kept, each vault has a {_size(DEMO_QUOTA)} quota, and users are deleted with "
            f"their data {DEMO_TTL // 3600} hours after they join. "
        )
    else:
        kept = (
            "Stored size counts history and deleted files still kept. "
            f"The server keeps every version for {KEEP_DAYS} days, at least the last "
            f"{KEEP_VERSIONS} of each file, and deleted files for {DELETED_DAYS} days; the "
            f"copies a key change leaves behind go after {OLD_EPOCH_DAYS} days. Older versions "
            "are removed automatically. "
        )
    parts.append(
        f'<p class="muted">{len(users)} users, {sum(len(u["vaults"]) for u in users)} vaults, '
        f"{_size(total)} stored. {kept}"
        "Each device is one encryption key in one vault; purging a vault deletes its devices."
        "</p>"
    )
    for u in users:
        name = u["username"]
        tag = ' <span class="tag">disabled</span>' if u["disabled"] else ""
        parts.append(f'<section class="{"disabled" if u["disabled"] else ""}">')
        parts.append(
            f"<header><h2>{html.escape(name)}{tag}</h2>"
            f"<div>{_actions(admin, 'users', u, name)}</div></header>"
            f'<p class="muted">Joined {_when(u["createdAt"])}. '
            f"Last seen {_when(u['lastSeenAt'])}.</p>"
        )
        if not u["vaults"] and not u["creating"]:
            parts.append('<p class="muted">No vaults.</p>')
        parts.extend(_vault_card(admin, v) for v in u["vaults"])
        # Keys that registered to create a vault: one card per vault name.
        creating: dict[str, list[dict]] = {}
        for c in u["creating"]:
            creating.setdefault(c["vaultName"], []).append(c["device"])
        for vault_name, devices in creating.items():
            parts.append(
                f'<section class="vault creating"><header><h3>{html.escape(vault_name)} '
                '<span class="muted">(being created)</span></h3></header>'
                f"{_keys(devices)}</section>"
            )
        parts.append("</section>")
    if not users:
        parts.append('<p class="muted">No users yet.</p>')
    return html_page("".join(parts))


def _spark(value_id: str) -> str:
    """Where the script draws the value's recent trend."""
    return f'<span class="spark" id="spark-{value_id}"></span>'


def _stat(label: str, value_id: str, spark: bool = False) -> str:
    trend = _spark(value_id) if spark else ""
    return (
        f'<span class="stat"><span class="label">{label}</span><b id="{value_id}">–</b>'
        f"{trend}</span>"
    )


def _line(label: str, value_id: str, row_id: str | None = None, spark: bool = False) -> str:
    row = f' id="{row_id}" hidden' if row_id else ""
    trend = _spark(value_id) if spark else ""
    return (
        f'<tr{row}><td>{label}</td><td class="trend">{trend}</td>'
        f'<td class="num" id="{value_id}">–</td></tr>'
    )


def _card(title: str, rows: str, card_id: str | None = None) -> str:
    """A titled table. With `card_id` it starts hidden, until the script has data for it."""
    attrs = f' id="{card_id}" hidden' if card_id else ""
    return f'<section class="stripe"{attrs}><h2>{title}</h2><table>{rows}</table></section>'


def _interval() -> str:
    """The refresh dropdown of the Performance and Activity tabs."""
    options = "".join(
        f'<option value="{s}"{" selected" if s == DEFAULT_INTERVAL else ""}>'
        f"{f'{s} s' if s else 'Paused'}</option>"
        for s in INTERVALS
    )
    return (
        '<div class="toolbar"><label>Refresh every '
        f'<select id="interval">{options}</select></label>'
        '<span class="muted" id="updated">Loading…</span></div>'
    )


def _performance(admin: Admin) -> HTMLResponse:
    """The Performance tab. The numbers are filled in by admin-performance.js."""
    requests = (
        '<section class="stripe"><h2>Requests <span class="muted">(last interval)</span></h2>'
        '<div class="stats">'
        + _stat("Requests/s", "rps", spark=True)
        + _stat("Errors/s (5xx)", "e5", spark=True)
        + _stat("4xx/s", "e4", spark=True)
        + '</div><div class="stats">'
        + _stat("Latency p50", "p50")
        + _stat("p95", "p95", spark=True)
        + _stat("p99", "p99")
        + '<span class="muted">(excludes /wait long-polls)</span></div>'
        '<table><thead><tr><th>Route</th><th class="num">Req/s</th><th class="num">p95</th>'
        '</tr></thead><tbody id="routes"></tbody></table></section>'
    )
    sync = _card(
        'Sync activity <span class="muted">(per second)</span>',
        _line("File commits", "commits", spark=True)
        + _line("Conflicts (409)", "conflicts", spark=True)
        + _line("Blob uploads", "uploads", spark=True)
        + _line("Blob downloads", "downloads", spark=True)
        + _line("Logins", "logins", spark=True)
        + _line("Unauthenticated (401)", "s401", spark=True)
        + _line("Rate limited (429)", "s429", spark=True),
    )
    load = _card(
        "Traffic and load",
        _line("Received", "bin", spark=True)
        + _line("Sent", "bout", spark=True)
        + _line("In flight (without long-polls)", "inflight", spark=True)
        + _line("Open long-polls", "longpolls", spark=True)
        + _line("Event-loop lag (worst of 10 s)", "lag", spark=True),
    )
    server = _card(
        "Server",
        _line("CPU (process)", "cpu", spark=True)
        + _line("CPU (container)", "ccpu", "row-ccpu", spark=True)
        + _line("Memory (process)", "mem", spark=True)
        + _line("Memory (container)", "cmem", "row-cmem", spark=True)
        + _line("Open files", "fds")
        + _line("Active locks", "locks")
        + _line("Maintenance", "maintenance")
        + _line("Wrong admin tokens / shared secrets", "failures"),
    )
    disk = _card(
        "Disk and database",
        _line("Free on the data disk", "disk", "row-disk")
        + _line("meta.db", "db", "row-db")
        + _line("Write-ahead log", "wal", "row-wal")
        + _line("Cleanup runs (retention/blobs)", "gc")
        + _line("Last cleanup", "gclast")
        + _line("Revisions removed by retention", "pruned")
        + _line("Blobs deleted by cleanup", "deleted"),
    )
    s3 = _card(
        'S3 blob store <span class="muted">(last interval)</span>',
        _line("Calls/s", "s3rps", spark=True)
        + _line("Failed calls/s", "s3err", spark=True)
        + _line("Latency p50 / p99", "s3p50p99")
        + _line("Latency p95", "s3p95", spark=True)
        + _line("Uploaded", "s3up", spark=True)
        + _line("Downloaded", "s3down", spark=True)
        + _line("Retries/s", "s3retries", spark=True)
        + _line("In flight", "s3inflight")
        + _line("Failures since start", "s3results"),
        "card-s3",
    )
    litestream = _card(
        'Database replication <span class="muted">(Litestream)</span>',
        _line("Status", "lsup")
        + _line("Syncs/s", "lssync", spark=True)
        + _line("Sync errors since start", "lserr")
        + _line("Time spent syncing", "lsbusy", spark=True)
        + _line("WAL written for replication", "lswal", spark=True)
        + _line("Uploads to S3/s", "lsput", spark=True)
        + _line("Uploaded to S3", "lsbytes", spark=True)
        + _line("Transaction ID", "lstxid"),
        "card-litestream",
    )
    storage = _card(
        "Storage",
        _line("Users", "users")
        + _line("Vaults", "vaults")
        + _line("Keys", "keys")
        + _line("Files", "files")
        + _line("Versions", "revisions")
        + _line("Blobs", "blobs")
        + _line("Stored", "stored", spark=True),
    )
    body = (
        _header(admin, "performance")
        + _interval()
        + '<noscript><p class="notice error">The Performance tab needs JavaScript. The same '
        "numbers are in GET /admin/api/performance.</p></noscript>"
        + requests
        + f'<div class="cols">{sync}{load}</div>'
        + f'<div class="cols">{server}{disk}</div>'
        + f'<div class="cols">{s3}{litestream}</div>'
        + storage
    )
    return html_page(body, script="/admin/performance.js")


def _activity(admin: Admin) -> HTMLResponse:
    """The Activity tab. The rows are filled in by admin-activity.js."""
    section = (
        '<section class="stripe"><h2>Activity <span class="muted" id="since">'
        "(since this tab opened)</span></h2>"
        '<div class="stats"><label>Group by <select id="groupby">'
        '<option value="device" selected>Device</option><option value="vault">Vault</option>'
        '<option value="user">User</option></select></label>'
        '<span class="muted">Totals since this tab opened, busiest first. Requests leave out '
        "the /wait long-polls, counted in Waits.</span></div>"
        "<table><thead><tr><th>User</th><th>Vault</th><th>Device</th>"
        '<th class="num">Requests</th><th class="num">Req/s</th><th class="num">Waits</th>'
        '<th class="num">Errors</th><th class="num">Received</th><th class="num">Sent</th>'
        '<th>Top route</th></tr></thead><tbody id="activity"></tbody></table></section>'
    )
    body = (
        _header(admin, "activity")
        + _interval()
        + '<noscript><p class="notice error">The Activity tab needs JavaScript. The same '
        "totals are in GET /admin/api/activity.</p></noscript>" + section
    )
    return html_page(body, script="/admin/activity.js")


async def _form(request: Request) -> dict[str, str]:
    fields = parse_qs((await request.body()).decode("utf-8", "replace"), keep_blank_values=True)
    return {k: v[0] for k, v in fields.items()}


def _back(code: str) -> RedirectResponse:
    return RedirectResponse(f"/admin?done={code}", status_code=303)


@router.get("")
async def page(request: Request, state: State, done: str = "", tab: str = "") -> Response:
    admin = await _admin(request, state)
    if admin is None:
        if done == "logged_out":
            return _login_page(MESSAGES[done], error=False)
        return _login_page(status=401 if _bearer(request) else 200)
    if tab == "performance":
        return _performance(admin)
    if tab == "activity":
        return _activity(admin)
    message = MESSAGES.get(done)
    error = done not in SUCCESS
    users = await state.db.read(lambda: overview(state))
    return _dashboard(admin, state, users, message, error)


@router.get("/performance.json")
async def performance_json(request: Request, state: State) -> Response:
    """The Performance tab's data, with the session cookie (a GET changes nothing, so no CSRF)."""
    if await _admin(request, state) is None:
        raise ApiError(401, "unauthenticated", "Log in first.")
    return JSONResponse(await metrics.snapshot(state), headers={"Cache-Control": "no-store"})


@router.get("/activity.json")
async def activity_json(request: Request, state: State) -> Response:
    """The Activity tab's data, with the session cookie (a GET changes nothing, so no CSRF)."""
    if await _admin(request, state) is None:
        raise ApiError(401, "unauthenticated", "Log in first.")
    return JSONResponse(await metrics.activity(state), headers={"Cache-Control": "no-store"})


@router.get("/activity.js")
async def activity_js() -> Response:
    """The Activity tab's script. Static, so it needs no login."""
    return Response(
        ACTIVITY_JS,
        media_type="text/javascript",
        headers={"Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff"},
    )


@router.get("/performance.js")
async def performance_js() -> Response:
    """The Performance tab's script. Static, so it needs no login."""
    return Response(
        PERFORMANCE_JS,
        media_type="text/javascript",
        headers={"Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff"},
    )


@router.post("/login")
async def login(request: Request, state: State) -> Response:
    if state.settings.demo_mode:
        return RedirectResponse("/admin", status_code=303)
    token = (await _form(request)).get("token", "").strip()
    if not check_token(request, state, token):
        return _login_page("Wrong token.", status=401)
    session = secrets.token_urlsafe(32)
    now = state.now()

    def store() -> None:
        with state.db.transaction() as db:
            db.execute("DELETE FROM admin_sessions WHERE expires_at < ?", (now,))
            db.execute(
                "INSERT INTO admin_sessions (token_hash, csrf, expires_at) VALUES (?, ?, ?)",
                (_hash(session), secrets.token_urlsafe(32), now + SESSION_TTL),
            )

    await state.db.run(store)
    log.info("admin: logged in from %s", client_ip(request, state))
    response = RedirectResponse("/admin", status_code=303)
    response.set_cookie(
        COOKIE,
        session,
        max_age=SESSION_TTL,
        path="/admin",
        httponly=True,
        secure=_secure_cookie(request_origin(request, state)),
        samesite="strict",
    )
    return response


def _secure_cookie(origin: str) -> bool:
    """`Secure` always, except for plain HTTP to this machine (development), where a browser
    wouldn't send the cookie back. Not from the scheme alone: a request that claims `http`
    must not get a cookie that may travel unencrypted."""
    host = (urlsplit(origin).hostname or "").lower()
    loopback = host == "localhost" or host == "::1" or host.startswith("127.")
    return not (origin.startswith("http:") and loopback)


async def _form_admin(request: Request, state: AppState, form: dict[str, str]) -> Admin | None:
    """Bearer, or the session cookie with the session's CSRF token."""
    admin = await _admin(request, state)
    if admin is None:
        return None
    if admin.csrf is not None and not hmac.compare_digest(
        form.get("csrf", "").encode(), admin.csrf.encode()
    ):
        raise AdminError("csrf", 403)
    return admin


@router.post("/logout")
async def logout(request: Request, state: State) -> Response:
    if state.settings.demo_mode:
        return RedirectResponse("/admin", status_code=303)
    try:
        admin = await _form_admin(request, state, await _form(request))
    except AdminError:
        return _back("csrf")
    if admin is not None and admin.session_hash is not None:
        session_hash = admin.session_hash

        def forget() -> None:
            with state.db.transaction() as db:
                db.execute("DELETE FROM admin_sessions WHERE token_hash = ?", (session_hash,))

        await state.db.run(forget)
    response = _back("logged_out")
    response.delete_cookie(COOKIE, path="/admin")
    return response


@router.post("/maintenance/{switch}")
async def form_maintenance(
    switch: Literal["on", "off"], request: Request, state: State
) -> Response:
    form = await _form(request)
    try:
        if await _form_admin(request, state, form) is None:
            return _login_page("Log in first.", status=401)
        code = await set_maintenance(state, switch == "on", form.get("message"))
    except AdminError as e:
        code = e.code
    return _back(code)


@router.post("/vaults/{vault_id}/grace")
async def form_grace(vault_id: str, request: Request, state: State) -> Response:
    form = await _form(request)
    try:
        if await _form_admin(request, state, form) is None:
            return _login_page("Log in first.", status=401)
        hours = form.get("hours", "").strip()
        if hours and not hours.isdigit():
            raise AdminError("bad_grace")
        code = await set_grace(state, vault_id, int(hours) * 3600 if hours else None)
    except AdminError as e:
        code = e.code
    return _back(code)


@router.post("/vaults/{vault_id}/quota")
async def form_quota(vault_id: str, request: Request, state: State) -> Response:
    form = await _form(request)
    try:
        if await _form_admin(request, state, form) is None:
            return _login_page("Log in first.", status=401)
        gb = form.get("gb", "").strip()
        if gb and (not gb.isdigit() or len(gb) > 9):
            raise AdminError("bad_quota")
        code = await set_quota(state, vault_id, int(gb) * GB if gb else None)
    except AdminError as e:
        code = e.code
    return _back(code)


@router.post("/{kind}/{item_id}/{action}")
async def form_action(
    kind: Kind, item_id: str, action: Action, request: Request, state: State
) -> Response:
    form = await _form(request)
    try:
        if await _form_admin(request, state, form) is None:
            return _login_page("Log in first.", status=401)
        code = await act(state, kind, item_id, action, form.get("confirm", "").strip())
    except AdminError as e:
        code = e.code
    return _back(code)
