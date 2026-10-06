"""The admin page and API (protocol.md 14).

Everything needs `ADMIN_TOKEN`: as `Authorization: Bearer <token>`, or entered once in the
login form, which starts a browser session (an HttpOnly cookie, plus a CSRF token in every
form). The page lists users, their vaults with stored sizes, and each vault's devices (one
encryption key each). Users and vaults can be disabled (no access, data kept), enabled
again, and purged once disabled. Purging a vault also deletes its devices.
Maintenance mode pauses the whole sync API until it is turned off (protocol.md 14.1).
"""

import hashlib
import hmac
import html
import logging
import secrets
import sqlite3
from dataclasses import dataclass
from typing import Annotated, Literal
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field

from syncryption_server import PROTOCOL_VERSION, __version__
from syncryption_server.auth import client_ip, limit_key, request_origin
from syncryption_server.config import MAX_NOTE, note_problem
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
}
# Codes that aren't errors, shown in green.
SUCCESS = ("disabled", "enabled", "purged", "logged_out", "maintenance_on", "maintenance_off")


# Authentication


@dataclass(frozen=True)
class Admin:
    # The browser session's CSRF token; None for Bearer requests, which need none.
    csrf: str | None
    session_hash: str | None = None


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
    state.limiter.check(key, *FAILURE_LIMIT)
    return False


def _bearer(request: Request) -> str | None:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token.strip() else None


async def _admin(request: Request, state: AppState) -> Admin | None:
    """The Bearer token, else the session cookie. None when neither is valid."""
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
    token = _bearer(request)
    if token is None or not check_token(request, state, token):
        raise ApiError(401, "unauthenticated", "Send the admin token as a Bearer token.")
    return Admin(csrf=None)


ApiAdmin = Annotated[Admin, Depends(api_admin)]


# Data


def overview(state: AppState) -> list[dict]:
    users = state.db.all("SELECT * FROM users ORDER BY username")
    vaults = state.db.all(
        "SELECT v.id, v.user_id, v.name, v.created_at, v.disabled_at, "
        "(SELECT COALESCE(SUM(size), 0) FROM blobs b WHERE b.vault_id = v.id) AS size, "
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
        for vault_id in await state.db.read(lambda: _vault_ids(state, kind, item_id)):
            await _purge_vault(state, item_id, vault_id)

        def forget() -> None:
            with state.db.transaction() as db:
                # Keys that were creating a vault, the only devices left.
                _delete_devices(db, "user_id = ?", item_id)
                db.execute("DELETE FROM challenges WHERE username = ?", (row["name"],))
                db.execute("DELETE FROM users WHERE id = ?", (item_id,))

        await state.db.run(forget)
    log.info("admin: purged %s", label)
    return "purged"


async def set_maintenance(state: AppState, on: bool, message: str | None = None) -> str:
    """Turn maintenance on (or update its message) or off. Returns the message code."""
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


class PurgeRequest(BaseModel):
    confirm: str = Field(max_length=64, description="The username or vault name, to confirm.")


@router.get("/api/users")
async def api_users(admin: ApiAdmin, state: State) -> dict:
    return {"users": await state.db.read(lambda: overview(state))}


class MaintenanceRequest(BaseModel):
    message: str | None = Field(None, max_length=MAX_NOTE, description="Shown to users.")


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
        raise bad_request(MESSAGES[e.code]) from e
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
section { border: 1px solid #ccc; border-radius: 6px; padding: 1rem; margin: 1rem 0; }
section.disabled { background: #f6f0f0; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0; }
th, td {
  text-align: left;
  padding: .25rem .5rem;
  border-bottom: 1px solid #eee;
  vertical-align: top;
}
td.num { text-align: right; }
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
"""


def _size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def _when(value: str | None) -> str:
    return html.escape(value.replace("T", " ").replace("Z", " UTC")) if value else "never"


def html_page(body: str, status: int = 200, title: str = "Vault Syncryption admin") -> HTMLResponse:
    """A page with the admin style and strict headers. Also used for the `/` page."""
    doc = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>{STYLE}</style></head>"
        f"<body>{body}</body></html>"
    )
    return HTMLResponse(
        doc,
        status_code=status,
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
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
        "<h1>Vault Syncryption admin</h1>"
        f"{notice}"
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
    if not item["disabled"]:
        return _button(admin, kind, item, "disable", name)
    return (
        _button(admin, kind, item, "enable", name) + " " + _button(admin, kind, item, "purge", name)
    )


def _maintenance_section(admin: Admin, state: AppState) -> str:
    csrf = f'<input type="hidden" name="csrf" value="{html.escape(admin.csrf or "")}">'
    m = state.maintenance
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


def _dashboard(
    admin: Admin, state: AppState, users: list[dict], message: str | None, error: bool
) -> HTMLResponse:
    total = sum(v["size"] for u in users for v in u["vaults"])
    logout = (
        '<form method="post" action="/admin/logout">'
        f'<input type="hidden" name="csrf" value="{html.escape(admin.csrf)}">'
        "<button>Log out</button></form>"
        if admin.csrf
        else ""
    )
    parts = [f"<header><h1>Vault Syncryption admin</h1>{logout}</header>"]
    if message:
        parts.append(f'<p class="notice{" error" if error else ""}">{html.escape(message)}</p>')
    parts.append(_maintenance_section(admin, state))
    parts.append(
        f'<p class="muted">{len(users)} users, {sum(len(u["vaults"]) for u in users)} vaults, '
        f"{_size(total)} stored. Stored size counts history and deleted files still kept. "
        f"The server keeps every version for {KEEP_DAYS} days, at least the last "
        f"{KEEP_VERSIONS} of each file, and deleted files for {DELETED_DAYS} days; the copies "
        f"a key change leaves behind go after {OLD_EPOCH_DAYS} days. Older versions are "
        "removed automatically. "
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
        if u["vaults"]:
            parts.append(
                "<table><tr><th>Vault</th><th>Stored</th><th>Files</th><th>Versions</th>"
                "<th>Created</th>"
                "<th>Last change</th><th></th></tr>"
            )
            for v in u["vaults"]:
                vtag = ' <span class="tag">disabled</span>' if v["disabled"] else ""
                parts.append(
                    f"<tr><td>{html.escape(v['name'])}{vtag}</td>"
                    f'<td class="num">{_size(v["size"])}</td><td class="num">{v["files"]}</td>'
                    f'<td class="num">{v["revisions"]}</td>'
                    f"<td>{_when(v['createdAt'])}</td><td>{_when(v['lastChangeAt'])}</td>"
                    f"<td>{_actions(admin, 'vaults', v, v['name'])}</td></tr>"
                )
            parts.append("</table>")
        else:
            parts.append('<p class="muted">No vaults.</p>')
        rows = [(v["name"], d) for v in u["vaults"] for d in v["devices"]]
        rows += [(f"{c['vaultName']} (being created)", c["device"]) for c in u["creating"]]
        if rows:
            parts.append(
                "<table><tr><th>Device</th><th>Vault</th><th>Key</th><th>Status</th>"
                "<th>Joined</th><th>Last seen</th></tr>"
            )
            for vault, d in rows:
                parts.append(
                    f"<tr><td>{html.escape(d['name'])}</td><td>{html.escape(vault)}</td>"
                    f'<td class="muted">{html.escape(d["fingerprint"])}</td>'
                    f"<td>{html.escape(d['status'])}</td>"
                    f"<td>{_when(d['createdAt'])}</td><td>{_when(d['lastSeenAt'])}</td></tr>"
                )
            parts.append("</table>")
        parts.append("</section>")
    if not users:
        parts.append('<p class="muted">No users yet.</p>')
    return html_page("".join(parts))


async def _form(request: Request) -> dict[str, str]:
    fields = parse_qs((await request.body()).decode("utf-8", "replace"), keep_blank_values=True)
    return {k: v[0] for k, v in fields.items()}


def _back(code: str) -> RedirectResponse:
    return RedirectResponse(f"/admin?done={code}", status_code=303)


@router.get("")
async def page(request: Request, state: State, done: str = "") -> Response:
    admin = await _admin(request, state)
    if admin is None:
        if done == "logged_out":
            return _login_page(MESSAGES[done], error=False)
        return _login_page(status=401 if _bearer(request) else 200)
    message = MESSAGES.get(done)
    error = done not in SUCCESS
    users = await state.db.read(lambda: overview(state))
    return _dashboard(admin, state, users, message, error)


@router.post("/login")
async def login(request: Request, state: State) -> Response:
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
        secure=request_origin(request, state).startswith("https:"),
        samesite="strict",
    )
    return response


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
