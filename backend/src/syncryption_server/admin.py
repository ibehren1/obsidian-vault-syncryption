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
The Network tab graphs the traffic network monitoring records and deletes old data
(protocol.md 14.4). The Billing tab estimates each month's AWS cost per user and vault
(protocol.md 14.5).
"""

import base64
import hashlib
import hmac
import html
import logging
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import parse_qs, urlsplit

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from syncryption_server import PROTOCOL_VERSION, __version__, billing, metrics, netmon
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
NETWORK_JS = (Path(__file__).parent / "static" / "admin-network.js").read_bytes()
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
    "netmon_pruned": "Old monitoring data deleted. The hourly totals for billing are kept.",
    "netmon_auto": "Automatic deletion saved. It runs every hour.",
    "bad_days": f"Days is a whole number from 0 to {netmon.MAX_DAYS} (from 1 for automatic "
    "deletion, or empty to turn it off).",
    "bad_filter": "Unknown filter.",
    "bad_tz": "Unknown time zone.",
    "rates_set": "Rates saved. They apply to the current month and later ones.",
    "bad_rate": f"Each rate is a number of dollars from 0 to {billing.MAX_RATE:g}.",
    "bad_month": "Unknown month: use YYYY-MM, not in the future.",
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
    "netmon_pruned",
    "netmon_auto",
    "rates_set",
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


class NetworkRequest(BaseModel):
    autoPruneDays: int | None = Field(
        None, description=f"Delete data older than this many days (1 to {netmon.MAX_DAYS})."
    )
    clearAutoPrune: bool = Field(False, description="Turn automatic deletion off.")


class PruneRequest(BaseModel):
    olderThanDays: int = Field(description=f"0 (everything) to {netmon.MAX_DAYS}.")


def _netmon_error(e: netmon.NetmonError) -> ApiError:
    return bad_request(MESSAGES[e.code])


async def set_network(state: AppState, days: int | None, clear: bool):
    """Set or clear the automatic deletion; read-only on a demo server."""
    if state.settings.demo_mode:
        raise AdminError("demo", 403)
    if days is not None or clear:
        await state.netmon.set_auto_prune(None if clear else days)


async def prune_network(state: AppState, days: int) -> int:
    if state.settings.demo_mode:
        raise AdminError("demo", 403)
    return await state.netmon.prune(days)


async def network_traffic(
    state: AppState, group: str, filter_key: str | None, start: int | None, end: int | None
) -> dict:
    if group not in netmon.GROUPS:
        raise netmon.NetmonError("bad_filter")
    data = await state.netmon.traffic(group, filter_key or None, start, end)  # type: ignore[arg-type]
    return {"status": await state.netmon.status(), **data}


async def network_totals(
    state: AppState, group: str, filter_key: str | None, period: str, tz: str, before: int | None
) -> dict:
    if group not in netmon.GROUPS or period not in ("hour", "day", "week", "month"):
        raise netmon.NetmonError("bad_filter")
    return await state.netmon.period_totals(group, filter_key or None, period, tz, before)  # type: ignore[arg-type]


@router.get("/api/network")
async def api_network(admin: ApiAdmin, state: State) -> dict:
    """Network monitoring: its settings, and the size and span of its data."""
    return await state.netmon.status()


@router.post("/api/network", status_code=204)
async def api_network_set(body: NetworkRequest, admin: ApiAdmin, state: State) -> Response:
    """Set or clear the automatic deletion of network monitoring data."""
    try:
        await set_network(state, body.autoPruneDays, body.clearAutoPrune)
    except AdminError as e:
        raise _api_error(e) from e
    except netmon.NetmonError as e:
        raise _netmon_error(e) from e
    return Response(status_code=204)


@router.post("/api/network/prune")
async def api_network_prune(body: PruneRequest, admin: ApiAdmin, state: State) -> dict:
    """Delete the monitoring data older than `olderThanDays` days."""
    try:
        return {"deletedRows": await prune_network(state, body.olderThanDays)}
    except AdminError as e:
        raise _api_error(e) from e
    except netmon.NetmonError as e:
        raise _netmon_error(e) from e


@router.get("/api/network/traffic")
async def api_network_traffic(
    admin: ApiAdmin,
    state: State,
    group: str = "device",
    filter: str = "",
    start: int | None = None,
    end: int | None = None,
) -> dict:
    """The Network tab's graphs, range totals and summary (protocol.md 14.4)."""
    try:
        return await network_traffic(state, group, filter, start, end)
    except netmon.NetmonError as e:
        raise _netmon_error(e) from e


@router.get("/api/network/totals")
async def api_network_totals(
    admin: ApiAdmin,
    state: State,
    group: str = "device",
    filter: str = "",
    period: str = "day",
    tz: str = "UTC",
    before: int | None = None,
) -> dict:
    """The Network tab's totals per hour, day, week or month (protocol.md 14.4)."""
    try:
        return await network_totals(state, group, filter, period, tz, before)
    except netmon.NetmonError as e:
        raise _netmon_error(e) from e


class RatesRequest(BaseModel):
    transferPerGb: float = Field(description="Dollars per GB (2^30 bytes) sent to clients.")
    localPerGbMonth: float = Field(description="Dollars per GB-month on the server's disk.")
    s3PerGbMonth: float = Field(description="Dollars per GB-month in S3.")


def _billing_error(e: billing.BillingError) -> ApiError:
    return bad_request(MESSAGES[e.code])


async def set_rates(state: AppState, rates: billing.Rates) -> None:
    if state.settings.demo_mode:
        raise AdminError("demo", 403)
    await billing.set_rates(state, rates)


@router.get("/api/billing")
async def api_billing(admin: ApiAdmin, state: State, month: str = "") -> dict:
    """One month's estimated costs per user and vault (protocol.md 14.5)."""
    try:
        return await billing.month_report(state, month or billing.month_of(state.now()))
    except billing.BillingError as e:
        raise _billing_error(e) from e


@router.get("/api/billing/months")
async def api_billing_months(admin: ApiAdmin, state: State) -> dict:
    """Every month with data, newest first, with its totals, and the current rates."""
    rates = await state.db.read(lambda: billing.rates_at(state.db, state.now()))
    return {"months": await billing.months(state), "rates": rates.json()}


@router.post("/api/billing/rates", status_code=204)
async def api_billing_rates(body: RatesRequest, admin: ApiAdmin, state: State) -> Response:
    """Set the rates, from now on: the current month is billed at them, past months aren't."""
    try:
        await set_rates(
            state, billing.Rates(body.transferPerGb, body.localPerGbMonth, body.s3PerGbMonth)
        )
    except AdminError as e:
        raise _api_error(e) from e
    except billing.BillingError as e:
        raise _billing_error(e) from e
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
/* The Network tab. */
.tag.on { background: #2b8a3e; }
.forms { display: flex; flex-direction: column; gap: .5rem; }
.filters { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem 1.5rem; }
.chart { position: relative; }
.chart svg { display: block; width: 100%; height: auto; }
.chart .axis { font-size: 11px; fill: #777; }
.chart .grid { stroke: #eceeef; }
.chart .base { stroke: #b9bcbf; }
.chart .gap { fill: #e6e7e3; }
.charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(26rem, 1fr)); gap: 0 1rem; }
.chart .cross { stroke: #2d2f31; stroke-width: 1; }
.chart .empty { font-size: 13px; fill: #777; }
.legend { display: flex; flex-wrap: wrap; gap: .25rem 1rem; margin: .5rem 0; }
.key { display: inline-flex; align-items: center; gap: .35rem; }
.swatch { display: inline-block; width: .75rem; height: .75rem; border-radius: 3px; }
.legend .gapkey { background: #e6e7e3; border: 1px solid #d5d7d9; }
table.pick tbody tr { cursor: pointer; }
table.pick tbody tr:hover { background: #f5f8f3; }
tr.sub td { color: #555; font-size: .9rem; }
tr.sub td:first-child { padding-left: 1.5rem; }
.tooltip {
  position: fixed;
  z-index: 10;
  pointer-events: none;
  background: #fff;
  border: 1px solid #d5d7d9;
  border-radius: 6px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, .12);
  padding: .4rem .6rem;
  font-size: .85rem;
  max-width: 24rem;
}
.tooltip .row { display: flex; align-items: center; gap: .4rem; }
.tooltip .row .v { margin-left: auto; padding-left: 1rem; font-variant-numeric: tabular-nums; }
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
            ("network", "Network", "/admin?tab=network"),
            ("billing", "Billing", "/admin?tab=billing"),
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


def _when_unix(t: int | None) -> str:
    return _when(rfc3339(t)) if t is not None else "never"


def _network_controls(admin: Admin, status: dict) -> str:
    """Since when it records, the space its data takes, and the deletion forms."""
    state_line = (
        f"Recording since {_when_unix(status['since'])}, when the server started: every "
        "request's bytes on the web port and every S3 call's bytes, per device, per minute. "
    )
    if status["rows"]:
        data = (
            f"Data from {_when_unix(status['oldest'])} to {_when_unix(status['newest'])}: "
            f"{status['rows']:,} rows, {_size(status['bytes'])} in netmon.db on the data disk."
        )
    elif status["bytes"]:
        data = f"No data yet; netmon.db takes {_size(status['bytes'])}."
    else:
        data = "No data."
    auto = status["autoPruneDays"]
    auto_line = (
        f"Data older than {auto} days is deleted automatically every hour."
        if auto
        else "Data is kept until you delete it."
    )
    parts = [
        '<section class="stripe"><h2>Network monitoring</h2>',
        f'<p>{state_line}<span class="muted">{data} {auto_line}</span></p>',
    ]
    if not admin.read_only:
        csrf = f'<input type="hidden" name="csrf" value="{html.escape(admin.csrf or "")}">'
        parts.append('<div class="forms">')
        if status["rows"] or status["bytes"]:
            parts.append(
                f'<form method="post" action="/admin/network/prune">{csrf}'
                '<label>Delete data older than <input name="days" size="4" '
                'inputmode="numeric" required aria-label="Days"> days</label> '
                '<button class="danger">Delete</button> '
                '<span class="muted">(0 deletes everything; the hourly totals for billing '
                "stay)</span></form>"
                f'<form method="post" action="/admin/network/auto-prune">{csrf}'
                '<label>Delete data older than <input name="days" size="4" '
                f'inputmode="numeric" value="{auto or ""}" placeholder="never" '
                'aria-label="Days"> days automatically</label> <button>Save</button></form>'
            )
        parts.append("</div>")
    parts.append("</section>")
    return "".join(parts)


def _network(admin: Admin, status: dict, message: str | None, error: bool) -> HTMLResponse:
    """The Network tab. The graphs and tables are filled in by admin-network.js."""
    notice = (
        f'<p class="notice{" error" if error else ""}">{html.escape(message)}</p>'
        if message
        else ""
    )
    ranges = "".join(
        f'<option value="{v}"{" selected" if v == "86400" else ""}>{label}</option>'
        for v, label in (
            ("3600", "Last hour"),
            ("21600", "Last 6 hours"),
            ("86400", "Last 24 hours"),
            ("604800", "Last 7 days"),
            ("2592000", "Last 30 days"),
            ("all", "All monitored time"),
        )
    )
    groups = (
        '<option value="device" selected>Device</option><option value="vault">Vault</option>'
        '<option value="user">User</option><option value="client">Client</option>'
    )
    toolbar = (
        '<div class="toolbar"><div class="filters">'
        f'<label>Range <select id="range">{ranges}</select></label>'
        f'<label>Group by <select id="groupby">{groups}</select></label>'
        '<span id="filter" hidden>Only <b id="filter-label"></b> '
        '<button id="filter-clear" type="button">Show all</button></span></div>'
        '<span class="muted" id="updated">Loading…</span></div>'
    )
    fields = (
        '<th class="num">Web in</th><th class="num">Web out</th><th class="num">Requests</th>'
        '<th class="num">S3 in</th><th class="num">S3 out</th><th class="num">S3 calls</th>'
    )
    summary = (
        '<section class="stripe"><h2>Totals <span class="muted" id="summary-scope"></span>'
        f"</h2><table><thead><tr><th>Period</th>{fields}</tr></thead>"
        '<tbody id="summary"></tbody></table></section>'
    )
    charts = "".join(
        f'<section class="stripe chart-card"><h2>{title} <span class="muted">{note}</span></h2>'
        f'<div class="chart" id="chart-{key}"></div></section>'
        for key, title, note in (
            ("web_in", "Web in", "(received from clients, per second)"),
            ("web_out", "Web out", "(sent to clients, per second)"),
            ("s3_in", "S3 in", "(downloaded from the bucket, per second)"),
            ("s3_out", "S3 out", "(uploaded to the bucket, per second)"),
        )
    )
    legend = '<div class="legend" id="legend"></div>'
    table = (
        '<section class="stripe"><h2>By <span id="group-name">device</span> '
        '<span class="muted">(selected range, busiest first; click a row to show only it)</span>'
        f'</h2><table class="pick"><thead><tr><th>Name</th><th>Client</th>{fields}</tr>'
        '</thead><tbody id="groups"></tbody></table></section>'
    )
    periods = (
        '<section class="stripe"><h2>Totals by period</h2><div class="toolbar">'
        '<label>Period <select id="period"><option value="hour">Hour</option>'
        '<option value="day" selected>Day</option><option value="week">Week</option>'
        '<option value="month">Month</option></select></label>'
        '<span class="muted" id="tz"></span></div>'
        f'<table class="pick"><thead><tr><th>Period</th>{fields}<th>Busiest</th></tr></thead>'
        '<tbody id="periods"></tbody></table>'
        '<p><button id="older" type="button" hidden>Older</button></p></section>'
    )
    body = (
        _header(admin, "network")
        + notice
        + _network_controls(admin, status)
        + '<noscript><p class="notice error">The graphs need JavaScript. The same data is in '
        "GET /admin/api/network/traffic and /admin/api/network/totals.</p></noscript>"
        + toolbar
        + summary
        + legend
        + f'<div class="charts">{charts}</div>'
        + table
        + periods
        + '<div class="tooltip" id="tooltip" hidden></div>'
    )
    return html_page(body, script="/admin/network.js")


def _usd(x: float) -> str:
    if x == 0:
        return "$0.00"
    if x < 0.01:
        return "&lt;$0.01"
    return f"${x:,.2f}"


def _gb_months(x: float) -> str:
    return f"{x:,.3f}" if x else "0"


def _cost_cells(line: dict) -> str:
    return (
        f'<td class="num">{_size(line["transferBytes"])}</td>'
        f'<td class="num">{_usd(line["transferCost"])}</td>'
        f'<td class="num">{_gb_months(line["localGbMonths"])}</td>'
        f'<td class="num">{_gb_months(line["s3GbMonths"])}</td>'
        f'<td class="num">{_usd(line["storageCost"])}</td>'
        f'<td class="num"><b>{_usd(line["total"])}</b></td>'
    )


COST_HEADERS = (
    '<th class="num">Outbound</th><th class="num">Transfer</th>'
    '<th class="num">Disk GB-months</th><th class="num">S3 GB-months</th>'
    '<th class="num">Storage</th><th class="num">Total</th>'
)


def _month_name(month: str) -> str:
    return datetime.strptime(month, "%Y-%m").strftime("%B %Y")


def _billing(
    admin: Admin,
    rates: dict,
    months: list[dict],
    report: dict | None,
    message: str | None,
    error: bool,
) -> HTMLResponse:
    """The Billing tab: the rates, every month's total, and one month per user and vault."""
    parts = [_header(admin, "billing")]
    if message:
        parts.append(f'<p class="notice{" error" if error else ""}">{html.escape(message)}</p>')
    explain = (
        "Estimated AWS cost per calendar month (UTC): outbound transfer to clients per GB, "
        "and each vault's stored blobs per GB-month, on the server's disk (EBS) or in S3, "
        "sampled every hour. Traffic to and from S3 isn't charged. A GB is 2^30 bytes. "
        "Traffic without a vault (logins, /health, the admin page, /metrics) and the "
        "server's own files (meta.db, netmon.db, certificates) are the server's line. A "
        "month is billed at the rates in force at its end."
    )
    fields = (
        ("transferPerGb", "Transfer out", "per GB"),
        ("localPerGbMonth", "Disk (EBS)", "per GB-month"),
        ("s3PerGbMonth", "S3", "per GB-month"),
    )
    if admin.read_only:
        form = " · ".join(f"{label} ${rates[k]:g} {unit}" for k, label, unit in fields)
    else:
        csrf = f'<input type="hidden" name="csrf" value="{html.escape(admin.csrf or "")}">'
        inputs = " ".join(
            f'<label>{label} $<input name="{k}" size="7" inputmode="decimal" '
            f'value="{rates[k]:g}" required> {unit}</label>'
            for k, label, unit in fields
        )
        form = (
            f'<form method="post" action="/admin/billing/rates">{csrf}{inputs} '
            "<button>Save</button></form>"
        )
    parts.append(
        f'<section class="stripe"><h2>Rates</h2><p class="muted">{explain}</p>{form}</section>'
    )
    rows = []
    for m in months:
        selected = report is not None and m["month"] == report["month"]
        name = html.escape(_month_name(m["month"])) + (" (so far)" if m["current"] else "")
        link = f'<a href="/admin?tab=billing&amp;month={m["month"]}">{name}</a>'
        rows.append(f"<tr><td>{f'<b>{link}</b>' if selected else link}</td>{_cost_cells(m)}</tr>")
    if not rows:
        rows.append('<tr><td colspan="7" class="muted">No data yet.</td></tr>')
    parts.append(
        '<section class="stripe"><h2>Months</h2>'
        f"<table><thead><tr><th>Month</th>{COST_HEADERS}</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></section>"
    )
    if report is not None:
        parts.append(_billing_month(report))
    return html_page("".join(parts))


def _billing_month(r: dict) -> str:
    title = html.escape(_month_name(r["month"])) + (" (so far)" if r["current"] else "")
    elapsed = r["elapsedSeconds"]
    share = r["monitoredSeconds"] / elapsed if elapsed else 0
    coverage = (
        f"Transfer was recorded for {share:.0%} of the month"
        + (" so far" if r["current"] else "")
        + " (while the server ran)."
        if share < 0.995
        else "Transfer was recorded for the whole month" + (" so far." if r["current"] else ".")
    )
    rates = r["rates"]
    rows = []
    for u in r["users"]:
        rows.append(f"<tr><td><b>{html.escape(u['username'])}</b></td>{_cost_cells(u)}</tr>")
        rows.extend(
            f'<tr class="sub"><td>{html.escape(v["vaultName"])}</td>{_cost_cells(v)}</tr>'
            for v in u["vaults"]
        )
    rows.append(
        '<tr><td><b>Server</b> <span class="muted">(no vault)</span></td>'
        f"{_cost_cells(r['server'])}</tr>"
    )
    rows.append(f"<tr><td><b>Total</b></td>{_cost_cells(r['total'])}</tr>")
    return (
        f'<section class="stripe"><h2>{title}</h2>'
        f'<p class="muted">{coverage} Rates: ${rates["transferPerGb"]:g} per GB out, '
        f"${rates['localPerGbMonth']:g} per GB-month on disk, ${rates['s3PerGbMonth']:g} per "
        "GB-month in S3. Each user's line adds up their vaults.</p>"
        f"<table><thead><tr><th>User / vault</th>{COST_HEADERS}</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></section>"
    )


async def _form(request: Request) -> dict[str, str]:
    fields = parse_qs((await request.body()).decode("utf-8", "replace"), keep_blank_values=True)
    return {k: v[0] for k, v in fields.items()}


def _back(code: str, tab: str | None = None) -> RedirectResponse:
    to = f"/admin?tab={tab}&done={code}" if tab else f"/admin?done={code}"
    return RedirectResponse(to, status_code=303)


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
    if tab == "network":
        return _network(admin, await state.netmon.status(), message, error)
    if tab == "billing":
        return await _billing_tab(request, admin, state, message, error)
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


async def _billing_tab(
    request: Request, admin: Admin, state: AppState, message: str | None, error: bool
) -> HTMLResponse:
    month = request.query_params.get("month") or billing.month_of(state.now())
    rates = await state.db.read(lambda: billing.rates_at(state.db, state.now()))
    months = await billing.months(state)
    try:
        report = await billing.month_report(state, month)
    except billing.BillingError as e:
        report, message, error = None, MESSAGES[e.code], True
    return _billing(admin, rates.json(), months, report, message, error)


def _query_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    if not value.lstrip("-").isdigit() or len(value) > 12:
        raise netmon.NetmonError("bad_filter")
    return int(value)


@router.get("/network.json")
async def network_json(request: Request, state: State) -> Response:
    """The Network tab's graphs and totals, with the session cookie (no CSRF: a GET)."""
    if await _admin(request, state) is None:
        raise ApiError(401, "unauthenticated", "Log in first.")
    q = request.query_params
    try:
        data = await network_traffic(
            state,
            q.get("group", "device"),
            q.get("filter"),
            _query_int(q.get("start")),
            _query_int(q.get("end")),
        )
    except netmon.NetmonError as e:
        raise _netmon_error(e) from e
    return JSONResponse(data, headers={"Cache-Control": "no-store"})


@router.get("/network-totals.json")
async def network_totals_json(request: Request, state: State) -> Response:
    """The Network tab's totals by period, with the session cookie (no CSRF: a GET)."""
    if await _admin(request, state) is None:
        raise ApiError(401, "unauthenticated", "Log in first.")
    q = request.query_params
    try:
        data = await network_totals(
            state,
            q.get("group", "device"),
            q.get("filter"),
            q.get("period", "day"),
            q.get("tz", "UTC"),
            _query_int(q.get("before")),
        )
    except netmon.NetmonError as e:
        raise _netmon_error(e) from e
    return JSONResponse(data, headers={"Cache-Control": "no-store"})


@router.get("/network.js")
async def network_js() -> Response:
    """The Network tab's script. Static, so it needs no login."""
    return Response(
        NETWORK_JS,
        media_type="text/javascript",
        headers={"Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff"},
    )


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


@router.post("/network/{action}")
async def form_network(
    action: Literal["prune", "auto-prune"], request: Request, state: State
) -> Response:
    form = await _form(request)
    try:
        if await _form_admin(request, state, form) is None:
            return _login_page("Log in first.", status=401)
        days = form.get("days", "").strip()
        if days and (not days.isdigit() or len(days) > 5):
            raise netmon.NetmonError("bad_days")
        if action == "prune":
            if not days:
                raise netmon.NetmonError("bad_days")
            await prune_network(state, int(days))
            code = "netmon_pruned"
        else:
            await set_network(state, int(days) if days else None, not days)
            code = "netmon_auto"
    except AdminError as e:
        code = e.code
    except netmon.NetmonError as e:
        code = e.code
    return _back(code, "network")


@router.post("/billing/rates")
async def form_billing_rates(request: Request, state: State) -> Response:
    form = await _form(request)
    try:
        if await _form_admin(request, state, form) is None:
            return _login_page("Log in first.", status=401)
        try:
            rates = billing.Rates(
                *(
                    float(form.get(k, "").strip())
                    for k in ("transferPerGb", "localPerGbMonth", "s3PerGbMonth")
                )
            )
        except ValueError as e:
            raise billing.BillingError("bad_rate") from e
        await set_rates(state, rates)
        code = "rates_set"
    except AdminError as e:
        code = e.code
    except billing.BillingError as e:
        code = e.code
    return _back(code, "billing")


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
