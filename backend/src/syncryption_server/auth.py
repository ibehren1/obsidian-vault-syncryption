"""Login and joining (docs/protocol.md 4 and 5): sshsig challenges and session tokens."""

import hashlib
import hmac
import ipaddress
import logging
import re
import secrets
import sqlite3
import uuid
from dataclasses import dataclass
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from syncryption_server.encoding import b64u, from_b64u, new_device_id, rfc3339
from syncryption_server.errors import ApiError, bad_request, user_disabled
from syncryption_server.sshkeys import (
    NAMESPACE_AUTH,
    KeyFormatError,
    SshSigError,
    fingerprint,
    parse_public_key,
    public_key_text,
    verify_sshsig,
)
from syncryption_server.state import AppState, get_state

CHALLENGE_TTL = 60
SESSION_TTL = 3600
PENDING_DEVICE_TTL = 24 * 3600
MAX_PENDING_DEVICES = 5
AUTH_LIMIT = (10, 60.0)  # per client address
JOIN_FAILURE_LIMIT = (5, 3600)  # wrong shared secrets per client address
JOIN_FAILURE_TOTAL = (50, 3600)  # wrong shared secrets from all addresses together
LAST_SEEN_RESOLUTION = 60

USERNAME_RE = re.compile(r"^[a-z0-9._-]{1,32}$")
JOIN_MESSAGE = "This server needs an access secret to join. Contact your administrator."

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
log = logging.getLogger(__name__)


class ChallengeRequest(BaseModel):
    username: str
    publicKey: str


class ChallengeResponse(BaseModel):
    challengeId: str
    message: str
    expiresAt: str


class VerifyRequest(BaseModel):
    challengeId: str = Field(max_length=64)
    signature: str = Field(max_length=4096)
    deviceName: str = Field(default="Device", max_length=64)
    sharedSecret: str | None = Field(default=None, max_length=1024)


class VerifyResponse(BaseModel):
    token: str
    expiresAt: str
    deviceId: str
    status: Literal["active", "pending"]
    created: bool


def client_ip(request: Request, state: AppState) -> str:
    if state.settings.behind_proxy:
        forwarded = request.headers.get("x-forwarded-for", "")
        # The last entry is the one our proxy added; earlier ones are client supplied.
        last = forwarded.split(",")[-1].strip()
        if last:
            return last
    return request.client.host if request.client else "unknown"


def limit_key(ip: str) -> str:
    """The address rate limits count against: IPv6 clients by their /64, as one host gets a
    whole /64 and could otherwise pick a new address for every request."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(ipaddress.IPv6Network((addr, 64), strict=False))
    return str(addr)


def request_origin(request: Request, state: AppState) -> str:
    if state.settings.url:
        return state.settings.url
    scheme = request.url.scheme
    host = request.headers.get("host", request.url.netloc)
    if state.settings.behind_proxy:
        scheme = request.headers.get("x-forwarded-proto", scheme).split(",")[0].strip()
        host = request.headers.get("x-forwarded-host", host).split(",")[0].strip()
    return f"{scheme}://{host.lower()}"


def limit_auth(state: AppState, ip: str) -> None:
    # Per address only: a per-username limit would let anyone who knows a username lock
    # its devices out (sessions last an hour), and sshsig can't be guessed anyway.
    state.limiter.check(f"auth-ip:{limit_key(ip)}", *AUTH_LIMIT)


def sweep_expired(state: AppState) -> None:
    """Drop expired challenges, sessions and unapproved pending devices."""
    now = state.now()
    with state.db.transaction() as db:
        db.execute("DELETE FROM challenges WHERE expires_at < ?", (now - CHALLENGE_TTL,))
        db.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        db.execute(
            "DELETE FROM devices WHERE status = 'pending' AND created_at <= ? "
            "AND id NOT IN (SELECT signer FROM keyrings) "
            "AND id NOT IN (SELECT device_id FROM revisions)",
            (now - PENDING_DEVICE_TTL,),
        )
        db.execute("DELETE FROM join_attempts WHERE at <= ?", (now - JOIN_FAILURE_LIMIT[1],))


@router.post("/challenge")
async def challenge(
    body: ChallengeRequest,
    request: Request,
    state: Annotated[AppState, Depends(get_state)],
) -> ChallengeResponse:
    if not USERNAME_RE.match(body.username):
        raise bad_request("Usernames are 1 to 32 characters: a-z, 0-9, '.', '_' or '-'.")
    try:
        pk = parse_public_key(body.publicKey)
    except KeyFormatError as e:
        raise bad_request("Only Ed25519 SSH keys are supported.") from e
    limit_auth(state, client_ip(request, state))

    now = state.now()
    challenge_id = b64u(secrets.token_bytes(16))
    expires = now + CHALLENGE_TTL
    message = (
        f"{NAMESPACE_AUTH}\n"
        f"origin: {request_origin(request, state)}\n"
        f"username: {body.username}\n"
        f"key: {fingerprint(pk)}\n"
        f"nonce: {b64u(secrets.token_bytes(32))}\n"
        f"expires: {rfc3339(expires)}\n"
    )
    with state.db.transaction() as db:
        db.execute(
            "INSERT INTO challenges (id, username, public_key, message, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (challenge_id, body.username, public_key_text(pk), message, expires),
        )
    return ChallengeResponse(challengeId=challenge_id, message=message, expiresAt=rfc3339(expires))


def _invalid() -> ApiError:
    return ApiError(401, "challenge_invalid", "The login challenge is invalid or expired.")


def _secret_ok(state: AppState, ip: str, secret: str | None) -> bool:
    """Check the shared secret, counting wrong guesses per address and in total (protocol.md 12)."""
    limit, window = JOIN_FAILURE_LIMIT
    total, _ = JOIN_FAILURE_TOTAL
    now = state.now()
    failures = state.db.one(
        "SELECT COUNT(*) FROM join_attempts WHERE ip = ? AND at > ?", ip, now - window
    )[0]
    everyone = state.db.one("SELECT COUNT(*) FROM join_attempts WHERE at > ?", now - window)[0]
    if failures >= limit or everyone >= total:
        raise ApiError(
            429,
            "rate_limited",
            "Too many attempts. Try again later.",
            headers={"Retry-After": str(window)},
        )
    if not secret:
        return False
    expected = state.settings.shared_secret.encode()
    if hmac.compare_digest(secret.encode(), expected):
        return True
    with state.db.transaction() as db:
        db.execute("INSERT INTO join_attempts (ip, at) VALUES (?, ?)", (ip, now))
    if everyone + 1 >= total:
        log.warning("%d wrong shared secrets in the last hour; joining is paused", total)
    return False


@router.post("/verify")
async def verify(
    body: VerifyRequest,
    request: Request,
    state: Annotated[AppState, Depends(get_state)],
) -> VerifyResponse:
    ip = limit_key(client_ip(request, state))
    limit_auth(state, ip)
    sweep_expired(state)
    now = state.now()

    # 1. Single use: mark the challenge used whatever happens next.
    with state.db.transaction() as db:
        row = db.execute(
            "SELECT * FROM challenges WHERE id = ? AND used = 0 AND expires_at >= ?",
            (body.challengeId, now),
        ).fetchone()
        if row is not None:
            db.execute("UPDATE challenges SET used = 1 WHERE id = ?", (body.challengeId,))
    if row is None:
        raise _invalid()

    # 2 and 3. Signature by the challenged key, in the auth namespace.
    try:
        signer = verify_sshsig(body.signature, NAMESPACE_AUTH, row["message"].encode())
    except SshSigError as e:
        raise _invalid() from e
    key_text = row["public_key"]
    if public_key_text(signer) != key_text:
        raise _invalid()

    # 4. Log in or join.
    username = row["username"]
    name = body.deviceName.strip() or "Device"
    user = state.db.one("SELECT id, disabled_at FROM users WHERE username = ?", username)
    if user is not None and user["disabled_at"] is not None:
        raise user_disabled(state.settings.admin_contact)
    device = (
        state.db.one(
            "SELECT id, status FROM devices WHERE user_id = ? AND public_key = ?",
            user["id"],
            key_text,
        )
        if user
        else None
    )
    created = False
    if device is not None:
        if device["status"] == "revoked":
            raise ApiError(403, "device_revoked", "This device has been revoked.")
        device_id, status = device["id"], device["status"]
    else:
        if not _secret_ok(state, ip, body.sharedSecret):
            raise ApiError(403, "join_required", JOIN_MESSAGE)
        device_id = new_device_id()
        try:
            with state.db.transaction() as db:
                if user is None:
                    user_id, status = str(uuid.uuid4()), "active"
                    db.execute(
                        "INSERT INTO users (id, username, created_at) VALUES (?, ?, ?)",
                        (user_id, username, now),
                    )
                else:
                    user_id, status = user["id"], "pending"
                    pending = db.execute(
                        "SELECT COUNT(*) FROM devices WHERE user_id = ? AND status = 'pending'",
                        (user_id,),
                    ).fetchone()[0]
                    if pending >= MAX_PENDING_DEVICES:
                        raise ApiError(
                            429,
                            "rate_limited",
                            "Too many devices are waiting for approval.",
                            headers={"Retry-After": str(PENDING_DEVICE_TTL)},
                        )
                db.execute(
                    "INSERT INTO devices (id, user_id, public_key, name, status, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (device_id, user_id, key_text, name, status, now),
                )
        except sqlite3.IntegrityError as e:
            # A concurrent join created the same user or key first: log in again.
            raise _invalid() from e
        created = True

    token = secrets.token_bytes(32)
    expires = now + SESSION_TTL
    with state.db.transaction() as db:
        db.execute(
            "INSERT INTO sessions (token_hash, device_id, expires_at) VALUES (?, ?, ?)",
            (hashlib.sha256(token).hexdigest(), device_id, expires),
        )
        db.execute("UPDATE devices SET last_seen_at = ? WHERE id = ?", (now, device_id))
    return VerifyResponse(
        token=b64u(token),
        expiresAt=rfc3339(expires),
        deviceId=device_id,
        status=status,
        created=created,
    )


@dataclass(frozen=True)
class Caller:
    device_id: str
    user_id: str
    username: str
    public_key: str
    status: str


def _caller(request: Request, state: AppState) -> Caller:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise ApiError(401, "unauthenticated", "Log in first.")
    try:
        token_hash = hashlib.sha256(from_b64u(token.strip())).hexdigest()
    except ValueError as e:
        raise ApiError(401, "unauthenticated", "Log in first.") from e
    row = state.db.one(
        "SELECT s.expires_at, d.id, d.user_id, d.public_key, d.status, d.last_seen_at, "
        "u.username, u.disabled_at FROM sessions s JOIN devices d ON d.id = s.device_id "
        "JOIN users u ON u.id = d.user_id WHERE s.token_hash = ?",
        token_hash,
    )
    if row is None:
        raise ApiError(401, "unauthenticated", "Log in first.")
    now = state.now()
    if row["expires_at"] < now:
        raise ApiError(401, "token_expired", "The session has expired. Log in again.")
    if row["status"] == "revoked":
        raise ApiError(403, "device_revoked", "This device has been revoked.")
    if row["disabled_at"] is not None:
        raise user_disabled(state.settings.admin_contact)
    if (row["last_seen_at"] or 0) + LAST_SEEN_RESOLUTION <= now:
        with state.db.transaction() as db:
            db.execute("UPDATE devices SET last_seen_at = ? WHERE id = ?", (now, row["id"]))
    return Caller(row["id"], row["user_id"], row["username"], row["public_key"], row["status"])


async def any_caller(request: Request, state: Annotated[AppState, Depends(get_state)]) -> Caller:
    """A logged-in device, pending or active."""
    return _caller(request, state)


async def active_caller(request: Request, state: Annotated[AppState, Depends(get_state)]) -> Caller:
    caller = _caller(request, state)
    if caller.status != "active":
        raise ApiError(403, "device_pending", "This device is waiting for approval.")
    return caller


AnyCaller = Annotated[Caller, Depends(any_caller)]
ActiveCaller = Annotated[Caller, Depends(active_caller)]
State = Annotated[AppState, Depends(get_state)]
