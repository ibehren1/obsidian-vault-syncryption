"""Shared encodings and identifiers (docs/protocol.md 1)."""

import base64
import binascii
import re
import secrets
import uuid
from datetime import UTC, datetime

_B64U = re.compile(r"^[A-Za-z0-9_-]*$")
_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

FILE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
BLOB_ID_RE = re.compile(r"^[0-9a-f]{64}$")
DEVICE_ID_RE = re.compile(r"^d_[0-9A-Za-z]{22}$")


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def from_b64u(text: str) -> bytes:
    """Strict base64url without padding. Raises ValueError on anything else."""
    if not _B64U.match(text) or len(text) % 4 == 1:
        raise ValueError("not base64url")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except binascii.Error as e:
        raise ValueError("not base64url") from e
    if b64u(data) != text:
        raise ValueError("not canonical base64url")
    return data


def rfc3339(ts: int) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_device_id() -> str:
    return "d_" + "".join(secrets.choice(_BASE62) for _ in range(22))


def is_uuid4(text: str) -> bool:
    try:
        u = uuid.UUID(text)
    except ValueError:
        return False
    return u.version == 4 and str(u) == text
