"""Test helpers: a reference sshsig signer and a scripted client device."""

import base64
import hashlib
import json
import secrets
import struct
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from syncryption_server.encoding import b64u
from syncryption_server.sshkeys import NAMESPACE_AUTH, NAMESPACE_KEYRING, public_key_text

if TYPE_CHECKING:  # TestClient needs httpx, which the container image doesn't have
    from fastapi.testclient import TestClient

VECTORS = Path(__file__).resolve().parents[2] / "testvectors"
SECRET = "open-sesame"
ADMIN_TOKEN = "admin-" + "0123456789abcdef" * 2


def load_vectors(name: str) -> Any:
    return json.loads((VECTORS / name).read_text())


def _string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def sign_sshsig(seed: bytes, namespace: str, message: bytes) -> str:
    key = Ed25519PrivateKey.from_private_bytes(seed)
    pk = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    wire = _string(b"ssh-ed25519") + _string(pk)
    ns = namespace.encode()
    signed = (
        b"SSHSIG"
        + _string(ns)
        + _string(b"")
        + _string(b"sha512")
        + _string(hashlib.sha512(message).digest())
    )
    sig_blob = _string(b"ssh-ed25519") + _string(key.sign(signed))
    blob = (
        b"SSHSIG"
        + struct.pack(">I", 1)
        + _string(wire)
        + _string(ns)
        + _string(b"")
        + _string(b"sha512")
        + _string(sig_blob)
    )
    b64 = base64.b64encode(blob).decode()
    lines = [b64[i : i + 70] for i in range(0, len(b64), 70)]
    return "\n".join(["-----BEGIN SSH SIGNATURE-----", *lines, "-----END SSH SIGNATURE-----", ""])


@dataclass
class Device:
    """One key of one installation in one vault, and a session once logged in."""

    client: "TestClient"
    username: str
    vault_name: str = "Personal"
    seed: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    name: str = "Laptop"
    token: str | None = None
    device_id: str | None = None
    vault_id: str | None = None

    @property
    def public_key(self) -> bytes:
        key = Ed25519PrivateKey.from_private_bytes(self.seed).public_key()
        return key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def public_key_text(self) -> str:
        return public_key_text(self.public_key)

    def challenge(self) -> dict:
        r = self.client.post(
            "/api/v1/auth/challenge",
            json={
                "username": self.username,
                "vaultName": self.vault_name,
                "publicKey": self.public_key_text + " comment",
            },
        )
        assert r.status_code == 200, r.text
        return r.json()

    def login(self, secret: str | None = None, expect: int = 200) -> dict:
        ch = self.challenge()
        body = {
            "challengeId": ch["challengeId"],
            "signature": sign_sshsig(self.seed, NAMESPACE_AUTH, ch["message"].encode()),
            "deviceName": self.name,
        }
        if secret is not None:
            body["sharedSecret"] = secret
        r = self.client.post("/api/v1/auth/verify", json=body)
        assert r.status_code == expect, r.text
        data = r.json()
        if expect == 200:
            self.token = data["token"]
            self.device_id = data["deviceId"]
            self.vault_id = data["vaultId"]
        return data

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def get(self, path: str, **kw: Any):
        return self.client.get(path, headers=self.headers, **kw)

    def post(self, path: str, **kw: Any):
        return self.client.post(path, headers=self.headers, **kw)

    def put(self, path: str, **kw: Any):
        return self.client.put(path, headers=self.headers, **kw)

    def delete(self, path: str, **kw: Any):
        return self.client.delete(path, headers=self.headers, **kw)

    def head(self, path: str, **kw: Any):
        return self.client.head(path, headers=self.headers, **kw)

    def keyring(
        self,
        version: int,
        data: bytes | None = None,
        *,
        recovery_signer: str | None = None,
        signing_seed: bytes | None = None,
    ) -> dict:
        data = data if data is not None else secrets.token_bytes(200)
        return {
            "version": version,
            "keyring": b64u(data),
            "signature": sign_sshsig(signing_seed or self.seed, NAMESPACE_KEYRING, data),
            "signer": self.device_id,
            "recoverySigner": recovery_signer,
        }

    def create_vault(self, **keyring: Any) -> str:
        """Create this key's vault (after a login with the shared secret)."""
        vault_id = str(uuid.uuid4())
        body = {"id": vault_id, "name": self.vault_name, "keyring": self.keyring(1, **keyring)}
        r = self.post("/api/v1/vaults", json=body)
        assert r.status_code == 201, r.text
        self.vault_id = vault_id
        return vault_id

    def join(self, approver: "Device") -> None:
        """Join `approver`'s vault as a new key, and have it approved."""
        assert self.login()["status"] == "pending"
        r = approver.post(f"/api/v1/vaults/{self.vault_id}/devices/{self.device_id}/approve")
        assert r.status_code == 200, r.text


def blob(data: bytes) -> tuple[str, bytes]:
    return hashlib.sha256(data).hexdigest(), data


def file_id(n: int = 0) -> str:
    return b64u(hashlib.sha256(str(n).encode()).digest())
