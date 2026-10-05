"""Ed25519 SSH public keys and sshsig verification (docs/crypto.md 3.1, 6.5, 7).

Only `ssh-ed25519` keys and `sha512` signatures are accepted. Verification uses
`cryptography`; the format is OpenSSH `PROTOCOL.sshsig`.
"""

import base64
import binascii
import hashlib
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

KEY_TYPE = b"ssh-ed25519"
NAMESPACE_AUTH = "syncryption-auth@v1"
NAMESPACE_KEYRING = "syncryption-keyring@v1"

_BEGIN = "-----BEGIN SSH SIGNATURE-----"
_END = "-----END SSH SIGNATURE-----"
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


class KeyFormatError(ValueError):
    pass


class SshSigError(ValueError):
    pass


def _string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


class _Reader:
    def __init__(self, data: bytes, error: type[ValueError]):
        self.data = data
        self.pos = 0
        self.error = error

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise self.error("truncated")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def string(self) -> bytes:
        return self.take(self.u32())

    def end(self) -> None:
        if self.pos != len(self.data):
            raise self.error("trailing bytes")


def public_key_wire(pk: bytes) -> bytes:
    return _string(KEY_TYPE) + _string(pk)


def _parse_wire(wire: bytes, error: type[ValueError]) -> bytes:
    r = _Reader(wire, error)
    if r.string() != KEY_TYPE:
        raise error("only Ed25519 SSH keys are supported")
    pk = r.string()
    r.end()
    if len(pk) != 32:
        raise error("bad Ed25519 public key")
    return pk


def parse_public_key(text: str) -> bytes:
    """`ssh-ed25519 <base64> [comment]` -> the 32-byte key."""
    fields = text.strip().split()
    if len(fields) < 2 or fields[0] != KEY_TYPE.decode():
        raise KeyFormatError("only Ed25519 SSH keys are supported")
    try:
        wire = base64.b64decode(fields[1], validate=True)
    except binascii.Error as e:
        raise KeyFormatError("bad public key encoding") from e
    return _parse_wire(wire, KeyFormatError)


def public_key_text(pk: bytes) -> str:
    """Canonical text form, without a comment."""
    return "ssh-ed25519 " + base64.b64encode(public_key_wire(pk)).decode("ascii")


def fingerprint(pk: bytes) -> str:
    digest = hashlib.sha256(public_key_wire(pk)).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def pairing_code(pk: bytes) -> str:
    """First 50 bits of SHA-256(pubWire), Crockford base32, `XXXXX-XXXXX`."""
    bits = int.from_bytes(hashlib.sha256(public_key_wire(pk)).digest()[:7]) >> 6
    code = "".join(_CROCKFORD[(bits >> (5 * i)) & 31] for i in range(9, -1, -1))
    return f"{code[:5]}-{code[5:]}"


def verify_sshsig(armored: str, namespace: str, message: bytes) -> bytes:
    """Verify an armored sshsig and return the signer's 32-byte public key.

    Raises SshSigError if the signature is malformed, uses another namespace, key type or
    hash, or doesn't verify.
    """
    lines = armored.strip().splitlines()
    if len(lines) < 3 or lines[0] != _BEGIN or lines[-1] != _END:
        raise SshSigError("not an armored SSH signature")
    try:
        blob = base64.b64decode("".join(line.strip() for line in lines[1:-1]), validate=True)
    except binascii.Error as e:
        raise SshSigError("bad signature encoding") from e

    r = _Reader(blob, SshSigError)
    if r.take(6) != b"SSHSIG" or r.u32() != 1:
        raise SshSigError("not an SSHSIG v1 signature")
    pk = _parse_wire(r.string(), SshSigError)
    ns = r.string()
    reserved = r.string()
    hash_alg = r.string()
    sig_blob = r.string()
    r.end()
    if ns != namespace.encode():
        raise SshSigError("wrong namespace")
    if reserved != b"" or hash_alg != b"sha512":
        raise SshSigError("unsupported signature parameters")

    s = _Reader(sig_blob, SshSigError)
    if s.string() != KEY_TYPE:
        raise SshSigError("only Ed25519 signatures are supported")
    sig = s.string()
    s.end()
    if len(sig) != 64:
        raise SshSigError("bad Ed25519 signature")

    signed = (
        b"SSHSIG"
        + _string(ns)
        + _string(b"")
        + _string(b"sha512")
        + _string(hashlib.sha512(message).digest())
    )
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, signed)
    except InvalidSignature as e:
        raise SshSigError("signature does not verify") from e
    return pk
