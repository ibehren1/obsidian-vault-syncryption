# ruff: noqa: S101, S603, S607  (dev-only script that runs ssh-keygen)
"""Generate the test vectors in this directory.

Run from the repository root:

    uv run --no-project --with cryptography --with bcrypt --with pynacl --with pyrage \
        python testvectors/generate.py [file.json ...]

With no arguments every file is regenerated. The vectors are committed. Keys in
`openssh-keys.json` come from `ssh-keygen`, and the age files from rage (`pyrage`), so those
change on every run: only regenerate them when adding cases. Other vectors use fixed seeds.
Expected values are computed with `cryptography` and libsodium (`pynacl`), independently of
the plugin code.
"""

import base64
import hashlib
import hmac
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path

import bcrypt
import nacl.bindings
import pyrage
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

OUT = Path(__file__).parent

PEM_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----"
PEM_END = "-----END OPENSSH PRIVATE KEY-----"


def ssh_keygen(directory: Path, name: str, *args: str) -> Path:
    path = directory / name
    subprocess.run(
        ["ssh-keygen", "-q", "-f", str(path), *args],
        check=True,
        stdin=subprocess.DEVNULL,
    )
    return path


def fingerprint(pub_path: Path) -> str:
    out = subprocess.run(
        ["ssh-keygen", "-l", "-E", "sha256", "-f", str(pub_path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return out.split()[1]


def pem_decode(pem: str) -> bytes:
    body = pem.strip().removeprefix(PEM_BEGIN).removesuffix(PEM_END)
    return base64.b64decode("".join(body.split()))


def pem_encode(blob: bytes) -> str:
    b64 = base64.b64encode(blob).decode()
    lines = [b64[i : i + 70] for i in range(0, len(b64), 70)]
    return "\n".join([PEM_BEGIN, *lines, PEM_END]) + "\n"


def read_string(buf: bytes, off: int) -> tuple[bytes, int]:
    (n,) = struct.unpack_from(">I", buf, off)
    return buf[off + 4 : off + 4 + n], off + 4 + n


def write_string(x: bytes) -> bytes:
    return struct.pack(">I", len(x)) + x


def split_key(blob: bytes) -> tuple[bytes, bytes]:
    """Split an openssh-key-v1 blob into (everything before the private section, section)."""
    off = len(b"openssh-key-v1\0")
    for _ in range(3):  # ciphername, kdfname, kdfoptions
        _, off = read_string(blob, off)
    off += 4  # nkeys
    _, off = read_string(blob, off)  # publickey
    section, end = read_string(blob, off)
    assert end == len(blob)
    return blob[:off], section


def key_params(pem: str, passphrase: str) -> dict:
    """The random values ssh-keygen chose: checkint, and the bcrypt salt and rounds."""
    blob = pem_decode(pem)
    off = len(b"openssh-key-v1\0")
    cipher, off = read_string(blob, off)
    _, off = read_string(blob, off)
    kdfoptions, off = read_string(blob, off)
    _, section = split_key(blob)
    params: dict = {}
    if cipher == b"aes256-ctr":
        salt, opt_off = read_string(kdfoptions, 0)
        (rounds,) = struct.unpack_from(">I", kdfoptions, opt_off)
        kiv = bcrypt.kdf(passphrase.encode(), salt, 48, rounds, ignore_few_rounds=True)
        dec = Cipher(algorithms.AES(kiv[:32]), modes.CTR(kiv[32:])).decryptor()
        section = dec.update(section) + dec.finalize()
        params = {"salt": salt.hex(), "rounds": rounds}
    (checkint,) = struct.unpack_from(">I", section, 0)
    return {"checkint": checkint, **params}


def ed25519_case(directory: Path, name: str, comment: str, passphrase: str, *args: str) -> dict:
    path = ssh_keygen(directory, name, "-t", "ed25519", "-C", comment, "-N", passphrase, *args)
    pem = path.read_text()
    key = serialization.load_ssh_private_key(
        pem.encode(), password=passphrase.encode() if passphrase else None
    )
    assert isinstance(key, Ed25519PrivateKey)
    seed = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    pk = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pub_text = path.with_suffix(".pub").read_text().strip()
    return {
        "pem": pem,
        "passphrase": passphrase,
        "seed": seed.hex(),
        "publicKey": pk.hex(),
        "publicKeyText": pub_text,
        "comment": comment,
        "fingerprint": fingerprint(path.with_suffix(".pub")),
        **key_params(pem, passphrase),
    }


def tamper_section(pem: str, change) -> str:
    """Apply `change` to the unencrypted private section of `pem` and re-encode it."""
    head, section = split_key(pem_decode(pem))
    return pem_encode(head + write_string(change(bytearray(section))))


def openssh_keys(directory: Path) -> dict:
    plain = ed25519_case(directory, "plain", "alice@laptop", "")
    valid = [
        {"name": "unencrypted", **plain},
        {
            "name": "aes256-ctr, bcrypt, 16 rounds",
            **ed25519_case(
                directory, "enc16", "bob@phone", "correct horse", "-Z", "aes256-ctr", "-a", "16"
            ),
        },
        {
            "name": "aes256-ctr, bcrypt, 4 rounds, non-ASCII passphrase",
            **ed25519_case(directory, "enc4", "", "pässwörd 🔑", "-Z", "aes256-ctr", "-a", "4"),
        },
    ]

    enc = valid[1]

    def bad_checkint(s: bytearray) -> bytearray:
        s[7] ^= 0x01
        return s

    def bad_padding(s: bytearray) -> bytearray:
        s[-1] ^= 0xFF
        return s

    def bad_inner_pk(s: bytearray) -> bytearray:
        # checkint1, checkint2, string("ssh-ed25519"), u32 len, then pk32
        off = 8 + 4 + len(b"ssh-ed25519") + 4
        s[off] ^= 0x01
        return s

    def bad_sk_half(s: bytearray) -> bytearray:
        # sk64 = seed32 || pk32 follows pk32; flip a byte in its pk half
        off = 8 + 4 + len(b"ssh-ed25519") + 4 + 32 + 4 + 32
        s[off] ^= 0x01
        return s

    def bad_seed(s: bytearray) -> bytearray:
        # Flip a seed byte: the pk derived from the seed no longer matches.
        off = 8 + 4 + len(b"ssh-ed25519") + 4 + 32 + 4
        s[off] ^= 0x01
        return s

    def outer_pk_mismatch(pem: str) -> str:
        blob = bytearray(pem_decode(pem))
        head, _ = split_key(bytes(blob))
        # The outer publickey ends just before the section length; flip its last byte.
        blob[len(head) - 4 - 1] ^= 0x01
        return pem_encode(bytes(blob))

    rsa = ssh_keygen(directory, "rsa", "-t", "rsa", "-b", "2048", "-N", "").read_text()
    ecdsa = ssh_keygen(directory, "ecdsa", "-t", "ecdsa", "-N", "").read_text()
    chacha = ssh_keygen(
        directory, "chacha", "-t", "ed25519", "-N", "pw", "-Z", "chacha20-poly1305@openssh.com"
    ).read_text()

    invalid = [
        {
            "name": "wrong passphrase",
            "pem": enc["pem"],
            "passphrase": "wrong",
            "error": "wrong-passphrase",
        },
        {
            "name": "missing passphrase",
            "pem": enc["pem"],
            "passphrase": "",
            "error": "passphrase-required",
        },
        {
            "name": "bad checkint, unencrypted",
            "pem": tamper_section(plain["pem"], bad_checkint),
            "passphrase": "",
            "error": "corrupt",
        },
        {
            "name": "bad padding",
            "pem": tamper_section(plain["pem"], bad_padding),
            "passphrase": "",
            "error": "corrupt",
        },
        {
            "name": "inner public key mismatch",
            "pem": tamper_section(plain["pem"], bad_inner_pk),
            "passphrase": "",
            "error": "corrupt",
        },
        {
            "name": "sk64 public half mismatch",
            "pem": tamper_section(plain["pem"], bad_sk_half),
            "passphrase": "",
            "error": "corrupt",
        },
        {
            "name": "seed does not match public key",
            "pem": tamper_section(plain["pem"], bad_seed),
            "passphrase": "",
            "error": "corrupt",
        },
        {
            "name": "outer public key mismatch",
            "pem": outer_pk_mismatch(plain["pem"]),
            "passphrase": "",
            "error": "corrupt",
        },
        {"name": "rsa key", "pem": rsa, "passphrase": "", "error": "unsupported-key-type"},
        {"name": "ecdsa key", "pem": ecdsa, "passphrase": "", "error": "unsupported-key-type"},
        {
            "name": "chacha20-poly1305 cipher",
            "pem": chacha,
            "passphrase": "pw",
            "error": "unsupported-cipher",
        },
        {
            "name": "not an OpenSSH key",
            "pem": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            "passphrase": "",
            "error": "not-openssh",
        },
        {
            "name": "truncated",
            "pem": pem_encode(pem_decode(plain["pem"])[:60]),
            "passphrase": "",
            "error": "corrupt",
        },
    ]
    return {
        "description": "OpenSSH private keys (crypto.md 3.2). Valid keys come from ssh-keygen, "
        "expected values from python cryptography. Strings are UTF-8, binary values hex.",
        "valid": valid,
        "invalid": invalid,
    }


def fixed(label: str, n: int = 32) -> bytes:
    """Deterministic test bytes, so these vectors are reproducible."""
    return hashlib.sha256(f"syncryption test vector: {label}".encode()).digest()[:n]


def ed25519_public(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def pub_wire(pk: bytes) -> bytes:
    return write_string(b"ssh-ed25519") + write_string(pk)


def pub_text(pk: bytes) -> str:
    return "ssh-ed25519 " + base64.b64encode(pub_wire(pk)).decode()


def b64_nopad(x: bytes) -> str:
    return base64.b64encode(x).decode().rstrip("=")


def x25519(scalar: bytes, point: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(scalar).exchange(
        X25519PublicKey.from_public_bytes(point)
    )


def x25519_base(scalar: bytes) -> bytes:
    return (
        X25519PrivateKey.from_private_bytes(scalar)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def ed25519_to_x25519() -> dict:
    cases = []
    for i in range(4):
        seed = fixed(f"ed25519-to-x25519 {i}")
        pk = ed25519_public(seed)
        x_pk = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(pk)
        x_sk = hashlib.sha512(seed).digest()[:32]
        # libsodium returns the clamped scalar; X25519 clamps anyway, so both agree.
        clamped = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(seed + pk)
        assert x25519_base(x_sk) == x25519_base(clamped) == x_pk
        cases.append(
            {
                "seed": seed.hex(),
                "edPublicKey": pk.hex(),
                "xPublicKey": x_pk.hex(),
                "xSecretKey": x_sk.hex(),
            }
        )
    return {
        "description": "Ed25519 to X25519 conversion (crypto.md 3.4). xPublicKey from libsodium, "
        "xSecretKey = SHA-512(seed)[0:32], unclamped.",
        "cases": cases,
    }


AGE_SSH_LABEL = b"age-encryption.org/v1/ssh-ed25519"


def age_ssh_wrap(pk: bytes, ephemeral: bytes, file_key: bytes) -> dict:
    """Reference wrap of crypto.md section 4, written against cryptography."""
    wire = pub_wire(pk)
    pk_x = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(pk)
    tweak = hkdf(b"", wire, AGE_SSH_LABEL)
    e_pk = x25519_base(ephemeral)
    shared = x25519(tweak, x25519(ephemeral, pk_x))
    wrap_key = hkdf(shared, e_pk + pk_x, AGE_SSH_LABEL)
    body = ChaCha20Poly1305(wrap_key).encrypt(b"\0" * 12, file_key, None)
    tag = b64_nopad(hashlib.sha256(wire).digest()[:4])
    return {"args": ["ssh-ed25519", tag, b64_nopad(e_pk)], "body": body.hex()}


def openssh_pem(seed: bytes) -> str:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        )
        .decode()
    )


def age_bin() -> str:
    """Path to the Go `age` CLI: `$AGE`, or `age` on PATH."""
    path = os.environ.get("AGE") or shutil.which("age")
    if not path:
        sys.exit("Go age is required: put it on PATH or set AGE=/path/to/age")
    return path


def go_age_encrypt(directory: Path, plaintext: bytes, recipients: list[str]) -> bytes:
    args = [age_bin()]
    for r in recipients:
        args += ["-r", r]
    return subprocess.run(args, input=plaintext, capture_output=True, check=True).stdout


def age_ssh_ed25519(directory: Path) -> dict:
    alice = fixed("age alice")
    bob = fixed("age bob")
    alice_pk, bob_pk = ed25519_public(alice), ed25519_public(bob)

    wraps = []
    for i in range(3):
        ephemeral, file_key = fixed(f"age wrap {i} ephemeral"), fixed(f"age wrap {i} file key", 16)
        wraps.append(
            {
                "seed": alice.hex(),
                "publicKey": alice_pk.hex(),
                "ephemeral": ephemeral.hex(),
                "fileKey": file_key.hex(),
                **age_ssh_wrap(alice_pk, ephemeral, file_key),
            }
        )

    good = age_ssh_wrap(alice_pk, fixed("age stanza ephemeral"), fixed("age stanza file key", 16))
    body = bytes.fromhex(good["body"])
    tampered_body = bytes([body[0] ^ 1]) + body[1:]
    other_tag = ["ssh-ed25519", "AAAAAA", good["args"][2]]
    stanzas = [
        {"name": "valid", **good, "result": fixed("age stanza file key", 16).hex()},
        {
            "name": "tampered body",
            "args": good["args"],
            "body": tampered_body.hex(),
            "result": None,
        },
        {"name": "other tag", "args": other_tag, "body": good["body"], "result": None},
        {
            "name": "other type",
            "args": ["X25519", good["args"][2]],
            "body": good["body"],
            "result": None,
        },
        {
            "name": "extra argument",
            "args": [*good["args"], "x"],
            "body": good["body"],
            "error": True,
        },
        {"name": "missing argument", "args": good["args"][:2], "body": good["body"], "error": True},
        {
            "name": "short ephemeral key",
            "args": [*good["args"][:2], b64_nopad(bytes(31))],
            "body": good["body"],
            "error": True,
        },
        {
            "name": "low-order ephemeral key",
            "args": [*good["args"][:2], b64_nopad(bytes(32))],
            "body": good["body"],
            "error": True,
        },
        {"name": "short body", "args": good["args"], "body": body[:31].hex(), "error": True},
    ]

    alice_r = pyrage.ssh.Recipient.from_str(pub_text(alice_pk))
    bob_r = pyrage.ssh.Recipient.from_str(pub_text(bob_pk))
    x25519_r = pyrage.x25519.Identity.generate().to_public()
    plaintext = "Hello from rage! 🔐\n".encode()
    files = [
        {
            "name": "to alice",
            "file": pyrage.encrypt(plaintext, [alice_r]).hex(),
            "plaintext": plaintext.hex(),
        },
        {
            "name": "to bob, an X25519 key and alice",
            "file": pyrage.encrypt(plaintext, [bob_r, x25519_r, alice_r]).hex(),
            "plaintext": plaintext.hex(),
        },
        {
            "name": "to bob only",
            "file": pyrage.encrypt(plaintext, [bob_r]).hex(),
            "plaintext": None,
        },
    ]
    go_version = subprocess.run(
        [age_bin(), "--version"], capture_output=True, text=True, check=True
    ).stdout.strip()
    go_plaintext = f"Hello from Go age {go_version}!\n".encode()
    files += [
        {
            "name": f"Go age {go_version}: to alice",
            "file": go_age_encrypt(directory, go_plaintext, [pub_text(alice_pk)]).hex(),
            "plaintext": go_plaintext.hex(),
        },
        {
            "name": f"Go age {go_version}: to bob and alice",
            "file": go_age_encrypt(
                directory, go_plaintext, [pub_text(bob_pk), pub_text(alice_pk)]
            ).hex(),
            "plaintext": go_plaintext.hex(),
        },
        {
            "name": f"Go age {go_version}: to bob only",
            "file": go_age_encrypt(directory, go_plaintext, [pub_text(bob_pk)]).hex(),
            "plaintext": None,
        },
    ]
    alice_id = pyrage.ssh.Identity.from_buffer(openssh_pem(alice).encode())
    for f in files:
        if f["plaintext"] is not None:
            assert pyrage.decrypt(bytes.fromhex(f["file"]), [alice_id]) == bytes.fromhex(
                f["plaintext"]
            )

    return {
        "description": "age ssh-ed25519 stanza (crypto.md 4). `wrap`: deterministic wraps from a "
        "reference implementation on cryptography. `stanzas`: unwrap cases for alice, where "
        "`result` null means not for us and `error` means a malformed stanza. `files`: age files "
        "encrypted by rage and by Go age, to be decrypted with alice's key.",
        "alice": {
            "seed": alice.hex(),
            "publicKey": alice_pk.hex(),
            "publicKeyText": pub_text(alice_pk),
        },
        "bob": {"seed": bob.hex(), "publicKey": bob_pk.hex(), "publicKeyText": pub_text(bob_pk)},
        "wrap": wraps,
        "stanzas": stanzas,
        "files": files,
    }


SSHSIG_AUTH = "syncryption-auth@v1"
SSHSIG_KEYRING = "syncryption-keyring@v1"


def sshsig_sign(seed: bytes, namespace: str, message: bytes) -> str:
    """Reference sshsig (crypto.md 7.1) on cryptography. Ed25519 is deterministic."""
    signed = (
        b"SSHSIG"
        + write_string(namespace.encode())
        + write_string(b"")
        + write_string(b"sha512")
        + write_string(hashlib.sha512(message).digest())
    )
    sig = Ed25519PrivateKey.from_private_bytes(seed).sign(signed)
    blob = (
        b"SSHSIG"
        + struct.pack(">I", 1)
        + write_string(pub_wire(ed25519_public(seed)))
        + write_string(namespace.encode())
        + write_string(b"")
        + write_string(b"sha512")
        + write_string(write_string(b"ssh-ed25519") + write_string(sig))
    )
    b64 = base64.b64encode(blob).decode()
    lines = [b64[i : i + 70] for i in range(0, len(b64), 70)]
    return (
        "\n".join(["-----BEGIN SSH SIGNATURE-----", *lines, "-----END SSH SIGNATURE-----"]) + "\n"
    )


def keygen_sign(directory: Path, key: Path, namespace: str, message: bytes, *opts: str) -> str:
    msg = directory / "message"
    msg.write_bytes(message)
    (directory / "message.sig").unlink(missing_ok=True)
    args = ["ssh-keygen", "-q", "-Y", "sign", "-f", str(key), "-n", namespace]
    for o in opts:
        args += ["-O", o]
    subprocess.run([*args, str(msg)], check=True, capture_output=True)
    return (directory / "message.sig").read_text()


def write_key(directory: Path, name: str, seed: bytes) -> Path:
    path = directory / name
    path.write_text(openssh_pem(seed))
    path.chmod(0o600)
    return path


def sshsig_vectors(directory: Path) -> dict:
    seed = fixed("sshsig key")
    pk = ed25519_public(seed)
    key = write_key(directory, "sshsig_key", seed)
    challenge = (
        b"syncryption-auth@v1\norigin: https://notes.example.com\nusername: alice\n"
        b"key: SHA256:x\nnonce: AAAA\nexpires: 2026-10-02T12:01:00Z\n"
    )
    keyring = fixed("sshsig keyring bytes", 32) * 5

    valid = []
    for name, ns, msg in [
        ("login challenge", SSHSIG_AUTH, challenge),
        ("keyring bytes", SSHSIG_KEYRING, keyring),
        ("empty message", SSHSIG_KEYRING, b""),
    ]:
        sig = keygen_sign(directory, key, ns, msg)
        assert sig == sshsig_sign(seed, ns, msg), "reference sshsig differs from ssh-keygen"
        valid.append({"name": name, "namespace": ns, "message": msg.hex(), "signature": sig})

    auth_sig = valid[0]["signature"]
    blob = pem_like_decode(auth_sig)
    tampered = bytearray(blob)
    tampered[-1] ^= 0x01
    sha256_sig = keygen_sign(directory, key, SSHSIG_AUTH, challenge, "hashalg=sha256")
    rsa_key = ssh_keygen(directory, "sshsig_rsa", "-t", "rsa", "-b", "2048", "-N", "")
    rsa_sig = keygen_sign(directory, rsa_key, SSHSIG_AUTH, challenge)

    invalid = [
        {
            "name": "wrong namespace",
            "namespace": SSHSIG_KEYRING,
            "message": challenge.hex(),
            "signature": auth_sig,
        },
        {
            "name": "tampered message",
            "namespace": SSHSIG_AUTH,
            "message": (challenge + b"x").hex(),
            "signature": auth_sig,
        },
        {
            "name": "tampered signature",
            "namespace": SSHSIG_AUTH,
            "message": challenge.hex(),
            "signature": sig_armor(bytes(tampered)),
        },
        {
            "name": "sha256 hash",
            "namespace": SSHSIG_AUTH,
            "message": challenge.hex(),
            "signature": sha256_sig,
        },
        {
            "name": "rsa key",
            "namespace": SSHSIG_AUTH,
            "message": challenge.hex(),
            "signature": rsa_sig,
        },
        {
            "name": "not armored",
            "namespace": SSHSIG_AUTH,
            "message": challenge.hex(),
            "signature": "garbage",
        },
        {
            "name": "truncated",
            "namespace": SSHSIG_AUTH,
            "message": challenge.hex(),
            "signature": sig_armor(blob[:40]),
        },
    ]
    return {
        "description": "sshsig (crypto.md 7). Valid signatures come from ssh-keygen -Y sign and "
        "equal the reference implementation byte for byte. Messages are hex.",
        "seed": seed.hex(),
        "publicKey": pk.hex(),
        "publicKeyText": pub_text(pk),
        "valid": valid,
        "invalid": invalid,
    }


def pem_like_decode(armored: str) -> bytes:
    lines = [ln for ln in armored.strip().splitlines() if not ln.startswith("-----")]
    return base64.b64decode("".join(lines))


def sig_armor(blob: bytes) -> str:
    b64 = base64.b64encode(blob).decode()
    lines = [b64[i : i + 70] for i in range(0, len(b64), 70)]
    return (
        "\n".join(["-----BEGIN SSH SIGNATURE-----", *lines, "-----END SSH SIGNATURE-----"]) + "\n"
    )


def b64u(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode().rstrip("=")


def hkdf_empty_salt(ikm: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(ikm)


def index_key(vdk1: bytes) -> bytes:
    return hkdf_empty_salt(vdk1, b"syncryption/v1/index")


def file_id(index: bytes, path: str) -> bytes:
    return hmac.new(index, unicodedata.normalize("NFC", path).encode(), hashlib.sha256).digest()


def file_key(vdk: bytes, fid: bytes) -> bytes:
    return hkdf_empty_salt(vdk, b"syncryption/v1/file" + fid)


CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def pairing_code(pk: bytes) -> str:
    bits = int.from_bytes(hashlib.sha256(pub_wire(pk)).digest()[:7], "big") >> 6
    code = "".join(CROCKFORD[(bits >> (5 * i)) & 31] for i in range(9, -1, -1))
    return f"{code[:5]}-{code[5:]}"


def kdf_vectors() -> dict:
    vdk1, vdk2 = fixed("kdf vdk 1"), fixed("kdf vdk 2")
    index = index_key(vdk1)
    paths = [
        ("plain", "Notes/Projects/Plan.md", "Notes/Projects/Plan.md"),
        ("case differs", "notes/projects/plan.md", "notes/projects/plan.md"),
        ("NFC already", "Caf\u00e9.md", "Caf\u00e9.md"),
        ("NFD input normalised to NFC", "Cafe\u0301.md", "Caf\u00e9.md"),
        ("config folder", ".obsidian/app.json", ".obsidian/app.json"),
        ("non-BMP", "Daily/\U0001f4dd 2026-10-02.md", "Daily/\U0001f4dd 2026-10-02.md"),
        ("spaces and dots", "a b/c.d.e/ f .md", "a b/c.d.e/ f .md"),
    ]
    files = []
    for name, path, norm in paths:
        fid = file_id(index, path)
        files.append(
            {
                "name": name,
                "path": path,
                "normPath": norm,
                "fileId": fid.hex(),
                "fileIdString": b64u(fid),
                "fileKeyEpoch1": file_key(vdk1, fid).hex(),
                "fileKeyEpoch2": file_key(vdk2, fid).hex(),
            }
        )
    invalid_paths = [
        "",
        "/Notes/a.md",
        "Notes/a.md/",
        "Notes//a.md",
        "./a.md",
        "Notes/../a.md",
        "..",
        ".",
    ]
    pairing = []
    for i in range(4):
        pk = ed25519_public(fixed(f"pairing {i}"))
        pairing.append(
            {"publicKey": pk.hex(), "publicKeyText": pub_text(pk), "code": pairing_code(pk)}
        )
    return {
        "description": "Vault key derivations (crypto.md 5) and pairing codes (crypto.md 6.5). "
        "Strings are UTF-8, binary values hex, fileIdString is b64u.",
        "vdk1": vdk1.hex(),
        "vdk2": vdk2.hex(),
        "indexKey": index.hex(),
        "files": files,
        "invalidPaths": invalid_paths,
        "pairingCodes": pairing,
    }


def xchacha_seal(key: bytes, nonce: bytes, plaintext: bytes, ad: bytes) -> bytes:
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, nonce, key)


def seal_object(key: bytes, epoch: int, domain: bytes, plaintext: bytes, nonce: bytes) -> bytes:
    header = b"\x01" + struct.pack(">I", epoch)
    return header + nonce + xchacha_seal(key, nonce, plaintext, header + domain)


def meta_domain(fid: bytes) -> bytes:
    return b"syncryption/v1/meta" + fid


def chunk_domain(fid: bytes, i: int) -> bytes:
    return b"syncryption/v1/chunk" + fid + struct.pack(">I", i)


def objects_vectors() -> dict:
    vdk1, vdk2 = fixed("objects vdk 1"), fixed("objects vdk 2")
    index = index_key(vdk1)
    path = "Notes/Hello.md"
    fid = file_id(index, path)
    content = "# Hello\n\nEncrypted with Syncryption. \u00e9\U0001f512\n".encode()

    chunk_nonce = fixed("objects chunk nonce", 24)
    chunk = seal_object(file_key(vdk2, fid), 2, chunk_domain(fid, 0), content, chunk_nonce)
    chunk_id = hashlib.sha256(chunk).hexdigest()
    meta = {
        "v": 1,
        "path": path,
        "deleted": False,
        "size": len(content),
        "mtime": 1790000000000,
        "ctime": 1789000000000,
        "sha256": hashlib.sha256(content).hexdigest(),
        "chunks": [{"id": chunk_id, "size": len(content)}],
        "device": "d_0123456789abcdefABCDEF",
    }
    meta_plain = json.dumps(meta, separators=(",", ":")).encode()
    meta_nonce = fixed("objects meta nonce", 24)
    meta_obj = seal_object(file_key(vdk2, fid), 2, meta_domain(fid), meta_plain, meta_nonce)

    # Metadata whose path hashes to another fileId: the server moved it.
    other_fid = file_id(index, "Notes/Other.md")
    moved = seal_object(
        file_key(vdk2, other_fid), 2, meta_domain(other_fid), meta_plain, meta_nonce
    )

    def flip(obj: bytes, i: int) -> str:
        b = bytearray(obj)
        b[i] ^= 0x01
        return bytes(b).hex()

    tombstone = {
        **meta,
        "deleted": True,
        "size": 0,
        "chunks": [],
        "sha256": hashlib.sha256(b"").hexdigest(),
    }
    tomb_plain = json.dumps(tombstone, separators=(",", ":")).encode()
    tomb_nonce = fixed("objects tombstone nonce", 24)
    tomb_obj = seal_object(file_key(vdk1, fid), 1, meta_domain(fid), tomb_plain, tomb_nonce)

    return {
        "description": "Encrypted objects (crypto.md 8) with fixed nonces. Keys come from the "
        "kdf rules; `vdk` lists the VDK per epoch. Binary values hex.",
        "vdk": {"1": vdk1.hex(), "2": vdk2.hex()},
        "indexKey": index.hex(),
        "path": path,
        "fileId": fid.hex(),
        "content": content.hex(),
        "chunk": {
            "epoch": 2,
            "index": 0,
            "nonce": chunk_nonce.hex(),
            "object": chunk.hex(),
            "blobId": chunk_id,
        },
        "meta": {
            "epoch": 2,
            "nonce": meta_nonce.hex(),
            "plaintext": meta_plain.hex(),
            "object": meta_obj.hex(),
            "value": meta,
        },
        "tombstone": {
            "epoch": 1,
            "nonce": tomb_nonce.hex(),
            "plaintext": tomb_plain.hex(),
            "object": tomb_obj.hex(),
            "value": tombstone,
        },
        "invalid": [
            {
                "name": "chunk: version byte changed",
                "kind": "chunk",
                "index": 0,
                "object": flip(chunk, 0),
            },
            {"name": "chunk: epoch changed", "kind": "chunk", "index": 0, "object": flip(chunk, 4)},
            {
                "name": "chunk: nonce changed",
                "kind": "chunk",
                "index": 0,
                "object": flip(chunk, 10),
            },
            {
                "name": "chunk: ciphertext changed",
                "kind": "chunk",
                "index": 0,
                "object": flip(chunk, len(chunk) - 1),
            },
            {
                "name": "chunk: opened at another index",
                "kind": "chunk",
                "index": 1,
                "object": chunk.hex(),
            },
            {
                "name": "chunk: opened as metadata",
                "kind": "meta",
                "index": 0,
                "object": chunk.hex(),
            },
            {
                "name": "meta: epoch changed",
                "kind": "meta",
                "index": 0,
                "object": flip(meta_obj, 4),
            },
            {
                "name": "meta: tag changed",
                "kind": "meta",
                "index": 0,
                "object": flip(meta_obj, len(meta_obj) - 1),
            },
            {"name": "meta: truncated", "kind": "meta", "index": 0, "object": meta_obj[:44].hex()},
            {
                "name": "meta: path belongs to another fileId",
                "kind": "meta-moved",
                "index": 0,
                "object": moved.hex(),
                "fileId": other_fid.hex(),
            },
        ],
    }


BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _bech32_hrp(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _to5(data: bytes) -> list[int]:
    acc, bits, out = 0, 0, []
    for b in data:
        acc, bits = (acc << 8) | b, bits + 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 31)
    if bits:
        out.append((acc << (5 - bits)) & 31)
    return out


def bech32_encode(hrp: str, data: bytes) -> str:
    """BIP 173 bech32, as age uses it (lowercase here)."""
    d = _to5(data)
    poly = _bech32_polymod(_bech32_hrp(hrp) + d + [0] * 6) ^ 1
    check = [(poly >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32[x] for x in d + check)


def recovery_identity(secret: bytes) -> str:
    """A native age X25519 identity, `AGE-SECRET-KEY-1...`, from its 32-byte secret."""
    return bech32_encode("age-secret-key-", secret).upper()


def recovery_signer(secret: bytes) -> bytes:
    """crypto.md 9: the Ed25519 seed that signs recovery uploads."""
    return hkdf_empty_salt(secret, b"syncryption/v1/recovery-signing")


def keyring_vectors(directory: Path) -> dict:
    """A keyring chain and the checks of crypto.md 6.3, 6.4 and 9."""
    names = ["alice", "bob", "carol", "dave", "mallory"]
    ids = {n: "d_" + n.ljust(22, "0") for n in names}
    seeds = {n: fixed(f"keyring {n}") for n in names}
    pks = {n: pub_text(ed25519_public(seeds[n])) for n in names}
    recovery_secret = fixed("keyring recovery")
    recovery = pyrage.x25519.Identity.from_str(recovery_identity(recovery_secret))
    other_recovery = pyrage.x25519.Identity.from_str(recovery_identity(fixed("other recovery")))
    recovery_seed = recovery_signer(recovery_secret)
    recovery_pk = pub_text(ed25519_public(recovery_seed))
    other_recovery_pk = pub_text(ed25519_public(recovery_signer(fixed("other recovery"))))
    vault_id = "8f6c0e9e-3b1d-4c55-9a43-2a0b7c1d9e10"
    vault_name = "Personal"
    vdk1, vdk2 = fixed("keyring vdk 1"), fixed("keyring vdk 2")

    def device(n: str, added: str) -> dict:
        return {"id": ids[n], "name": n.capitalize(), "publicKey": pks[n], "added": added}

    with_recovery = {
        "recovery": str(recovery.to_public()),
        "recoverySigner": recovery_pk,
        "recoverySetBy": ids["alice"],
    }

    def plaintext(version: int, devices: list[str], epochs: int, by: str, **over) -> dict:
        keys = [{"epoch": 1, "vdk": b64u(vdk1)}] + (
            [{"epoch": 2, "vdk": b64u(vdk2)}] if epochs > 1 else []
        )
        k = {
            "v": 1,
            "vaultId": vault_id,
            "version": version,
            "name": vault_name,
            "indexKey": b64u(index_key(vdk1)),
            "currentEpoch": epochs,
            "keys": keys,
            "devices": [device(n, "2026-10-02T12:00:00Z") for n in devices],
            # The recovery key is set in version 2 (by alice) and kept after that.
            **(with_recovery if version >= 2 else {}),
            "updatedBy": ids[by],
            "updatedAt": f"2026-10-02T12:0{version}:00Z",
        }
        k.update(over)
        return {key: value for key, value in k.items() if value is not None}

    def seal(
        k: dict,
        signer: str,
        server_version: int | None = None,
        namespace: str = SSHSIG_KEYRING,
    ) -> dict:
        recipients = [pyrage.ssh.Recipient.from_str(d["publicKey"]) for d in k["devices"]]
        if "recovery" in k:
            recipients.append(pyrage.x25519.Recipient.from_str(k["recovery"]))
        age = pyrage.encrypt(json.dumps(k).encode(), recipients)
        seed = recovery_seed if signer == "recovery" else seeds[signer]
        return {
            "version": k["version"] if server_version is None else server_version,
            "keyring": age.hex(),
            "signature": sshsig_sign(seed, namespace, age),
            "plaintext": k,
        }

    v1 = plaintext(1, ["alice"], 1, "alice")
    v2 = plaintext(2, ["alice", "bob"], 1, "alice")
    v3 = plaintext(3, ["alice", "bob", "carol"], 1, "bob")
    v4 = plaintext(4, ["bob", "carol"], 2, "bob")
    # Every device is lost: dave recovers the vault with the recovery key.
    v5 = plaintext(5, ["bob", "carol", "dave"], 2, "dave")
    no_recovery = {"recovery": None, "recoverySigner": None, "recoverySetBy": None}
    blobs = {
        "v1": seal(v1, "alice"),
        "v2": seal(v2, "alice"),
        "v3": seal(v3, "bob"),
        "v4": seal(v4, "bob"),
        "v5-recovered": seal(v5, "recovery"),
        "v1-signed-by-mallory": seal(v1, "mallory"),
        "v1-signed-by-recovery": seal(v1, "recovery"),
        "v2-signed-by-mallory": seal(
            plaintext(2, ["alice", "bob", "mallory"], 1, "mallory"), "mallory"
        ),
        "v2-signed-by-recovery": seal(plaintext(2, ["alice", "dave"], 1, "dave"), "recovery"),
        "v2-reencrypted": seal(v2, "alice"),
        "v2-other-vault": seal(
            plaintext(
                2, ["alice", "bob"], 1, "alice", vaultId="00000000-0000-4000-8000-000000000000"
            ),
            "alice",
        ),
        "v2-other-name": seal(plaintext(2, ["alice", "bob"], 1, "alice", name="Work"), "alice"),
        "v2-served-as-v3": seal(v2, "alice", server_version=3),
        "v2-wrong-namespace": seal(v2, "alice", namespace=SSHSIG_AUTH),
        "v2-recovery-without-signer": seal(
            plaintext(2, ["alice", "bob"], 1, "alice", recoverySigner=None), "alice"
        ),
        "v2-recovery-set-by-another-device": seal(
            plaintext(2, ["alice", "bob"], 1, "alice", recoverySetBy=ids["bob"]), "alice"
        ),
        "v3-recovery-replaced": seal(
            plaintext(
                3,
                ["alice", "bob", "carol"],
                1,
                "bob",
                recovery=str(other_recovery.to_public()),
                recoverySigner=other_recovery_pk,
                recoverySetBy=ids["bob"],
            ),
            "bob",
        ),
        "v3-recovery-removed": seal(
            plaintext(3, ["alice", "bob", "carol"], 1, "bob", **no_recovery), "bob"
        ),
        "v5-recovery-replaced-by-recovery": seal(
            plaintext(
                5,
                ["bob", "carol", "dave"],
                2,
                "dave",
                recovery=str(other_recovery.to_public()),
                recoverySigner=other_recovery_pk,
                recoverySetBy=ids["dave"],
            ),
            "recovery",
        ),
        "v5-epoch2-changed": seal(
            plaintext(
                5,
                ["bob", "carol"],
                2,
                "bob",
                keys=[
                    {"epoch": 1, "vdk": b64u(vdk1)},
                    {"epoch": 2, "vdk": b64u(fixed("other vdk 2"))},
                ],
            ),
            "bob",
        ),
        "v5-current-epoch-missing": seal(
            plaintext(5, ["bob", "carol"], 2, "bob", currentEpoch=3), "bob"
        ),
    }
    # Signature over other bytes: take v2's signature for v2-reencrypted's bytes.
    blobs["v2-signature-mismatch"] = {
        **blobs["v2-reencrypted"],
        "signature": blobs["v2"]["signature"],
    }

    def case(name: str, open_: str, as_: str, trusted: list[str], expect: str) -> dict:
        return {"name": name, "open": open_, "as": as_, "trustedChain": trusted, "expect": expect}

    cases = [
        case("genesis, first use", "v1", "alice", [], "ok"),
        case("pairing: bob trusts v2 on first use", "v2", "bob", [], "ok"),
        case("next version signed by a trusted device", "v2", "alice", ["v1"], "ok"),
        case("same version and bytes as the pin", "v2", "alice", ["v1", "v2"], "ok"),
        case("signed by a device added in the previous version", "v3", "bob", ["v2"], "ok"),
        case("rotation removes alice", "v4", "carol", ["v3"], "ok"),
        case("signed by the previous version's recovery key", "v5-recovered", "carol", ["v4"], "ok"),
        case("recovered device, first use", "v5-recovered", "dave", [], "ok"),
        case("recovery key removed by a device", "v3-recovery-removed", "bob", ["v2"], "ok"),
        case("recovery key replaced by a device", "v3-recovery-replaced", "bob", ["v2"], "ok"),
        case(
            "alice is no longer a recipient", "v4", "alice", ["v1", "v2", "v3"], "not-a-recipient"
        ),
        case("mallory is not a recipient", "v2", "mallory", [], "not-a-recipient"),
        case(
            "genesis signed by a device outside the keyring",
            "v1-signed-by-mallory",
            "alice",
            [],
            "untrusted-signer",
        ),
        case(
            "first use signed by a recovery key the keyring doesn't name",
            "v1-signed-by-recovery",
            "alice",
            [],
            "untrusted-signer",
        ),
        case(
            "next version signed by an untrusted device",
            "v2-signed-by-mallory",
            "alice",
            ["v1"],
            "untrusted-signer",
        ),
        case(
            "signed by a recovery key the previous version didn't have",
            "v2-signed-by-recovery",
            "alice",
            ["v1"],
            "untrusted-signer",
        ),
        case(
            "recovery key set in the name of another device",
            "v2-recovery-set-by-another-device",
            "alice",
            ["v1"],
            "inconsistent",
        ),
        case(
            "recovery key replaced by the recovery key",
            "v5-recovery-replaced-by-recovery",
            "carol",
            ["v4"],
            "inconsistent",
        ),
        case(
            "recovery key without its signer",
            "v2-recovery-without-signer",
            "alice",
            ["v1"],
            "malformed",
        ),
        case("older version than the pin", "v1", "alice", ["v1", "v2"], "rollback"),
        case("same version, different bytes", "v2-reencrypted", "alice", ["v1", "v2"], "rollback"),
        case("skips a version", "v3", "alice", ["v1"], "chain-gap"),
        case("another vault", "v2-other-vault", "alice", ["v1"], "wrong-vault"),
        case("another vault name", "v2-other-name", "alice", ["v1"], "wrong-vault"),
        case(
            "plaintext version differs from the server's",
            "v2-served-as-v3",
            "alice",
            ["v1", "v2"],
            "version-mismatch",
        ),
        case(
            "signature in the auth namespace",
            "v2-wrong-namespace",
            "alice",
            ["v1"],
            "bad-signature",
        ),
        case(
            "signature over other bytes", "v2-signature-mismatch", "alice", ["v1"], "bad-signature"
        ),
        case(
            "past epoch key changed", "v5-epoch2-changed", "bob", ["v2", "v3", "v4"], "inconsistent"
        ),
        case(
            "currentEpoch not in keys",
            "v5-current-epoch-missing",
            "bob",
            ["v2", "v3", "v4"],
            "malformed",
        ),
    ]

    for name in ["v2", "v3", "v4", "v5-recovered"]:
        b = blobs[name]
        assert json.loads(pyrage.decrypt(bytes.fromhex(b["keyring"]), [recovery])) == b["plaintext"]

    return {
        "description": "Keyring chain and checks (crypto.md 6, 9). Each case opens `open` as "
        "device `as`, after trusting `trustedChain` in order (the first entry on first use). "
        "`expect` is `ok` or a KeyringError code. Keyring files are hex, encrypted by rage, and "
        "signed by the reference sshsig. The recovery key is set from version 2 on; its "
        "signing seed is HKDF(secret, '', 'syncryption/v1/recovery-signing').",
        "vault": {"id": vault_id, "name": vault_name},
        "devices": {
            n: {"id": ids[n], "seed": seeds[n].hex(), "publicKeyText": pks[n]} for n in names
        },
        "recovery": {
            "identity": str(recovery),
            "recipient": str(recovery.to_public()),
            "secret": recovery_secret.hex(),
            "signerSeed": recovery_seed.hex(),
            "signerPublicKeyText": recovery_pk,
        },
        "blobs": blobs,
        "cases": cases,
    }


def write(name: str, data: dict) -> None:
    (OUT / name).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        generators = {
            "openssh-keys.json": lambda: openssh_keys(Path(tmp)),
            "ed25519-to-x25519.json": ed25519_to_x25519,
            "age-ssh-ed25519.json": lambda: age_ssh_ed25519(Path(tmp)),
            "sshsig.json": lambda: sshsig_vectors(Path(tmp)),
            "kdf.json": kdf_vectors,
            "objects.json": objects_vectors,
            "keyring.json": lambda: keyring_vectors(Path(tmp)),
        }
        for name in sys.argv[1:] or generators:
            write(name, generators[name]())


if __name__ == "__main__":
    main()
