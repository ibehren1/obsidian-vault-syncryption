import pytest

from syncryption_server.sshkeys import (
    KeyFormatError,
    SshSigError,
    fingerprint,
    pairing_code,
    parse_public_key,
    public_key_text,
    verify_sshsig,
)
from tests.helpers import load_vectors, sign_sshsig

SIG = load_vectors("sshsig.json")


@pytest.mark.parametrize("case", SIG["valid"], ids=lambda c: c["name"])
def test_verifies_ssh_keygen_signatures(case):
    pk = verify_sshsig(case["signature"], case["namespace"], bytes.fromhex(case["message"]))
    assert pk.hex() == SIG["publicKey"]


@pytest.mark.parametrize("case", SIG["valid"], ids=lambda c: c["name"])
def test_reference_signer_matches_ssh_keygen(case):
    sig = sign_sshsig(bytes.fromhex(SIG["seed"]), case["namespace"], bytes.fromhex(case["message"]))
    assert sig == case["signature"]


@pytest.mark.parametrize("case", SIG["invalid"], ids=lambda c: c["name"])
def test_rejects_invalid_signatures(case):
    with pytest.raises(SshSigError):
        verify_sshsig(case["signature"], case["namespace"], bytes.fromhex(case["message"]))


@pytest.mark.parametrize("case", load_vectors("kdf.json")["pairingCodes"], ids=lambda c: c["code"])
def test_pairing_codes(case):
    pk = parse_public_key(case["publicKeyText"])
    assert pk.hex() == case["publicKey"]
    assert pairing_code(pk) == case["code"]


def test_public_key_text_round_trip():
    pk = bytes.fromhex(SIG["publicKey"])
    assert parse_public_key(SIG["publicKeyText"] + " user@host") == pk
    assert public_key_text(pk) == " ".join(SIG["publicKeyText"].split()[:2])
    assert fingerprint(pk).startswith("SHA256:")
    assert not fingerprint(pk).endswith("=")


@pytest.mark.parametrize(
    "text",
    [
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ",
        "ssh-ed25519",
        "ssh-ed25519 not*base64",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAAQA=",
    ],
)
def test_rejects_bad_public_keys(text):
    with pytest.raises(KeyFormatError):
        parse_public_key(text)
