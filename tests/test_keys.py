import stat

import pytest

from firmware_index import cli, keys


def test_keygen_writes_a_private_key_only_its_owner_reads(tmp_path, capsys):
    path = tmp_path / "ed25519.pem"
    assert cli.main(["keygen", str(path)]) == 0
    public = capsys.readouterr().out.strip()
    assert len(public) == 64
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert keys.public_hex(keys.load(path)) == public


def test_keygen_never_writes_over_a_key(tmp_path, capsys):
    path = tmp_path / "ed25519.pem"
    path.write_text("kept")
    assert cli.main(["keygen", str(path)]) == 1
    assert path.read_text() == "kept"
    assert "never written over" in capsys.readouterr().err


def test_a_signature_verifies_only_its_own_message_and_key(tmp_path):
    path = tmp_path / "a.pem"
    public = keys.generate(path)
    key = keys.load(path)
    other = keys.generate(tmp_path / "b.pem")
    message = b"snapshots/20261030T040000Z.json\nabc"
    signature = keys.sign(key, message)
    assert keys.verify(public, message, signature)
    assert not keys.verify(public, message + b"x", signature)
    assert not keys.verify(other, message, signature)
    assert not keys.verify(public, message, "zz")


def test_load_refuses_a_key_of_another_kind(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    path = tmp_path / "ec.pem"
    path.write_bytes(
        ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError, match="not an Ed25519"):
        keys.load(path)
