"""The Ed25519 key that signs each snapshot, and checks of its signatures."""

import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate(path: Path) -> str:
    """Write a new private key to path (mode 0600, never over a file) and return its public key."""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    return public_hex(key)


def load(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def public_hex(key: Ed25519PrivateKey) -> str:
    """The raw 32-byte public key in hex, as signing-key.pub publishes it."""
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )


def sign(key: Ed25519PrivateKey, message: bytes) -> str:
    return key.sign(message).hex()


def verify(public: str, message: bytes, signature: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(
            bytes.fromhex(signature), message
        )
    except (InvalidSignature, ValueError):
        return False
    return True
