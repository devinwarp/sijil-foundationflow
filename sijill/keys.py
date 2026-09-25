"""Node keypair generation and loading. Private key PEM (PKCS8, mode 0600), public key PEM."""

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate(key_path: str | Path, pub_path: str | Path) -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.generate()
    key_path, pub_path = Path(key_path), Path(pub_path)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    pub_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo))
    return key


def load(key_path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{key_path} is not an Ed25519 private key")
    return key


def load_or_generate(key_path: str | Path, pub_path: str | Path) -> Ed25519PrivateKey:
    if Path(key_path).exists():
        key = load(key_path)
        if not Path(pub_path).exists():
            Path(pub_path).write_bytes(key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        return key
    return generate(key_path, pub_path)
