"""
Engare key management.

Supports three key modes:
1. Key pair (X25519) — generate locally, share public key, keep private key safe
2. Password — derive key from a passphrase
3. Video-as-key — a video file IS the key (share on USB drive)
"""

import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from . import crypto


# ── Key File Format ──

KEY_DIR_NAME = ".engare"


def get_key_dir() -> Path:
    """Get or create the key storage directory."""
    d = Path.home() / KEY_DIR_NAME
    d.mkdir(exist_ok=True)
    return d


def generate_identity(name: str, passphrase: str | None = None) -> dict:
    """
    Generate a new identity (X25519 key pair).
    Saves to ~/.engare/<name>.key (private) and ~/.engare/<name>.pub (public).

    If passphrase is provided, the private key is encrypted at rest with
    scrypt + AES-256-GCM. The passphrase is required to use the key later.
    """
    private, public = crypto.generate_keypair()

    priv_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    key_dir = get_key_dir()

    # Save private key (optionally encrypted)
    priv_path = key_dir / f"{name}.key"
    if passphrase:
        enc_key, salt = crypto.password_to_key(passphrase)
        encrypted = crypto.encrypt(priv_bytes, enc_key)
        priv_data = {
            "type": "engare-private-key-v1-encrypted",
            "name": name,
            "encrypted_private": base64.b64encode(encrypted).decode(),
            "salt": base64.b64encode(salt).decode(),
            "public": base64.b64encode(pub_bytes).decode(),
        }
    else:
        priv_data = {
            "type": "engare-private-key-v1",
            "name": name,
            "private": base64.b64encode(priv_bytes).decode(),
            "public": base64.b64encode(pub_bytes).decode(),
        }
    priv_path.write_text(json.dumps(priv_data, indent=2))
    os.chmod(priv_path, 0o600)  # Owner read/write only

    # Save public key
    pub_path = key_dir / f"{name}.pub"
    pub_data = {
        "type": "engare-public-key-v1",
        "name": name,
        "public": base64.b64encode(pub_bytes).decode(),
    }
    pub_path.write_text(json.dumps(pub_data, indent=2))

    return {
        "name": name,
        "private_path": str(priv_path),
        "public_path": str(pub_path),
        "public_key": base64.b64encode(pub_bytes).decode(),
        "fingerprint": fingerprint(pub_bytes),
        "encrypted": passphrase is not None,
    }


def load_private_key(name_or_path: str, passphrase: str | None = None) -> X25519PrivateKey:
    """Load a private key by identity name or file path.

    If the key is encrypted, a passphrase is required. If not provided,
    the user is prompted interactively.
    """
    path = _resolve_key_path(name_or_path, ".key")
    data = json.loads(Path(path).read_text())

    if data.get("type") == "engare-private-key-v1-encrypted":
        if not passphrase:
            import getpass
            passphrase = getpass.getpass(f"Passphrase for {data.get('name', name_or_path)}: ")
        salt = base64.b64decode(data["salt"])
        enc_key, _ = crypto.password_to_key(passphrase, salt)
        encrypted = base64.b64decode(data["encrypted_private"])
        try:
            priv_bytes = crypto.decrypt(encrypted, enc_key)
        except Exception:
            raise ValueError("Wrong passphrase")
        return X25519PrivateKey.from_private_bytes(priv_bytes)

    priv_bytes = base64.b64decode(data["private"])
    return X25519PrivateKey.from_private_bytes(priv_bytes)


def load_public_key(name_or_path: str) -> X25519PublicKey:
    """Load a public key by identity name, file path, or base64 string."""
    # Try as base64 first
    try:
        raw = base64.b64decode(name_or_path)
        if len(raw) == 32:
            return X25519PublicKey.from_public_bytes(raw)
    except Exception:
        pass

    path = _resolve_key_path(name_or_path, ".pub")
    data = json.loads(Path(path).read_text())
    pub_bytes = base64.b64decode(data["public"])
    return X25519PublicKey.from_public_bytes(pub_bytes)


def export_public_key(name: str) -> str:
    """Export a public key as a shareable base64 string."""
    path = _resolve_key_path(name, ".pub")
    data = json.loads(Path(path).read_text())
    return data["public"]


def list_identities() -> list[dict]:
    """List all local identities."""
    key_dir = get_key_dir()
    identities = []
    for f in sorted(key_dir.glob("*.key")):
        data = json.loads(f.read_text())
        pub_bytes = base64.b64decode(data["public"])
        identities.append({
            "name": data["name"],
            "public_key": data["public"],
            "fingerprint": fingerprint(pub_bytes),
            "encrypted": data.get("type") == "engare-private-key-v1-encrypted",
        })
    return identities


def import_public_key(name: str, pub_b64: str):
    """Import someone's public key and save it locally."""
    pub_bytes = base64.b64decode(pub_b64)
    X25519PublicKey.from_public_bytes(pub_bytes)  # Validate

    key_dir = get_key_dir()
    pub_path = key_dir / f"{name}.pub"
    pub_data = {
        "type": "engare-public-key-v1",
        "name": name,
        "public": pub_b64,
    }
    pub_path.write_text(json.dumps(pub_data, indent=2))
    return {
        "name": name,
        "path": str(pub_path),
        "fingerprint": fingerprint(pub_bytes),
    }


def fingerprint(pub_bytes: bytes) -> str:
    """Short fingerprint for visual verification."""
    import hashlib
    h = hashlib.sha256(pub_bytes).hexdigest()
    return ":".join(h[i:i+4] for i in range(0, 20, 4))


# ── Helpers ──

def _resolve_key_path(name_or_path: str, suffix: str) -> str:
    """Resolve a key name to its file path."""
    p = Path(name_or_path)
    if p.exists():
        return str(p)
    key_dir = get_key_dir()
    path = key_dir / f"{name_or_path}{suffix}"
    if path.exists():
        return str(path)
    # Try without suffix
    path = key_dir / name_or_path
    if path.exists():
        return str(path)
    raise FileNotFoundError(f"Key not found: {name_or_path}")
