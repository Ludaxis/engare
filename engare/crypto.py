"""
Engare cryptographic engine.

- X25519 key exchange (modern Diffie-Hellman on Curve25519)
- AES-256-GCM authenticated encryption (tamper-proof)
- HKDF for shared secret derivation
- Scrypt for password-based key derivation

Security: knowing this code does NOT help an attacker.
The security is in the KEY, not the algorithm (Kerckhoffs's Principle).
"""

import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes


# ── Key Exchange ──

def generate_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    """Generate an X25519 key pair for key exchange."""
    private = X25519PrivateKey.generate()
    return private, private.public_key()


def derive_shared_key(
    private_key: X25519PrivateKey,
    peer_public_key: X25519PublicKey,
) -> bytes:
    """
    Compute a shared AES-256 key from X25519 key exchange.
    Both parties arrive at the same key independently.
    """
    shared_secret = private_key.exchange(peer_public_key)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"engare-v1",
    )
    return hkdf.derive(shared_secret)


# ── Password-Based Key Derivation ──

def password_to_key(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Derive a 256-bit key from a password using scrypt.
    Returns (key, salt). Store salt with the ciphertext.
    """
    if salt is None:
        salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    key = kdf.derive(password.encode("utf-8"))
    return key, salt


# ── Authenticated Encryption ──

def encrypt(data: bytes, key: bytes) -> bytes:
    """
    AES-256-GCM authenticated encryption.
    Returns: nonce (12 bytes) + ciphertext + tag (16 bytes).
    Tamper-proof: any modification is detected on decryption.
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt(data: bytes, key: bytes) -> bytes:
    """
    AES-256-GCM authenticated decryption.
    Raises InvalidTag if key is wrong or data was tampered with.
    """
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ── Per-Frame Key Derivation ──

def derive_frame_key(master_key: bytes, frame_index: int) -> bytes:
    """
    Derive a unique key for each frame.
    Prevents pattern analysis across frames.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"engare-frame-" + frame_index.to_bytes(4, "big"),
    )
    return hkdf.derive(master_key)
