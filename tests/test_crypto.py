"""Tests for the Engare crypto module."""

import pytest
from engare import crypto


def test_keypair_generation():
    priv, pub = crypto.generate_keypair()
    assert priv is not None
    assert pub is not None


def test_shared_key_derivation():
    """Two parties derive the same shared key."""
    priv_a, pub_a = crypto.generate_keypair()
    priv_b, pub_b = crypto.generate_keypair()

    key_ab = crypto.derive_shared_key(priv_a, pub_b)
    key_ba = crypto.derive_shared_key(priv_b, pub_a)

    assert key_ab == key_ba
    assert len(key_ab) == 32


def test_encrypt_decrypt():
    plaintext = b"hidden message in plain sight"
    key = b"\x42" * 32

    ciphertext = crypto.encrypt(plaintext, key)
    decrypted = crypto.decrypt(ciphertext, key)

    assert decrypted == plaintext
    assert ciphertext != plaintext


def test_wrong_key_fails():
    plaintext = b"secret data"
    key = b"\x42" * 32
    wrong_key = b"\x43" * 32

    ciphertext = crypto.encrypt(plaintext, key)

    with pytest.raises(Exception):
        crypto.decrypt(ciphertext, wrong_key)


def test_tampered_data_fails():
    plaintext = b"secret data"
    key = b"\x42" * 32

    ciphertext = crypto.encrypt(plaintext, key)
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 0xFF  # Flip last byte
    tampered = bytes(tampered)

    with pytest.raises(Exception):
        crypto.decrypt(tampered, key)


def test_password_to_key():
    key1, salt = crypto.password_to_key("my-password")
    key2, _ = crypto.password_to_key("my-password", salt)
    key3, _ = crypto.password_to_key("wrong-password", salt)

    assert key1 == key2  # Same password + salt = same key
    assert key1 != key3  # Different password = different key
    assert len(key1) == 32


def test_frame_key_derivation():
    master = b"\x42" * 32
    k0 = crypto.derive_frame_key(master, 0)
    k1 = crypto.derive_frame_key(master, 1)
    k0_again = crypto.derive_frame_key(master, 0)

    assert k0 != k1           # Different frames = different keys
    assert k0 == k0_again     # Same frame = same key
    assert len(k0) == 32


def test_end_to_end_keypair():
    """Full flow: keygen -> exchange -> encrypt -> decrypt."""
    priv_a, pub_a = crypto.generate_keypair()
    priv_b, pub_b = crypto.generate_keypair()

    # Alice encrypts for Bob
    shared_key = crypto.derive_shared_key(priv_a, pub_b)
    plaintext = b"Engare: the ancient art of carrying secrets"
    ciphertext = crypto.encrypt(plaintext, shared_key)

    # Bob decrypts
    shared_key_bob = crypto.derive_shared_key(priv_b, pub_a)
    decrypted = crypto.decrypt(ciphertext, shared_key_bob)

    assert decrypted == plaintext


def test_encrypted_key_storage():
    """Private key encrypted at rest with passphrase."""
    import tempfile, json
    from engare import keys

    tmpdir = tempfile.mkdtemp(prefix="engare_test_keys_")
    original_func = keys.get_key_dir

    try:
        # Monkey-patch key dir to temp
        from pathlib import Path
        keys.get_key_dir = lambda: Path(tmpdir)

        # Generate with passphrase
        result = keys.generate_identity("test-enc", passphrase="my-secret")
        assert result["encrypted"] is True

        # Verify key file is encrypted
        key_data = json.loads(Path(result["private_path"]).read_text())
        assert key_data["type"] == "engare-private-key-v1-encrypted"
        assert "encrypted_private" in key_data
        assert "private" not in key_data  # Raw private key NOT stored

        # Load with correct passphrase
        priv = keys.load_private_key("test-enc", passphrase="my-secret")
        assert priv is not None

        # Load with wrong passphrase
        with pytest.raises(ValueError, match="Wrong passphrase"):
            keys.load_private_key("test-enc", passphrase="wrong")

        # Generate without passphrase (backward compatible)
        result2 = keys.generate_identity("test-plain")
        assert result2["encrypted"] is False
        key_data2 = json.loads(Path(result2["private_path"]).read_text())
        assert key_data2["type"] == "engare-private-key-v1"
        assert "private" in key_data2

    finally:
        keys.get_key_dir = original_func
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
