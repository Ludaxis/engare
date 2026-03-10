"""
Tests for Engare core library (encode/decode pipeline).

Tests the v2 format (encrypted headers, AAD), v1 backward compat,
deniability, data loss guards, and key resolution.

Does NOT require FFmpeg — all video I/O is mocked.
"""

import struct
from unittest.mock import patch, MagicMock

import numpy as np
import pytest

from engare import crypto, stego, core
from engare.core import (
    KeyConfig, EncodeResult, DecodeResult,
    MAGIC, MAGIC_PWD, MAGIC_V2, V2_VERSION, SCRYPT_N_V1, SCRYPT_N_LOG2_V2,
    resolve_key,
    _v2_build_text, _v2_build_video, _v2_wrap,
    _v2_try_decode, _v2_parse_inner,
    _v1_try_decode_frame,
    _v2_text_overhead, _v2_video_overhead,
)


# ── Helpers ──

def make_frames(n=3, width=128, height=128):
    """Create synthetic RGB frames."""
    return [np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
            for _ in range(n)]


def make_video_info(width=128, height=128, fps=10.0):
    return {"width": width, "height": height, "fps": fps,
            "duration": 1.0, "has_audio": False}


# ── S7: resolve_key tests ──

class TestResolveKey:
    def test_password_mode(self):
        config = KeyConfig(mode="password", password="test123")
        key, salt = resolve_key(config)
        assert len(key) == 32
        assert len(salt) == 16

    def test_keypair_mode_with_objects(self):
        priv, pub = crypto.generate_keypair()
        priv_b, pub_b = crypto.generate_keypair()
        config = KeyConfig(mode="keypair", private_key=priv, public_key=pub_b)
        key, salt = resolve_key(config)
        assert len(key) == 32
        assert salt is None

    def test_keypair_mode_with_bytes(self):
        from cryptography.hazmat.primitives import serialization
        priv_a, pub_a = crypto.generate_keypair()
        priv_b, pub_b = crypto.generate_keypair()

        priv_bytes = priv_a.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = pub_b.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        config = KeyConfig(mode="keypair", private_key=priv_bytes, public_key=pub_bytes)
        key_from_bytes, _ = resolve_key(config)

        config2 = KeyConfig(mode="keypair", private_key=priv_a, public_key=pub_b)
        key_from_objects, _ = resolve_key(config2)

        assert key_from_bytes == key_from_objects

    def test_unknown_mode_raises(self):
        config = KeyConfig(mode="invalid")
        with pytest.raises(ValueError, match="Unknown key mode"):
            resolve_key(config)


# ── S2: AAD tests ──

class TestAAD:
    def test_encrypt_decrypt_with_aad(self):
        key = b"\x42" * 32
        data = b"test data"
        aad = b"\x00\x00\x00\x01"
        ct = crypto.encrypt(data, key, aad=aad)
        pt = crypto.decrypt(ct, key, aad=aad)
        assert pt == data

    def test_wrong_aad_fails(self):
        key = b"\x42" * 32
        data = b"test data"
        ct = crypto.encrypt(data, key, aad=b"\x00\x00\x00\x01")
        with pytest.raises(Exception):
            crypto.decrypt(ct, key, aad=b"\x00\x00\x00\x02")

    def test_aad_none_backward_compat(self):
        key = b"\x42" * 32
        data = b"test data"
        ct = crypto.encrypt(data, key)
        pt = crypto.decrypt(ct, key)
        assert pt == data

    def test_v2_frame_aad_binding(self):
        """v2 payload encrypted with frame_index=0 cannot be decrypted as frame_index=1."""
        master_key = b"\x42" * 32
        msg = b"hello"
        payload = _v2_build_text(msg, master_key, frame_index=0)

        # Correct frame index succeeds
        result = _v2_try_decode(payload, master_key, frame_index=0)
        assert result is not None
        assert result["text"] == "hello"

        # Wrong frame index fails (AAD mismatch)
        result = _v2_try_decode(payload, master_key, frame_index=1)
        assert result is None


# ── S4: Scrypt cost tests ──

class TestScryptCost:
    def test_default_n_is_2_17(self):
        """Default scrypt cost is 2^17 (OWASP minimum)."""
        key1, salt = crypto.password_to_key("test")
        key2, _ = crypto.password_to_key("test", salt, n=2**17)
        assert key1 == key2

    def test_v1_compat_n_2_14(self):
        """v1 backward compat uses n=2^14."""
        key_v1, salt = crypto.password_to_key("test", n=2**14)
        key_v2, _ = crypto.password_to_key("test", salt, n=2**17)
        assert key_v1 != key_v2  # Different cost = different key


# ── S1: v2 Format Tests ──

class TestV2TextPayload:
    def test_build_and_decode_no_salt(self):
        master_key = b"\x42" * 32
        msg = b"secret message"
        payload = _v2_build_text(msg, master_key, frame_index=0)

        result = _v2_try_decode(payload, master_key, 0, has_salt=False)
        assert result is not None
        assert result["type"] == "text"
        assert result["text"] == "secret message"

    def test_build_and_decode_with_salt(self):
        master_key, salt = crypto.password_to_key("testpw")
        msg = b"password-protected text"
        payload = _v2_build_text(msg, master_key, frame_index=0, salt=salt)

        result = _v2_try_decode(payload, master_key, 0, has_salt=True)
        assert result is not None
        assert result["type"] == "text"
        assert result["text"] == "password-protected text"

    def test_wrong_key_returns_none(self):
        master_key = b"\x42" * 32
        wrong_key = b"\x43" * 32
        payload = _v2_build_text(b"msg", master_key, frame_index=0)

        result = _v2_try_decode(payload, wrong_key, 0)
        assert result is None

    def test_no_cleartext_magic(self):
        """v2 payloads must NOT have ENG1/ENP1/ENG2 at offset 0."""
        master_key = b"\x42" * 32
        payload = _v2_build_text(b"test", master_key, frame_index=0)

        assert payload[:4] != MAGIC
        assert payload[:4] != MAGIC_PWD
        assert payload[:4] != MAGIC_V2

    def test_random_prefix_varies(self):
        """Each v2 payload has a different random prefix."""
        master_key = b"\x42" * 32
        p1 = _v2_build_text(b"test", master_key, frame_index=0)
        p2 = _v2_build_text(b"test", master_key, frame_index=0)
        assert p1[:4] != p2[:4]  # Random prefixes differ


class TestV2VideoPayload:
    def test_build_and_decode(self):
        master_key = b"\x42" * 32
        pixels = np.random.randint(0, 256, (32, 48, 3), dtype=np.uint8).tobytes()
        payload = _v2_build_video(pixels, 48, 32, 10, 0, master_key)

        result = _v2_try_decode(payload, master_key, 0)
        assert result is not None
        assert result["type"] == "video"
        assert result["index"] == 0
        assert result["frame"].shape == (32, 48, 3)


class TestV2Deniability:
    def test_lsb_indistinguishable_without_key(self):
        """Extracted LSBs from a v2 stego frame look like noise, not a pattern."""
        master_key = b"\x42" * 32
        frame = np.random.randint(0, 256, (128, 128, 3), dtype=np.uint8)
        cap = stego.capacity(128, 128)

        payload = _v2_build_text(b"secret", master_key, frame_index=0)
        payload += b"\x00" * (cap - len(payload))
        stego_frame = stego.embed(frame, payload)

        # Extract raw bytes (what an adversary would see)
        raw = stego.extract(stego_frame, cap)

        # No magic bytes at any known offset
        assert raw[:4] != MAGIC
        assert raw[:4] != MAGIC_PWD
        assert raw[:4] != MAGIC_V2

        # Without the key, decryption fails
        wrong_key = b"\x43" * 32
        assert _v2_try_decode(raw, wrong_key, 0) is None

    def test_wrong_password_returns_not_found(self):
        """Wrong password -> DecodeResult(found=False), no crash."""
        correct_key, salt = crypto.password_to_key("correct")
        payload = _v2_build_text(b"secret", correct_key, frame_index=0, salt=salt)

        wrong_key, _ = crypto.password_to_key("wrong", salt)
        result = _v2_try_decode(payload, wrong_key, 0, has_salt=True)
        assert result is None


# ── S1: v1 Backward Compat ──

class TestV1BackwardCompat:
    def test_v1_keypair_text_decode(self):
        """v1 ENG1 text payload decodes correctly."""
        master_key = b"\x42" * 32
        message = b"v1 keypair text"
        frame_key = crypto.derive_frame_key(master_key, 0)
        encrypted = crypto.encrypt(message, frame_key)

        header = MAGIC + struct.pack(">BH", ord("T"), len(message))
        payload = header + struct.pack(">I", len(encrypted)) + encrypted

        result = _v1_try_decode_frame(payload, master_key, 0, data_offset=4)
        assert result is not None
        assert result["type"] == "text"
        assert result["text"] == "v1 keypair text"

    def test_v1_password_text_decode(self):
        """v1 ENP1 text payload decodes correctly."""
        master_key, salt = crypto.password_to_key("test", n=SCRYPT_N_V1)
        message = b"v1 password text"
        frame_key = crypto.derive_frame_key(master_key, 0)
        encrypted = crypto.encrypt(message, frame_key)

        header = MAGIC_PWD + salt + struct.pack(">BH", ord("T"), len(message))
        payload = header + struct.pack(">I", len(encrypted)) + encrypted

        result = _v1_try_decode_frame(payload, master_key, 0, data_offset=20)
        assert result is not None
        assert result["type"] == "text"
        assert result["text"] == "v1 password text"

    def test_v1_wrong_key_returns_none(self):
        """Wrong key on v1 payload returns None, no crash."""
        master_key = b"\x42" * 32
        wrong_key = b"\x43" * 32
        message = b"secret"
        frame_key = crypto.derive_frame_key(master_key, 0)
        encrypted = crypto.encrypt(message, frame_key)

        header = MAGIC + struct.pack(">BH", ord("T"), len(message))
        payload = header + struct.pack(">I", len(encrypted)) + encrypted

        result = _v1_try_decode_frame(payload, wrong_key, 0, data_offset=4)
        assert result is None


# ── S13: Data Loss Guard ──

class TestDataLossGuard:
    def test_text_too_large_raises(self):
        """Message larger than frame capacity raises ValueError."""
        cap = stego.capacity(16, 16)  # Tiny frame
        overhead = _v2_text_overhead(False)
        big_message = "A" * (cap - overhead + 1)

        frames = make_frames(1, 16, 16)
        info = make_video_info(16, 16)

        with patch("engare.core.video") as mock_video:
            mock_video.read_frames.return_value = (frames, info)
            mock_video.extract_audio.return_value = False

            config = KeyConfig(mode="keypair", private_key=b"\x42" * 32,
                               public_key=b"\x43" * 32)
            # Monkeypatch resolve_key to avoid real ECDH
            with patch("engare.core.resolve_key", return_value=(b"\x42" * 32, None)):
                with pytest.raises(ValueError, match="too large"):
                    core.encode_text("cover.mkv", big_message, config, "out.mkv")


# ── S1: v2 Full Encode/Decode Integration (mocked video I/O) ──

class TestV2EncodeDecodeIntegration:
    def _mock_encode_decode(self, key_config, message="test message"):
        """Helper: encode text, then decode it, using mocked video I/O."""
        frames = make_frames(3, 128, 128)
        info = make_video_info(128, 128)
        cap = stego.capacity(128, 128)

        # Capture written frames
        written_frames = []

        def mock_write_frames(frs, output, fps, codec="ffv1", audio=None):
            written_frames.extend(frs)

        with patch("engare.core.video") as mock_video:
            mock_video.read_frames.return_value = (frames, info)
            mock_video.extract_audio.return_value = False
            mock_video.write_frames.side_effect = mock_write_frames
            mock_video.video_to_key = video_to_key_stub

            result = core.encode_text("cover.mkv", message, key_config, "out.mkv")

        assert len(written_frames) == 3

        # Now decode the written frames
        with patch("engare.core.video") as mock_video:
            mock_video.read_frames.return_value = (written_frames, info)

            decode_result = core.decode("out.mkv", key_config)

        return decode_result

    def test_password_roundtrip(self):
        config = KeyConfig(mode="password", password="testpass")
        result = self._mock_encode_decode(config, "password roundtrip")
        assert result.found is True
        assert result.content_type == "text"
        assert result.message == "password roundtrip"

    def test_keypair_roundtrip(self):
        priv_a, pub_a = crypto.generate_keypair()
        priv_b, pub_b = crypto.generate_keypair()

        encode_config = KeyConfig(mode="keypair", private_key=priv_a, public_key=pub_b)
        decode_config = KeyConfig(mode="keypair", private_key=priv_b, public_key=pub_a)

        frames = make_frames(3, 128, 128)
        info = make_video_info(128, 128)
        written_frames = []

        def mock_write(frs, output, fps, codec="ffv1", audio=None):
            written_frames.extend(frs)

        with patch("engare.core.video") as mock_video:
            mock_video.read_frames.return_value = (frames, info)
            mock_video.extract_audio.return_value = False
            mock_video.write_frames.side_effect = mock_write
            core.encode_text("cover.mkv", "keypair test", encode_config, "out.mkv")

        with patch("engare.core.video") as mock_video:
            mock_video.read_frames.return_value = (written_frames, info)
            result = core.decode("out.mkv", decode_config)

        assert result.found is True
        assert result.message == "keypair test"

    def test_wrong_password_not_found(self):
        """Wrong password must return found=False, not crash."""
        config_enc = KeyConfig(mode="password", password="correct")
        config_dec = KeyConfig(mode="password", password="wrong")

        frames = make_frames(3, 128, 128)
        info = make_video_info(128, 128)
        written_frames = []

        def mock_write(frs, output, fps, codec="ffv1", audio=None):
            written_frames.extend(frs)

        with patch("engare.core.video") as mock_video:
            mock_video.read_frames.return_value = (frames, info)
            mock_video.extract_audio.return_value = False
            mock_video.write_frames.side_effect = mock_write
            core.encode_text("cover.mkv", "secret", config_enc, "out.mkv")

        with patch("engare.core.video") as mock_video:
            mock_video.read_frames.return_value = (written_frames, info)
            result = core.decode("out.mkv", config_dec)

        assert result.found is False

    def test_progress_callback(self):
        config = KeyConfig(mode="password", password="test")
        frames = make_frames(3, 128, 128)
        info = make_video_info(128, 128)
        progress_calls = []

        def mock_write(frs, output, fps, codec="ffv1", audio=None):
            pass

        with patch("engare.core.video") as mock_video:
            mock_video.read_frames.return_value = (frames, info)
            mock_video.extract_audio.return_value = False
            mock_video.write_frames.side_effect = mock_write
            core.encode_text("cover.mkv", "test", config, "out.mkv",
                             on_progress=lambda cur, tot: progress_calls.append((cur, tot)))

        assert len(progress_calls) == 3
        assert progress_calls[0] == (1, 3)
        assert progress_calls[2] == (3, 3)


# Stub for video_to_key in mocked context
def video_to_key_stub(path):
    import hashlib
    return hashlib.sha256(path.encode()).digest()
