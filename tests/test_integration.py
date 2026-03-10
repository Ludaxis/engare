"""
Integration tests for the Engare encode/decode pipeline.
Requires FFmpeg to be installed.
"""

import os
import shutil
import struct
import tempfile

import numpy as np
import pytest
from PIL import Image

from engare import crypto, stego
from engare.cli import MAGIC, MAGIC_PWD


HAS_FFMPEG = shutil.which("ffmpeg") is not None
needs_ffmpeg = pytest.mark.skipif(not HAS_FFMPEG, reason="FFmpeg required")


def make_test_video(path, width=64, height=64, frames=5, fps=10, color=(255, 0, 0)):
    """Create a small synthetic video for testing."""
    tmpdir = tempfile.mkdtemp()
    try:
        for i in range(frames):
            img = Image.new("RGB", (width, height), color)
            img.save(os.path.join(tmpdir, f"frame_{i:06d}.png"))
        import subprocess
        subprocess.run([
            "ffmpeg", "-y", "-framerate", str(fps),
            "-i", os.path.join(tmpdir, "frame_%06d.png"),
            "-c:v", "ffv1", "-pix_fmt", "rgb24",
            path,
        ], capture_output=True)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@needs_ffmpeg
class TestPasswordTextRoundtrip:
    """Encode text with password, decode with same password."""

    def test_roundtrip(self):
        tmpdir = tempfile.mkdtemp(prefix="engare_test_")
        try:
            cover = os.path.join(tmpdir, "cover.mkv")
            stego_out = os.path.join(tmpdir, "stego.mkv")
            make_test_video(cover, width=128, height=128, frames=3)

            password = "test-password-123"
            message = "Engare integration test message"

            # Encode
            from engare import video
            master_key, salt = crypto.password_to_key(password)
            cover_info = video.get_info(cover)
            cap = stego.capacity(cover_info["width"], cover_info["height"])

            cover_dir = os.path.join(tmpdir, "cover_frames")
            num_cover = video.extract_frames(cover, cover_dir)

            stego_dir = os.path.join(tmpdir, "stego_frames")
            os.makedirs(stego_dir)

            secret_data = message.encode("utf-8")
            for ci in range(num_cover):
                cf = os.path.join(cover_dir, f"frame_{ci:06d}.png")
                cover_img = video.load_frame(cf)
                frame_key = crypto.derive_frame_key(master_key, ci)
                encrypted = crypto.encrypt(secret_data, frame_key)

                magic_header = MAGIC_PWD + salt
                header = magic_header + struct.pack(">BH", ord("T"), len(secret_data))
                payload = header + struct.pack(">I", len(encrypted)) + encrypted
                payload += b"\x00" * (cap - len(payload))

                stego_frame = stego.embed(cover_img, payload)
                video.save_frame(stego_frame, os.path.join(stego_dir, f"frame_{ci:06d}.png"))

            video.build_video(stego_dir, stego_out, cover_info["fps"])
            assert os.path.exists(stego_out)

            # Decode
            dec_dir = os.path.join(tmpdir, "dec_frames")
            num_dec = video.extract_frames(stego_out, dec_dir)

            decoded_msg = None
            for fi in range(num_dec):
                ff = os.path.join(dec_dir, f"frame_{fi:06d}.png")
                img = video.load_frame(ff)
                payload = stego.extract(img, cap)

                if payload[:4] == MAGIC_PWD:
                    embedded_salt = payload[4:20]
                    dec_key, _ = crypto.password_to_key(password, embedded_salt)
                    frame_key = crypto.derive_frame_key(dec_key, fi)

                    o = 20  # data offset after "ENP1" + salt
                    stype = chr(payload[o])
                    text_len = struct.unpack(">H", payload[o+1:o+3])[0]
                    enc_len = struct.unpack(">I", payload[o+3:o+7])[0]
                    enc_data = payload[o+7:o+7 + enc_len]

                    dec = crypto.decrypt(enc_data, frame_key)
                    decoded_msg = dec[:text_len].decode("utf-8")
                    break

            assert decoded_msg == message

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


@needs_ffmpeg
class TestWrongPasswordDeniability:
    """Wrong password must produce no error — deniability is sacred."""

    def test_wrong_password_no_crash(self):
        tmpdir = tempfile.mkdtemp(prefix="engare_test_")
        try:
            cover = os.path.join(tmpdir, "cover.mkv")
            stego_out = os.path.join(tmpdir, "stego.mkv")
            make_test_video(cover, width=128, height=128, frames=3)

            # Encode with correct password
            from engare import video
            master_key, salt = crypto.password_to_key("correct-password")
            cover_info = video.get_info(cover)
            cap = stego.capacity(cover_info["width"], cover_info["height"])

            cover_dir = os.path.join(tmpdir, "cover_frames")
            num_cover = video.extract_frames(cover, cover_dir)

            stego_dir = os.path.join(tmpdir, "stego_frames")
            os.makedirs(stego_dir)

            secret_data = b"secret message"
            for ci in range(num_cover):
                cf = os.path.join(cover_dir, f"frame_{ci:06d}.png")
                cover_img = video.load_frame(cf)
                frame_key = crypto.derive_frame_key(master_key, ci)
                encrypted = crypto.encrypt(secret_data, frame_key)

                magic_header = MAGIC_PWD + salt
                header = magic_header + struct.pack(">BH", ord("T"), len(secret_data))
                payload = header + struct.pack(">I", len(encrypted)) + encrypted
                payload += b"\x00" * (cap - len(payload))

                stego_frame = stego.embed(cover_img, payload)
                video.save_frame(stego_frame, os.path.join(stego_dir, f"frame_{ci:06d}.png"))

            video.build_video(stego_dir, stego_out, cover_info["fps"])

            # Try to decode with WRONG password — must not crash
            dec_dir = os.path.join(tmpdir, "dec_frames")
            num_dec = video.extract_frames(stego_out, dec_dir)

            found_message = False
            for fi in range(num_dec):
                ff = os.path.join(dec_dir, f"frame_{fi:06d}.png")
                img = video.load_frame(ff)
                payload = stego.extract(img, cap)

                if payload[:4] == MAGIC_PWD:
                    embedded_salt = payload[4:20]
                    wrong_key, _ = crypto.password_to_key("WRONG-password", embedded_salt)
                    frame_key = crypto.derive_frame_key(wrong_key, fi)

                    o = 20
                    try:
                        enc_len = struct.unpack(">I", payload[o+3:o+7])[0]
                        enc_data = payload[o+7:o+7 + enc_len]
                        crypto.decrypt(enc_data, frame_key)
                        found_message = True  # Should NOT reach here
                    except Exception:
                        pass  # Expected — wrong key fails silently

            assert not found_message, "Wrong password should NOT decrypt successfully"

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


@needs_ffmpeg
class TestKeypairTextRoundtrip:
    """Encode with keypair, decode with matching keypair."""

    def test_roundtrip(self):
        tmpdir = tempfile.mkdtemp(prefix="engare_test_")
        try:
            cover = os.path.join(tmpdir, "cover.mkv")
            stego_out = os.path.join(tmpdir, "stego.mkv")
            make_test_video(cover, width=128, height=128, frames=3)

            # Generate two key pairs
            priv_a, pub_a = crypto.generate_keypair()
            priv_b, pub_b = crypto.generate_keypair()

            # Alice encrypts for Bob
            shared_key = crypto.derive_shared_key(priv_a, pub_b)
            message = "keypair roundtrip test"

            from engare import video
            cover_info = video.get_info(cover)
            cap = stego.capacity(cover_info["width"], cover_info["height"])

            cover_dir = os.path.join(tmpdir, "cover_frames")
            num_cover = video.extract_frames(cover, cover_dir)

            stego_dir = os.path.join(tmpdir, "stego_frames")
            os.makedirs(stego_dir)

            secret_data = message.encode("utf-8")
            for ci in range(num_cover):
                cf = os.path.join(cover_dir, f"frame_{ci:06d}.png")
                cover_img = video.load_frame(cf)
                frame_key = crypto.derive_frame_key(shared_key, ci)
                encrypted = crypto.encrypt(secret_data, frame_key)

                header = struct.pack(">4sBH", MAGIC, ord("T"), len(secret_data))
                payload = header + struct.pack(">I", len(encrypted)) + encrypted
                payload += b"\x00" * (cap - len(payload))

                stego_frame = stego.embed(cover_img, payload)
                video.save_frame(stego_frame, os.path.join(stego_dir, f"frame_{ci:06d}.png"))

            video.build_video(stego_dir, stego_out, cover_info["fps"])

            # Bob decodes
            bob_shared = crypto.derive_shared_key(priv_b, pub_a)
            assert bob_shared == shared_key

            dec_dir = os.path.join(tmpdir, "dec_frames")
            video.extract_frames(stego_out, dec_dir)

            ff = os.path.join(dec_dir, "frame_000000.png")
            img = video.load_frame(ff)
            payload = stego.extract(img, cap)

            assert payload[:4] == MAGIC
            frame_key = crypto.derive_frame_key(bob_shared, 0)
            text_len = struct.unpack(">H", payload[5:7])[0]
            enc_len = struct.unpack(">I", payload[7:11])[0]
            enc_data = payload[11:11 + enc_len]
            dec = crypto.decrypt(enc_data, frame_key)
            assert dec[:text_len].decode("utf-8") == message

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestSaltEmbedding:
    """Verify salt is correctly embedded and extractable."""

    def test_salt_in_payload(self):
        cover = np.random.randint(0, 256, (128, 128, 3), dtype=np.uint8)
        cap = stego.capacity(128, 128)

        password = "test-salt-embedding"
        key, salt = crypto.password_to_key(password)
        assert len(salt) == 16

        # Build payload with salt
        message = b"salt test"
        frame_key = crypto.derive_frame_key(key, 0)
        encrypted = crypto.encrypt(message, frame_key)

        magic_header = MAGIC_PWD + salt
        header = magic_header + struct.pack(">BH", ord("T"), len(message))
        payload = header + struct.pack(">I", len(encrypted)) + encrypted
        payload += b"\x00" * (cap - len(payload))

        stego_frame = stego.embed(cover, payload)
        extracted = stego.extract(stego_frame, cap)

        # Verify magic and salt
        assert extracted[:4] == MAGIC_PWD
        extracted_salt = extracted[4:20]
        assert extracted_salt == salt

        # Derive key from extracted salt
        key2, _ = crypto.password_to_key(password, extracted_salt)
        assert key2 == key

        # Decrypt
        o = 20
        frame_key2 = crypto.derive_frame_key(key2, 0)
        enc_len = struct.unpack(">I", extracted[o+3:o+7])[0]
        enc_data = extracted[o+7:o+7 + enc_len]
        dec = crypto.decrypt(enc_data, frame_key2)
        assert dec[:len(message)] == message


@needs_ffmpeg
class TestH264LosslessRoundtrip:
    """Verify H.264 lossless (libx264rgb) preserves steganographic data."""

    def test_roundtrip(self):
        tmpdir = tempfile.mkdtemp(prefix="engare_test_")
        try:
            from engare import video

            # Check if libx264rgb is available
            import subprocess
            r = subprocess.run(["ffmpeg", "-codecs"], capture_output=True, text=True)
            if "libx264rgb" not in r.stdout:
                pytest.skip("libx264rgb not available in this FFmpeg build")

            # Create stego frame with embedded data
            frame = np.random.randint(0, 256, (128, 128, 3), dtype=np.uint8)
            cap = stego.capacity(128, 128)

            password = "h264-test"
            key, salt = crypto.password_to_key(password)
            message = b"H.264 lossless roundtrip test"
            frame_key = crypto.derive_frame_key(key, 0)
            encrypted = crypto.encrypt(message, frame_key)

            magic_header = MAGIC_PWD + salt
            header = magic_header + struct.pack(">BH", ord("T"), len(message))
            payload = header + struct.pack(">I", len(encrypted)) + encrypted
            payload += b"\x00" * (cap - len(payload))

            stego_frame = stego.embed(frame, payload)

            # Save as PNG, build H.264 video, extract back
            stego_dir = os.path.join(tmpdir, "stego_frames")
            os.makedirs(stego_dir)
            video.save_frame(stego_frame, os.path.join(stego_dir, "frame_000000.png"))

            h264_out = os.path.join(tmpdir, "stego.mp4")
            video.build_video(stego_dir, h264_out, 10, codec="h264")
            assert os.path.exists(h264_out)

            # Extract frame from H.264 and verify data survives
            dec_dir = os.path.join(tmpdir, "dec_frames")
            video.extract_frames(h264_out, dec_dir)
            dec_frame = video.load_frame(os.path.join(dec_dir, "frame_000000.png"))
            extracted = stego.extract(dec_frame, cap)

            assert extracted[:4] == MAGIC_PWD
            embedded_salt = extracted[4:20]
            assert embedded_salt == salt

            key2, _ = crypto.password_to_key(password, embedded_salt)
            frame_key2 = crypto.derive_frame_key(key2, 0)
            o = 20
            enc_len = struct.unpack(">I", extracted[o+3:o+7])[0]
            enc_data = extracted[o+7:o+7 + enc_len]
            dec = crypto.decrypt(enc_data, frame_key2)
            assert dec[:len(message)] == message

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestStegoPerformance:
    """Verify vectorized stego operations are fast enough."""

    def test_embed_extract_speed(self):
        import time

        frame = np.random.randint(0, 256, (720, 1280, 3), dtype=np.uint8)
        cap = stego.capacity(1280, 720)
        data = bytes(np.random.randint(0, 256, cap, dtype=np.uint8))

        start = time.perf_counter()
        result = stego.embed(frame, data)
        embed_ms = (time.perf_counter() - start) * 1000

        start = time.perf_counter()
        extracted = stego.extract(result, cap)
        extract_ms = (time.perf_counter() - start) * 1000

        assert extracted == data, "Roundtrip data mismatch"
        # 720p embed should be under 200ms (vectorized), extract under 50ms
        assert embed_ms < 200, f"Embed too slow: {embed_ms:.0f}ms"
        assert extract_ms < 50, f"Extract too slow: {extract_ms:.0f}ms"
