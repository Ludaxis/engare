"""
Engare core library — encode/decode API for any frontend.

This module exposes the encode/decode pipeline as clean functions
that any frontend (CLI, GUI, web, TUI) can call.

v2 format (default): encrypted headers, random prefix, AAD-bound frames.
v1 format: cleartext magic bytes (ENG1/ENP1). Supported for decode only.
"""

import os
import struct
from dataclasses import dataclass

import numpy as np
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from PIL import Image

from . import crypto, stego, video


# ── Format Constants ──

# v1 (legacy, decode-only)
MAGIC = b"ENG1"
MAGIC_PWD = b"ENP1"
SCRYPT_N_V1 = 2**14

# v2 (current)
MAGIC_V2 = b"ENG2"
V2_VERSION = 2
SCRYPT_N_LOG2_V2 = 17  # log2(2**17)


# ── Data Classes ──

@dataclass
class KeyConfig:
    """Encryption key configuration."""
    mode: str  # "password", "keypair", or "video-key"
    password: str | None = None
    private_key: bytes | None = None
    public_key: bytes | None = None
    video_key_path: str | None = None


@dataclass
class EncodeResult:
    """Result of an encode operation."""
    output_path: str
    size_bytes: int
    num_frames: int
    codec: str


@dataclass
class DecodeResult:
    """Result of a decode operation."""
    found: bool
    content_type: str | None = None  # "text", "video", or None
    message: str | None = None
    output_path: str | None = None
    num_frames: int = 0


# ── Key Resolution ──

def resolve_key(config: KeyConfig) -> tuple[bytes, bytes | None]:
    """Resolve a KeyConfig to (master_key, salt_or_none)."""
    if config.mode == "password":
        return crypto.password_to_key(config.password)
    elif config.mode == "video-key":
        return video.video_to_key(config.video_key_path), None
    elif config.mode == "keypair":
        priv = config.private_key
        pub = config.public_key
        if isinstance(priv, bytes):
            priv = X25519PrivateKey.from_private_bytes(priv)
        if isinstance(pub, bytes):
            pub = X25519PublicKey.from_public_bytes(pub)
        return crypto.derive_shared_key(priv, pub), None
    else:
        raise ValueError(f"Unknown key mode: {config.mode}")


# ── v2 Payload Building ──

def _v2_build_text(message_bytes: bytes, master_key: bytes, frame_index: int,
                   salt: bytes | None = None) -> bytes:
    """Build a v2 payload for a text message.

    Inner (encrypted): ENG2(4) + version(1) + n_log2(1) + type(1,'T') + text_len(2) + text
    Outer non-pwd:     random(4) + enc_len(4) + ciphertext
    Outer password:    random(4) + salt(16) + enc_len(4) + ciphertext
    """
    n_log2 = SCRYPT_N_LOG2_V2 if salt is not None else 0
    inner = (MAGIC_V2 +
             struct.pack(">BBB", V2_VERSION, n_log2, ord("T")) +
             struct.pack(">H", len(message_bytes)) +
             message_bytes)
    return _v2_wrap(inner, master_key, frame_index, salt)


def _v2_build_video(pixel_data: bytes, width: int, height: int,
                    total_frames: int, frame_index: int,
                    master_key: bytes,
                    salt: bytes | None = None) -> bytes:
    """Build a v2 payload for a video frame.

    Inner (encrypted): ENG2(4) + version(1) + n_log2(1) + type(1,'V')
                       + width(2) + height(2) + total(4) + idx(4) + pixels
    """
    n_log2 = SCRYPT_N_LOG2_V2 if salt is not None else 0
    inner = (MAGIC_V2 +
             struct.pack(">BBB", V2_VERSION, n_log2, ord("V")) +
             struct.pack(">HHII", width, height, total_frames, frame_index) +
             pixel_data)
    return _v2_wrap(inner, master_key, frame_index, salt)


def _v2_wrap(inner: bytes, master_key: bytes, frame_index: int,
             salt: bytes | None) -> bytes:
    """Encrypt inner payload and build outer v2 frame."""
    aad = frame_index.to_bytes(4, "big")
    frame_key = crypto.derive_frame_key(master_key, frame_index)
    encrypted = crypto.encrypt(inner, frame_key, aad=aad)

    random_prefix = os.urandom(4)
    enc_len = struct.pack(">I", len(encrypted))

    if salt is not None:
        return random_prefix + salt + enc_len + encrypted
    else:
        return random_prefix + enc_len + encrypted


# ── v2 Overhead Constants ──

def _v2_text_overhead(has_salt: bool) -> int:
    """Total payload overhead for v2 text (excluding message bytes)."""
    # outer: random(4) + [salt(16)] + enc_len(4) + nonce(12) + tag(16)
    # inner: ENG2(4) + version(1) + n_log2(1) + type(1) + text_len(2)
    outer = 4 + (16 if has_salt else 0) + 4 + 12 + 16
    inner = 4 + 1 + 1 + 1 + 2
    return outer + inner


def _v2_video_overhead(has_salt: bool) -> int:
    """Total payload overhead for v2 video (excluding pixel bytes)."""
    outer = 4 + (16 if has_salt else 0) + 4 + 12 + 16
    inner = 4 + 1 + 1 + 1 + 2 + 2 + 4 + 4  # ENG2 + ver + n + type + w + h + total + idx
    return outer + inner


# ── v2 Decoding ──

def _v2_try_decode(payload: bytes, master_key: bytes, frame_index: int,
                   has_salt: bool = False) -> dict | None:
    """Try to decode a frame as v2 format. Returns parsed inner or None."""
    try:
        if has_salt:
            if len(payload) < 24:
                return None
            enc_len = struct.unpack(">I", payload[20:24])[0]
            offset = 24
        else:
            if len(payload) < 8:
                return None
            enc_len = struct.unpack(">I", payload[4:8])[0]
            offset = 8

        if offset + enc_len > len(payload) or enc_len == 0:
            return None

        enc_data = payload[offset:offset + enc_len]
        aad = frame_index.to_bytes(4, "big")
        frame_key = crypto.derive_frame_key(master_key, frame_index)
        inner = crypto.decrypt(enc_data, frame_key, aad=aad)

        if len(inner) < 7 or inner[:4] != MAGIC_V2:
            return None

        return _v2_parse_inner(inner)
    except Exception:
        return None


def _v2_parse_inner(inner: bytes) -> dict | None:
    """Parse decrypted v2 inner payload."""
    # ENG2(4) + version(1) + n_log2(1) + type(1)
    stype = chr(inner[6])

    if stype == "T":
        text_len = struct.unpack(">H", inner[7:9])[0]
        text_data = inner[9:9 + text_len]
        return {"type": "text", "text": text_data.decode("utf-8")}

    elif stype == "V":
        sw = struct.unpack(">H", inner[7:9])[0]
        sh = struct.unpack(">H", inner[9:11])[0]
        total = struct.unpack(">I", inner[11:15])[0]
        idx = struct.unpack(">I", inner[15:19])[0]
        pixel_data = inner[19:]
        frame = np.frombuffer(pixel_data, dtype=np.uint8).reshape((sh, sw, 3))
        return {"type": "video", "frame": frame, "index": idx}

    return None


# ── v1 Decoding (backward compat) ──

def _v1_try_decode_frame(payload: bytes, master_key: bytes, frame_index: int,
                         data_offset: int) -> dict | None:
    """Try to decode a frame using v1 format."""
    try:
        stype = chr(payload[data_offset])
        frame_key = crypto.derive_frame_key(master_key, frame_index)

        if stype == "T":
            o = data_offset + 1
            text_len = struct.unpack(">H", payload[o:o+2])[0]
            enc_len = struct.unpack(">I", payload[o+2:o+6])[0]
            enc_data = payload[o+6:o+6 + enc_len]
            dec = crypto.decrypt(enc_data, frame_key)
            return {"type": "text", "text": dec[:text_len].decode("utf-8")}

        elif stype == "V":
            o = data_offset + 1
            sw = struct.unpack(">H", payload[o:o+2])[0]
            sh = struct.unpack(">H", payload[o+2:o+4])[0]
            idx = struct.unpack(">I", payload[o+8:o+12])[0]
            enc_len = struct.unpack(">I", payload[o+12:o+16])[0]
            enc_data = payload[o+16:o+16 + enc_len]
            dec = crypto.decrypt(enc_data, frame_key)
            frame = np.frombuffer(dec, dtype=np.uint8).reshape((sh, sw, 3))
            return {"type": "video", "frame": frame, "index": idx}
    except Exception:
        pass
    return None


# ── Encode ──

def encode_text(cover_path: str, message: str, key_config: KeyConfig,
                output_path: str, codec: str = "ffv1",
                on_progress=None) -> EncodeResult:
    """Encode a text message into a cover video (v2 format).

    on_progress: optional callback(current_frame, total_frames)
    """
    master_key, salt = resolve_key(key_config)
    cover_frames, cover_info = video.read_frames(cover_path)
    num_cover = len(cover_frames)
    cap = stego.capacity(cover_info["width"], cover_info["height"])

    secret_data = message.encode("utf-8")
    has_salt = salt is not None

    # Check capacity on first frame (all frames have same overhead)
    overhead = _v2_text_overhead(has_salt)
    if overhead + len(secret_data) > cap:
        raise ValueError(
            f"Message too large: payload {overhead + len(secret_data)} bytes exceeds "
            f"frame capacity {cap} bytes"
        )

    stego_frames = []
    for ci in range(num_cover):
        payload = _v2_build_text(secret_data, master_key, ci, salt=salt)
        payload += b"\x00" * (cap - len(payload))
        stego_frames.append(stego.embed(cover_frames[ci], payload))

        if on_progress:
            on_progress(ci + 1, num_cover)

    # Extract audio for muxing
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp(prefix="engare_")
    try:
        audio_path = os.path.join(tmpdir, "audio.aac")
        has_audio = video.extract_audio(cover_path, audio_path)
        video.write_frames(stego_frames, output_path, cover_info["fps"],
                           codec=codec, audio=audio_path if has_audio else None)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
    return EncodeResult(output_path=output_path, size_bytes=size,
                        num_frames=num_cover, codec=codec)


def encode_video(cover_path: str, secret_path: str, key_config: KeyConfig,
                 output_path: str, codec: str = "ffv1",
                 on_progress=None) -> EncodeResult:
    """Encode a secret video into a cover video (v2 format).

    on_progress: optional callback(current_frame, total_frames)
    """
    master_key, salt = resolve_key(key_config)
    cover_frames, cover_info = video.read_frames(cover_path)
    secret_frames, secret_info = video.read_frames(secret_path)
    num_cover = len(cover_frames)
    num_secret = len(secret_frames)
    cap = stego.capacity(cover_info["width"], cover_info["height"])

    has_salt = salt is not None
    overhead = _v2_video_overhead(has_salt)
    available = cap - overhead
    aspect = secret_info["width"] / secret_info["height"]
    sh = int((available / 3 / aspect) ** 0.5)
    sw = int(sh * aspect)
    sw = min(sw, 240) & ~1
    sh = min(sh, 180) & ~1

    if sw < 16 or sh < 16:
        raise ValueError("Cover video too small to hide secret video")

    stego_frames = []
    for ci in range(num_cover):
        si = ci % num_secret
        sec_img = Image.fromarray(secret_frames[si]).resize((sw, sh), Image.LANCZOS)
        sec_bytes = np.array(sec_img).tobytes()

        payload = _v2_build_video(sec_bytes, sw, sh, num_secret, si,
                                  master_key, salt=salt)
        if len(payload) > cap:
            raise ValueError(
                f"Secret video payload too large: {len(payload)} bytes exceeds "
                f"frame capacity {cap} bytes"
            )
        payload += b"\x00" * (cap - len(payload))
        stego_frames.append(stego.embed(cover_frames[ci], payload))

        if on_progress:
            on_progress(ci + 1, num_cover)

    import tempfile, shutil
    tmpdir = tempfile.mkdtemp(prefix="engare_")
    try:
        audio_path = os.path.join(tmpdir, "audio.aac")
        has_audio = video.extract_audio(cover_path, audio_path)
        video.write_frames(stego_frames, output_path, cover_info["fps"],
                           codec=codec, audio=audio_path if has_audio else None)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
    return EncodeResult(output_path=output_path, size_bytes=size,
                        num_frames=num_cover, codec=codec)


# ── Decode ──

def decode(input_path: str, key_config: KeyConfig,
           output_path: str | None = None,
           on_progress=None) -> DecodeResult:
    """Decode hidden content from a stego video.

    Tries v2 format first (encrypted headers), then falls back to v1
    (cleartext ENG1/ENP1 magic) for backward compatibility.

    on_progress: optional callback(current_frame, total_frames)
    Returns DecodeResult with content_type and either message or output_path.
    """
    frames, info = video.read_frames(input_path)
    num = len(frames)
    cap = stego.capacity(info["width"], info["height"])

    if num == 0:
        return DecodeResult(found=False)

    # ── Phase 1: Probe frame 0 to determine format and derive master key ──

    payload0 = stego.extract(frames[0], cap)
    master_key = None
    fmt = None  # "v2", "v2-pwd", "v1-std", "v1-pwd"

    if key_config.mode == "password" and key_config.password:
        # Try v2 password: salt at payload[4:20]
        salt_v2 = payload0[4:20]
        try:
            mk_v2, _ = crypto.password_to_key(key_config.password, salt_v2)
            result = _v2_try_decode(payload0, mk_v2, 0, has_salt=True)
            if result is not None:
                master_key = mk_v2
                fmt = "v2-pwd"
        except Exception:
            pass

        # Try v1 ENP1 fallback
        if fmt is None and payload0[:4] == MAGIC_PWD:
            salt_v1 = payload0[4:20]
            try:
                mk_v1, _ = crypto.password_to_key(key_config.password, salt_v1,
                                                  n=SCRYPT_N_V1)
                master_key = mk_v1
                fmt = "v1-pwd"
            except Exception:
                pass
    else:
        # keypair or video-key: derive master key once
        try:
            mk, _ = resolve_key(key_config)
        except Exception:
            return DecodeResult(found=False)

        # Try v2 non-password
        result = _v2_try_decode(payload0, mk, 0, has_salt=False)
        if result is not None:
            master_key = mk
            fmt = "v2"

        # Try v1 ENG1 fallback
        if fmt is None and payload0[:4] == MAGIC:
            master_key = mk
            fmt = "v1-std"

    if fmt is None or master_key is None:
        return DecodeResult(found=False)

    # ── Phase 2: Decode all frames ──

    msg_text = None
    secret_decoded = []

    for fi in range(num):
        payload = stego.extract(frames[fi], cap)

        if fmt == "v2" or fmt == "v2-pwd":
            parsed = _v2_try_decode(payload, master_key, fi,
                                    has_salt=(fmt == "v2-pwd"))
            if parsed is None:
                continue

            if parsed["type"] == "text":
                msg_text = parsed["text"]
                break
            elif parsed["type"] == "video":
                secret_decoded.append((parsed["index"], parsed["frame"]))

        elif fmt == "v1-pwd":
            if payload[:4] != MAGIC_PWD:
                continue
            result = _v1_try_decode_frame(payload, master_key, fi, data_offset=20)
            if result is None:
                continue
            if result["type"] == "text":
                msg_text = result["text"]
                break
            elif result["type"] == "video":
                secret_decoded.append((result["index"], result["frame"]))

        elif fmt == "v1-std":
            if payload[:4] != MAGIC:
                continue
            result = _v1_try_decode_frame(payload, master_key, fi, data_offset=4)
            if result is None:
                continue
            if result["type"] == "text":
                msg_text = result["text"]
                break
            elif result["type"] == "video":
                secret_decoded.append((result["index"], result["frame"]))

        if on_progress:
            on_progress(fi + 1, num)

    if msg_text:
        return DecodeResult(found=True, content_type="text", message=msg_text)

    if secret_decoded and output_path:
        secret_decoded.sort(key=lambda x: x[0])
        secret_frames = [f for _, f in secret_decoded]
        video.write_frames(secret_frames, output_path, info["fps"])
        size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
        return DecodeResult(found=True, content_type="video",
                            output_path=output_path, num_frames=len(secret_frames))

    return DecodeResult(found=False)
