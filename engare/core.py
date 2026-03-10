"""
Engare core library — encode/decode API for any frontend.

This module exposes the encode/decode pipeline as clean functions
that any frontend (CLI, GUI, web, TUI) can call.
"""

import struct
from dataclasses import dataclass

import numpy as np
from PIL import Image

from . import crypto, stego, video


MAGIC = b"ENG1"
MAGIC_PWD = b"ENP1"


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


def resolve_key(config: KeyConfig) -> tuple[bytes, bytes | None]:
    """Resolve a KeyConfig to (master_key, salt_or_none)."""
    if config.mode == "password":
        return crypto.password_to_key(config.password)
    elif config.mode == "video-key":
        return video.video_to_key(config.video_key_path), None
    elif config.mode == "keypair":
        return crypto.derive_shared_key(config.private_key, config.public_key), None
    else:
        raise ValueError(f"Unknown key mode: {config.mode}")


def encode_text(cover_path: str, message: str, key_config: KeyConfig,
                output_path: str, codec: str = "ffv1",
                on_progress=None) -> EncodeResult:
    """Encode a text message into a cover video.

    on_progress: optional callback(current_frame, total_frames)
    """
    master_key, salt = resolve_key(key_config)
    cover_frames, cover_info = video.read_frames(cover_path)
    num_cover = len(cover_frames)
    cap = stego.capacity(cover_info["width"], cover_info["height"])

    if salt is not None:
        magic_header = MAGIC_PWD + salt
    else:
        magic_header = MAGIC

    secret_data = message.encode("utf-8")
    stego_frames = []

    for ci in range(num_cover):
        frame_key = crypto.derive_frame_key(master_key, ci)
        encrypted = crypto.encrypt(secret_data, frame_key)

        header = magic_header + struct.pack(">BH", ord("T"), len(secret_data))
        payload = header + struct.pack(">I", len(encrypted)) + encrypted

        if len(payload) <= cap:
            payload += b"\x00" * (cap - len(payload))
            stego_frames.append(stego.embed(cover_frames[ci], payload))
        else:
            stego_frames.append(cover_frames[ci])

        if on_progress:
            on_progress(ci + 1, num_cover)

    # Extract audio for muxing
    import os, tempfile, shutil
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
    """Encode a secret video into a cover video.

    on_progress: optional callback(current_frame, total_frames)
    """
    master_key, salt = resolve_key(key_config)
    cover_frames, cover_info = video.read_frames(cover_path)
    secret_frames, secret_info = video.read_frames(secret_path)
    num_cover = len(cover_frames)
    num_secret = len(secret_frames)
    cap = stego.capacity(cover_info["width"], cover_info["height"])

    if salt is not None:
        magic_header = MAGIC_PWD + salt
        extra_overhead = 16
    else:
        magic_header = MAGIC
        extra_overhead = 0

    # Calculate max secret resolution
    overhead = 49 + extra_overhead
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

        frame_key = crypto.derive_frame_key(master_key, ci)
        encrypted = crypto.encrypt(sec_bytes, frame_key)

        header = magic_header + struct.pack(">BHHII", ord("V"), sw, sh, num_secret, si)
        payload = header + struct.pack(">I", len(encrypted)) + encrypted

        if len(payload) <= cap:
            payload += b"\x00" * (cap - len(payload))
            stego_frames.append(stego.embed(cover_frames[ci], payload))
        else:
            stego_frames.append(cover_frames[ci])

        if on_progress:
            on_progress(ci + 1, num_cover)

    import os, tempfile, shutil
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


def decode(input_path: str, key_config: KeyConfig,
           output_path: str | None = None,
           on_progress=None) -> DecodeResult:
    """Decode hidden content from a stego video.

    on_progress: optional callback(current_frame, total_frames)
    Returns DecodeResult with content_type and either message or output_path.
    """
    frames, info = video.read_frames(input_path)
    num = len(frames)
    cap = stego.capacity(info["width"], info["height"])

    # Probe for magic type
    key_mode = None
    probe = None
    for fi in range(num):
        probe = stego.extract(frames[fi], cap)
        if probe[:4] == MAGIC_PWD:
            key_mode = "pwd"
            break
        elif probe[:4] == MAGIC:
            key_mode = "std"
            break

    if key_mode is None:
        return DecodeResult(found=False)

    # Derive master key
    if key_mode == "pwd":
        if key_config.mode != "password" or not key_config.password:
            return DecodeResult(found=False)
        embedded_salt = probe[4:20]
        master_key, _ = crypto.password_to_key(key_config.password, embedded_salt)
    else:
        master_key, _ = resolve_key(key_config)

    msg_text = None
    secret_decoded = []

    for fi in range(num):
        payload = stego.extract(frames[fi], cap)

        if payload[:4] == MAGIC_PWD:
            data_offset = 20
        elif payload[:4] == MAGIC:
            data_offset = 4
        else:
            continue

        stype = chr(payload[data_offset])
        frame_key = crypto.derive_frame_key(master_key, fi)

        if stype == "T":
            try:
                o = data_offset + 1
                text_len = struct.unpack(">H", payload[o:o+2])[0]
                enc_len = struct.unpack(">I", payload[o+2:o+6])[0]
                enc_data = payload[o+6:o+6 + enc_len]
                dec = crypto.decrypt(enc_data, frame_key)
                msg_text = dec[:text_len].decode("utf-8")
                break
            except Exception:
                continue

        elif stype == "V":
            try:
                o = data_offset + 1
                sw = struct.unpack(">H", payload[o:o+2])[0]
                sh = struct.unpack(">H", payload[o+2:o+4])[0]
                idx = struct.unpack(">I", payload[o+8:o+12])[0]
                enc_len = struct.unpack(">I", payload[o+12:o+16])[0]
                enc_data = payload[o+16:o+16 + enc_len]
                dec = crypto.decrypt(enc_data, frame_key)
                frame = np.frombuffer(dec, dtype=np.uint8).reshape((sh, sw, 3))
                secret_decoded.append((idx, frame))
            except Exception:
                continue

        if on_progress:
            on_progress(fi + 1, num)

    if msg_text:
        return DecodeResult(found=True, content_type="text", message=msg_text)

    if secret_decoded and output_path:
        secret_decoded.sort(key=lambda x: x[0])
        secret_frames = [f for _, f in secret_decoded]
        video.write_frames(secret_frames, output_path, info["fps"])
        import os
        size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
        return DecodeResult(found=True, content_type="video",
                            output_path=output_path, num_frames=len(secret_frames))

    return DecodeResult(found=False)
