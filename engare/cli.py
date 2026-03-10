"""
Engare CLI — The ancient art of carrying secrets.

Commands:
  engare keygen <name>             Generate a new identity (key pair)
  engare keys                      List all identities
  engare export <name>             Export public key to share
  engare import <name> <key>       Import someone's public key
  engare encode                    Hide a secret video inside a cover video
  engare decode                    Extract a secret video from a stego video
  engare info                      Show capacity analysis
"""

import argparse
import os
import shutil
import struct
import sys
import tempfile

import numpy as np
from PIL import Image

from . import crypto, stego, video, keys


MAGIC = b"ENG1"  # Engare v1 format marker


def cmd_keygen(args):
    """Generate a new identity."""
    result = keys.generate_identity(args.name)
    print(f"Identity created: {args.name}")
    print(f"  Fingerprint: {result['fingerprint']}")
    print(f"  Private key: {result['private_path']}")
    print(f"  Public key:  {result['public_path']}")
    print(f"\nShare your public key:")
    print(f"  {result['public_key']}")
    print(f"\nOr give them the file: {result['public_path']}")


def cmd_keys(args):
    """List all identities."""
    identities = keys.list_identities()
    if not identities:
        print("No identities yet. Create one with: engare keygen <name>")
        return
    for ident in identities:
        print(f"  {ident['name']}")
        print(f"    Fingerprint: {ident['fingerprint']}")
        print(f"    Public key:  {ident['public_key']}")
        print()


def cmd_export(args):
    """Export a public key."""
    pub = keys.export_public_key(args.name)
    print(pub)


def cmd_import(args):
    """Import someone's public key."""
    result = keys.import_public_key(args.name, args.key)
    print(f"Imported: {args.name}")
    print(f"  Fingerprint: {result['fingerprint']}")
    print(f"  Saved to: {result['path']}")


def cmd_encode(args):
    """Hide a secret video inside a cover video."""
    print("Engare - ENCODE")
    print("=" * 50)

    # Determine encryption key
    master_key = _resolve_key(args)

    cover_info = video.get_info(args.cover)
    cap = stego.capacity(cover_info["width"], cover_info["height"])

    print(f"Cover:    {cover_info['width']}x{cover_info['height']} @ {cover_info['fps']:.1f}fps")
    print(f"Capacity: {cap:,} bytes/frame ({cap/1024:.1f} KB)")

    tmpdir = tempfile.mkdtemp(prefix="engare_")
    try:
        # Extract cover frames
        cover_dir = os.path.join(tmpdir, "cover")
        print("Extracting cover frames...")
        num_cover = video.extract_frames(args.cover, cover_dir)
        print(f"  {num_cover} frames")

        # Extract audio
        audio_path = os.path.join(tmpdir, "audio.aac")
        has_audio = video.extract_audio(args.cover, audio_path)

        if args.message:
            _encode_text(args, master_key, cover_dir, num_cover, cap, tmpdir, audio_path, has_audio, cover_info)
        elif args.secret:
            _encode_video(args, master_key, cover_dir, num_cover, cap, tmpdir, audio_path, has_audio, cover_info)
        else:
            print("Error: provide --message or --secret")
            sys.exit(1)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _encode_text(args, master_key, cover_dir, num_cover, cap, tmpdir, audio_path, has_audio, cover_info):
    """Encode a text message (embedded in every frame for redundancy)."""
    secret_data = args.message.encode("utf-8")
    print(f"Message:  {len(secret_data)} bytes")

    stego_dir = os.path.join(tmpdir, "stego")
    os.makedirs(stego_dir)

    print(f"Encoding {num_cover} frames...")
    for ci in range(num_cover):
        cf = os.path.join(cover_dir, f"frame_{ci:06d}.png")
        if not os.path.exists(cf):
            break

        cover_img = video.load_frame(cf)
        frame_key = crypto.derive_frame_key(master_key, ci)
        encrypted = crypto.encrypt(secret_data, frame_key)

        # Header: MAGIC(4) + type(1) + text_len(2) + enc_len(4) = 11 bytes
        header = struct.pack(">4sBH", MAGIC, ord("T"), len(secret_data))
        payload = header + struct.pack(">I", len(encrypted)) + encrypted

        out_path = os.path.join(stego_dir, f"frame_{ci:06d}.png")
        if len(payload) <= cap:
            payload += b"\x00" * (cap - len(payload))
            stego_frame = stego.embed(cover_img, payload)
            video.save_frame(stego_frame, out_path)
        else:
            video.save_frame(cover_img, out_path)

        if (ci + 1) % 30 == 0 or ci == num_cover - 1:
            print(f"  [{(ci+1)/num_cover*100:5.1f}%]")

    video.build_video(stego_dir, args.output, cover_info["fps"], audio_path if has_audio else None)
    if os.path.exists(args.output):
        size_mb = os.path.getsize(args.output) / (1024 * 1024)
        print(f"Done: {args.output} ({size_mb:.1f} MB)")


def _encode_video(args, master_key, cover_dir, num_cover, cap, tmpdir, audio_path, has_audio, cover_info):
    """Encode a secret video inside the cover video."""
    secret_info = video.get_info(args.secret)
    print(f"Secret:   {secret_info['width']}x{secret_info['height']} @ {secret_info['fps']:.1f}fps")

    sec_dir = os.path.join(tmpdir, "secret")
    print("Extracting secret frames...")
    num_secret = video.extract_frames(args.secret, sec_dir)
    print(f"  {num_secret} frames")

    # Calculate max secret resolution that fits in capacity
    # Reserve space for header(17) + enc_len(4) + AES overhead(28)
    overhead = 49
    available = cap - overhead
    aspect = secret_info["width"] / secret_info["height"]
    sh = int((available / 3 / aspect) ** 0.5)
    sw = int(sh * aspect)
    sw = min(sw, 240) & ~1
    sh = min(sh, 180) & ~1

    if sw < 16 or sh < 16:
        print("Error: cover video too small to hide secret video")
        sys.exit(1)

    print(f"Secret resized to {sw}x{sh} ({sw*sh*3:,} bytes/frame)")

    stego_dir = os.path.join(tmpdir, "stego")
    os.makedirs(stego_dir)

    print(f"Encoding {num_cover} frames...")
    for ci in range(num_cover):
        cf = os.path.join(cover_dir, f"frame_{ci:06d}.png")
        if not os.path.exists(cf):
            break

        cover_img = video.load_frame(cf)

        si = ci % num_secret
        sf = os.path.join(sec_dir, f"frame_{si:06d}.png")
        out_path = os.path.join(stego_dir, f"frame_{ci:06d}.png")

        if os.path.exists(sf):
            sec_img = Image.open(sf).convert("RGB").resize((sw, sh), Image.LANCZOS)
            sec_bytes = np.array(sec_img).tobytes()

            frame_key = crypto.derive_frame_key(master_key, ci)
            encrypted = crypto.encrypt(sec_bytes, frame_key)

            # Header: MAGIC(4) + type(1) + width(2) + height(2) + total(4) + index(4) = 17 bytes
            header = struct.pack(">4sBHHII", MAGIC, ord("V"), sw, sh, num_secret, si)
            payload = header + struct.pack(">I", len(encrypted)) + encrypted

            if len(payload) <= cap:
                payload += b"\x00" * (cap - len(payload))
                stego_frame = stego.embed(cover_img, payload)
                video.save_frame(stego_frame, out_path)
            else:
                video.save_frame(cover_img, out_path)
        else:
            video.save_frame(cover_img, out_path)

        if (ci + 1) % 30 == 0 or ci == num_cover - 1:
            print(f"  [{(ci+1)/num_cover*100:5.1f}%]")

    video.build_video(stego_dir, args.output, cover_info["fps"], audio_path if has_audio else None)
    if os.path.exists(args.output):
        size_mb = os.path.getsize(args.output) / (1024 * 1024)
        print(f"Done: {args.output} ({size_mb:.1f} MB)")


def cmd_decode(args):
    """Extract hidden content from a stego video."""
    master_key = _resolve_key(args)

    info = video.get_info(args.input)
    cap = stego.capacity(info["width"], info["height"])

    tmpdir = tempfile.mkdtemp(prefix="engare_dec_")
    try:
        frames_dir = os.path.join(tmpdir, "frames")
        num = video.extract_frames(args.input, frames_dir)

        found = False
        msg_text = None
        sec_dir = os.path.join(tmpdir, "secret")
        os.makedirs(sec_dir, exist_ok=True)
        sec_count = 0

        for fi in range(num):
            ff = os.path.join(frames_dir, f"frame_{fi:06d}.png")
            if not os.path.exists(ff):
                break

            img = video.load_frame(ff)
            payload = stego.extract(img, cap)

            if payload[:4] != MAGIC:
                continue

            stype = chr(payload[4])
            frame_key = crypto.derive_frame_key(master_key, fi)

            if stype == "T":
                try:
                    text_len = struct.unpack(">H", payload[5:7])[0]
                    enc_len = struct.unpack(">I", payload[7:11])[0]
                    enc_data = payload[11:11 + enc_len]
                    dec = crypto.decrypt(enc_data, frame_key)
                    msg_text = dec[:text_len].decode("utf-8")
                    found = True
                    break
                except Exception:
                    continue

            elif stype == "V":
                try:
                    _, _, sw, sh, total, idx = struct.unpack(">4sBHHII", payload[:17])
                    enc_len = struct.unpack(">I", payload[17:21])[0]
                    enc_data = payload[21:21 + enc_len]
                    dec = crypto.decrypt(enc_data, frame_key)
                    frame = np.frombuffer(dec, dtype=np.uint8).reshape((sh, sw, 3))
                    video.save_frame(frame, os.path.join(sec_dir, f"frame_{idx:06d}.png"))
                    sec_count += 1
                    found = True
                except Exception:
                    continue

        if found and msg_text:
            print(f"Message: {msg_text}")
            if args.output:
                shutil.copy2(args.input, args.output)

        elif found and sec_count > 0:
            video.build_video(sec_dir, args.output, info["fps"])
            if os.path.exists(args.output):
                size_mb = os.path.getsize(args.output) / (1024 * 1024)
                print(f"Secret video extracted: {args.output} ({size_mb:.1f} MB)")

        else:
            # Wrong key or no hidden content — just output normal video
            # No hint that anything was ever hidden
            if args.output:
                shutil.copy2(args.input, args.output)
            print(f"Video saved: {args.output or args.input}")

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def cmd_info(args):
    """Show capacity analysis for a cover video."""
    info = video.get_info(args.cover)
    cap = stego.capacity(info["width"], info["height"])
    total_frames = int(info["duration"] * info["fps"])
    total_cap = cap * total_frames

    print("Engare - INFO")
    print("=" * 50)
    print(f"Cover:     {info['width']}x{info['height']} @ {info['fps']:.1f}fps, {info['duration']:.1f}s")
    print(f"Frames:    {total_frames}")
    print(f"Per frame: {cap:,} bytes ({cap/1024:.1f} KB)")
    print(f"Total:     {total_cap:,} bytes ({total_cap/1024/1024:.1f} MB)")

    overhead = 49
    available = cap - overhead
    max_pixels = available // 3

    print(f"\nMax secret resolution per frame:")
    for label, aspect in [("16:9", 16/9), ("4:3", 4/3), ("1:1", 1)]:
        h = int((max_pixels / aspect) ** 0.5)
        w = int(h * aspect)
        w = min(w, 480) & ~1
        h = min(h, 360) & ~1
        print(f"  {label}: {w}x{h}")


def _resolve_key(args) -> bytes:
    """Resolve encryption key from CLI arguments."""
    if hasattr(args, "password") and args.password:
        key, _ = crypto.password_to_key(args.password)
        return key

    if hasattr(args, "video_key") and args.video_key:
        return video.video_to_key(args.video_key)

    if hasattr(args, "identity") and args.identity and hasattr(args, "recipient") and args.recipient:
        priv = keys.load_private_key(args.identity)
        pub = keys.load_public_key(args.recipient)
        return crypto.derive_shared_key(priv, pub)

    if hasattr(args, "identity") and args.identity:
        priv = keys.load_private_key(args.identity)
        if hasattr(args, "sender") and args.sender:
            pub = keys.load_public_key(args.sender)
        else:
            print("Error: need --sender (their public key) for decryption")
            sys.exit(1)
        return crypto.derive_shared_key(priv, pub)

    print("Error: provide a key method:")
    print("  --password <pass>          Password-based encryption")
    print("  --video-key <video>        Use a video file as the key")
    print("  --identity <name> --recipient <name>   Key pair encryption")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="engare",
        description="Engare -- Only the intended eyes shall see.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate your identity:
  engare keygen reza

  # Import a friend's public key:
  engare import ali "base64-public-key-here"

  # Hide a message (password):
  engare encode --cover beach.mp4 --message "meet at 8pm" --password "secret" --output vacation.mkv

  # Hide a video (key pair):
  engare encode --cover beach.mp4 --secret evidence.mp4 --identity reza --recipient ali --output vacation.mkv

  # Hide a video (video-as-key on USB):
  engare encode --cover beach.mp4 --secret evidence.mp4 --video-key /usb/face.mp4 --output vacation.mkv

  # Extract (password):
  engare decode --input vacation.mkv --password "secret" --output result.mkv

  # Extract (key pair):
  engare decode --input vacation.mkv --identity ali --sender reza --output result.mkv

  # Check capacity:
  engare info --cover beach.mp4
""",
    )

    sub = parser.add_subparsers(dest="command")

    # keygen
    kg = sub.add_parser("keygen", help="Generate a new identity (key pair)")
    kg.add_argument("name", help="Identity name")

    # keys
    sub.add_parser("keys", help="List all identities")

    # export
    ex = sub.add_parser("export", help="Export public key")
    ex.add_argument("name", help="Identity name")

    # import
    im = sub.add_parser("import", help="Import someone's public key")
    im.add_argument("name", help="Name for this contact")
    im.add_argument("key", help="Base64 public key string")

    # encode
    enc = sub.add_parser("encode", help="Hide secret content inside a cover video")
    enc.add_argument("--cover", required=True, help="Cover video file")
    enc.add_argument("--message", help="Text message to hide")
    enc.add_argument("--secret", help="Secret video to hide")
    enc.add_argument("--output", required=True, help="Output file (.mkv)")
    enc.add_argument("--password", help="Encrypt with password")
    enc.add_argument("--video-key", help="Use a video file as encryption key")
    enc.add_argument("--identity", help="Your identity name (for key pair mode)")
    enc.add_argument("--recipient", help="Recipient identity name (for key pair mode)")

    # decode
    dec = sub.add_parser("decode", help="Extract hidden content from a video")
    dec.add_argument("--input", required=True, help="Stego video file")
    dec.add_argument("--output", help="Output file")
    dec.add_argument("--password", help="Decrypt with password")
    dec.add_argument("--video-key", help="Video file used as key")
    dec.add_argument("--identity", help="Your identity name (for key pair mode)")
    dec.add_argument("--sender", help="Sender identity name (for key pair mode)")

    # info
    inf = sub.add_parser("info", help="Show video capacity analysis")
    inf.add_argument("--cover", required=True, help="Cover video file")

    args = parser.parse_args()

    commands = {
        "keygen": cmd_keygen,
        "keys": cmd_keys,
        "export": cmd_export,
        "import": cmd_import,
        "encode": cmd_encode,
        "decode": cmd_decode,
        "info": cmd_info,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
