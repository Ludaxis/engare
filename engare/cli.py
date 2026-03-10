"""
Engare CLI — The ancient art of carrying secrets.

Commands:
  engare keygen <name>             Generate a new identity (key pair)
  engare keys                      List all identities
  engare export <name>             Export public key to share
  engare import <name> <key>       Import someone's public key
  engare encode                    Hide a secret video inside a cover video
  engare decode                    Extract a secret video from a stego video
  engare verify                    Check if a video contains hidden data
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


def _progress_bar(current, total, width=30):
    """Print an ASCII progress bar to stderr."""
    pct = current / total if total else 1
    filled = int(width * pct)
    bar = "\u2588" * filled + "\u2591" * (width - filled)
    sys.stderr.write(f"\r  [{bar}] {pct*100:5.1f}% ({current}/{total} frames)")
    if current >= total:
        sys.stderr.write("\n")
    sys.stderr.flush()


MAGIC = b"ENG1"      # Engare v1 format marker (keypair / video-key modes)
MAGIC_PWD = b"ENP1"  # Engare v1 password mode (salt embedded in header)


def cmd_keygen(args):
    """Generate a new identity."""
    passphrase = getattr(args, "passphrase", None)
    if passphrase is None and getattr(args, "encrypt", False):
        import getpass
        passphrase = getpass.getpass("Passphrase to protect private key: ")
        confirm = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirm:
            print("Error: passphrases do not match")
            sys.exit(1)
    result = keys.generate_identity(args.name, passphrase=passphrase)
    print(f"Identity created: {args.name}")
    if result.get("encrypted"):
        print(f"  Protected: passphrase-encrypted")
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
        enc_mark = " [encrypted]" if ident.get("encrypted") else ""
        print(f"  {ident['name']}{enc_mark}")
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

    # Determine encryption key and salt
    salt = None
    if hasattr(args, "password") and args.password:
        master_key, salt = crypto.password_to_key(args.password)
    else:
        master_key = _resolve_key(args)

    # Read cover frames via pipe (no temp files)
    print("Reading cover video...")
    cover_frames, cover_info = video.read_frames(args.cover)
    num_cover = len(cover_frames)
    cap = stego.capacity(cover_info["width"], cover_info["height"])

    print(f"Cover:    {cover_info['width']}x{cover_info['height']} @ {cover_info['fps']:.1f}fps, {num_cover} frames")
    print(f"Capacity: {cap:,} bytes/frame ({cap/1024:.1f} KB)")
    print(f"Codec:    {getattr(args, 'codec', 'ffv1')}")

    # Dry-run: show analysis and exit
    if getattr(args, "dry_run", False):
        if args.message:
            msg_bytes = len(args.message.encode("utf-8"))
            enc_overhead = 28  # AES-GCM nonce(12) + tag(16)
            header_size = (20 if salt else 4) + 7  # magic + type + text_len + enc_len
            total = header_size + msg_bytes + enc_overhead
            print(f"\nDry run:")
            print(f"  Message:   {msg_bytes} bytes")
            print(f"  Payload:   {total} bytes/frame")
            print(f"  Fits:      {'yes' if total <= cap else 'NO -- message too large'}")
        elif args.secret:
            secret_info = video.get_info(args.secret)
            print(f"\nDry run:")
            print(f"  Secret: {secret_info['width']}x{secret_info['height']} @ {secret_info['fps']:.1f}fps")
            extra = 16 if salt else 0
            overhead = 49 + extra
            available = cap - overhead
            aspect = secret_info["width"] / secret_info["height"]
            sh = int((available / 3 / aspect) ** 0.5)
            sw = int(sh * aspect)
            sw = min(sw, 240) & ~1
            sh = min(sh, 180) & ~1
            if sw < 16 or sh < 16:
                print(f"  Fits:   NO -- cover too small")
            else:
                print(f"  Resized to: {sw}x{sh}")
                print(f"  Fits:   yes ({sw*sh*3:,} bytes/frame)")
        return

    if not args.message and not args.secret:
        print("Error: provide --message or --secret")
        sys.exit(1)

    # Extract audio to temp file (still needed for muxing)
    tmpdir = tempfile.mkdtemp(prefix="engare_")
    try:
        audio_path = os.path.join(tmpdir, "audio.aac")
        has_audio = video.extract_audio(args.cover, audio_path)

        if args.message:
            _encode_text(args, master_key, salt, cover_frames, cap, audio_path, has_audio, cover_info)
        elif args.secret:
            _encode_video(args, master_key, salt, cover_frames, cap, audio_path, has_audio, cover_info)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _encode_text(args, master_key, salt, cover_frames, cap, audio_path, has_audio, cover_info):
    """Encode a text message (embedded in every frame for redundancy)."""
    secret_data = args.message.encode("utf-8")
    num_cover = len(cover_frames)
    print(f"Message:  {len(secret_data)} bytes")

    # Build magic + optional salt prefix
    if salt is not None:
        magic_header = MAGIC_PWD + salt
    else:
        magic_header = MAGIC

    stego_frames = []
    print(f"Encoding {num_cover} frames...")
    for ci in range(num_cover):
        cover_img = cover_frames[ci]
        frame_key = crypto.derive_frame_key(master_key, ci)
        encrypted = crypto.encrypt(secret_data, frame_key)

        header = magic_header + struct.pack(">BH", ord("T"), len(secret_data))
        payload = header + struct.pack(">I", len(encrypted)) + encrypted

        if len(payload) <= cap:
            payload += b"\x00" * (cap - len(payload))
            stego_frames.append(stego.embed(cover_img, payload))
        else:
            stego_frames.append(cover_img)

        _progress_bar(ci + 1, num_cover)

    codec = getattr(args, "codec", "ffv1")
    video.write_frames(stego_frames, args.output, cover_info["fps"],
                       codec=codec, audio=audio_path if has_audio else None)
    if os.path.exists(args.output):
        size_mb = os.path.getsize(args.output) / (1024 * 1024)
        print(f"Done: {args.output} ({size_mb:.1f} MB)")


def _encode_video(args, master_key, salt, cover_frames, cap, audio_path, has_audio, cover_info):
    """Encode a secret video inside the cover video."""
    num_cover = len(cover_frames)

    # Read secret frames via pipe
    print("Reading secret video...")
    secret_frames, secret_info = video.read_frames(args.secret)
    num_secret = len(secret_frames)
    print(f"Secret:   {secret_info['width']}x{secret_info['height']} @ {secret_info['fps']:.1f}fps, {num_secret} frames")

    # Build magic + optional salt prefix
    if salt is not None:
        magic_header = MAGIC_PWD + salt
        extra_overhead = 16
    else:
        magic_header = MAGIC
        extra_overhead = 0

    # Calculate max secret resolution that fits in capacity
    overhead = 49 + extra_overhead
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

    stego_frames = []
    print(f"Encoding {num_cover} frames...")
    for ci in range(num_cover):
        cover_img = cover_frames[ci]
        si = ci % num_secret
        sec_img = Image.fromarray(secret_frames[si]).resize((sw, sh), Image.LANCZOS)
        sec_bytes = np.array(sec_img).tobytes()

        frame_key = crypto.derive_frame_key(master_key, ci)
        encrypted = crypto.encrypt(sec_bytes, frame_key)

        header = magic_header + struct.pack(">BHHII", ord("V"), sw, sh, num_secret, si)
        payload = header + struct.pack(">I", len(encrypted)) + encrypted

        if len(payload) <= cap:
            payload += b"\x00" * (cap - len(payload))
            stego_frames.append(stego.embed(cover_img, payload))
        else:
            stego_frames.append(cover_img)

        _progress_bar(ci + 1, num_cover)

    codec = getattr(args, "codec", "ffv1")
    video.write_frames(stego_frames, args.output, cover_info["fps"],
                       codec=codec, audio=audio_path if has_audio else None)
    if os.path.exists(args.output):
        size_mb = os.path.getsize(args.output) / (1024 * 1024)
        print(f"Done: {args.output} ({size_mb:.1f} MB)")


def cmd_decode(args):
    """Extract hidden content from a stego video."""
    # Read all frames via pipe
    frames, info = video.read_frames(args.input)
    num = len(frames)
    cap = stego.capacity(info["width"], info["height"])

    # Probe first frame to detect key mode
    master_key = None
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

    if key_mode == "pwd":
        if not (hasattr(args, "password") and args.password):
            if args.output:
                shutil.copy2(args.input, args.output)
            print(f"Video saved: {args.output or args.input}")
            return
        embedded_salt = probe[4:20]
        master_key, _ = crypto.password_to_key(args.password, embedded_salt)
    elif key_mode == "std":
        master_key = _resolve_key(args)
    else:
        if args.output:
            shutil.copy2(args.input, args.output)
        print(f"Video saved: {args.output or args.input}")
        return

    found = False
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
                found = True
                break
            except Exception:
                continue

        elif stype == "V":
            try:
                o = data_offset + 1
                sw = struct.unpack(">H", payload[o:o+2])[0]
                sh = struct.unpack(">H", payload[o+2:o+4])[0]
                total = struct.unpack(">I", payload[o+4:o+8])[0]
                idx = struct.unpack(">I", payload[o+8:o+12])[0]
                enc_len = struct.unpack(">I", payload[o+12:o+16])[0]
                enc_data = payload[o+16:o+16 + enc_len]
                dec = crypto.decrypt(enc_data, frame_key)
                frame = np.frombuffer(dec, dtype=np.uint8).reshape((sh, sw, 3))
                secret_decoded.append((idx, frame))
                found = True
            except Exception:
                continue

    if found and msg_text:
        print(f"Message: {msg_text}")
        if args.output:
            shutil.copy2(args.input, args.output)

    elif found and secret_decoded:
        # Sort by frame index and write via pipe
        secret_decoded.sort(key=lambda x: x[0])
        secret_frames = [f for _, f in secret_decoded]
        video.write_frames(secret_frames, args.output, info["fps"])
        if os.path.exists(args.output):
            size_mb = os.path.getsize(args.output) / (1024 * 1024)
            print(f"Secret video extracted: {args.output} ({size_mb:.1f} MB)")

    else:
        if args.output:
            shutil.copy2(args.input, args.output)
        print(f"Video saved: {args.output or args.input}")


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


def cmd_verify(args):
    """Check if a video contains intact hidden data (without decrypting)."""
    frames, info = video.read_frames(args.input)
    num = len(frames)
    cap = stego.capacity(info["width"], info["height"])

    print("Engare - VERIFY")
    print("=" * 50)
    print(f"Input:  {info['width']}x{info['height']} @ {info['fps']:.1f}fps, {num} frames")

    detected = 0
    content_type = None
    magic_type = None

    for fi in range(num):
        payload = stego.extract(frames[fi], cap)
        if payload[:4] == MAGIC_PWD:
            magic_type = "ENP1 (password)"
            data_offset = 20
        elif payload[:4] == MAGIC:
            magic_type = "ENG1 (keypair/video-key)"
            data_offset = 4
        else:
            continue

        stype = chr(payload[data_offset])
        if stype == "T":
            content_type = "text"
        elif stype == "V":
            content_type = "video"
        detected += 1

    if detected > 0:
        print(f"Status: Hidden data detected")
        print(f"  Format:  {magic_type}")
        print(f"  Type:    {content_type}")
        print(f"  Frames:  {detected}/{num} contain data")
    else:
        print(f"Status: No hidden data detected")
        print(f"  (This could mean no data, or you need the right key to check)")


def _resolve_key(args) -> bytes:
    """Resolve encryption key from CLI arguments (non-password modes)."""
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
  # Generate your identity (with passphrase protection):
  engare keygen reza --encrypt

  # Import a friend's public key:
  engare import ali "base64-public-key-here"

  # Hide a message (password, smaller MP4 output):
  engare encode --cover beach.mp4 --message "meet at 8pm" --password "secret" --codec h264 --output vacation.mp4

  # Preview capacity without encoding:
  engare encode --cover beach.mp4 --message "test" --password "x" --output x --dry-run

  # Hide a video (key pair):
  engare encode --cover beach.mp4 --secret evidence.mp4 --identity reza --recipient ali --output vacation.mkv

  # Extract (password):
  engare decode --input vacation.mp4 --password "secret" --output result.mkv

  # Check if a video has hidden data:
  engare verify --input vacation.mp4

  # Check capacity:
  engare info --cover beach.mp4
""",
    )

    sub = parser.add_subparsers(dest="command")

    # keygen
    kg = sub.add_parser("keygen", help="Generate a new identity (key pair)")
    kg.add_argument("name", help="Identity name")
    kg.add_argument("--encrypt", action="store_true",
                     help="Protect private key with a passphrase")

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
    enc.add_argument("--output", required=True, help="Output file")
    enc.add_argument("--codec", choices=["ffv1", "h264"], default="ffv1",
                     help="Codec: ffv1 (lossless, large) or h264 (lossless RGB, 2-5x smaller)")
    enc.add_argument("--dry-run", action="store_true",
                     help="Show capacity analysis without encoding")
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

    # verify
    ver = sub.add_parser("verify", help="Check if a video contains hidden data")
    ver.add_argument("--input", required=True, help="Video file to check")

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
        "verify": cmd_verify,
        "info": cmd_info,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
