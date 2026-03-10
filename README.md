# Engare

**Only the intended eyes shall see.**

Engare hides encrypted videos inside normal-looking videos. Anyone watching sees a regular video. Only the person with the right key can extract the real content.

Named after the ancient Persian royal dispatch riders (*Angareion*) — elite couriers whose sealed messages could only be opened by the intended recipient. 2,500 years later, the same principle carries video instead of scrolls.

## How It Works

```
You record a cat video.
Inside it, you hide a completely different video.
Anyone who plays it sees the cat.
Your friend — with the key — sees the truth.
Wrong key? Just a cat video. No error. No hint.
```

- **AES-256-GCM** authenticated encryption (military-grade, tamper-proof)
- **LSB steganography** — changes < 2.5% of pixel values (invisible to the eye)
- **X25519 key exchange** — modern elliptic-curve cryptography
- **Per-frame encryption** — each frame has a unique key, preventing pattern analysis
- **Perfect deniability** — wrong key produces a normal video, no evidence anything is hidden

## Install

```bash
# Requirements: Python 3.9+, FFmpeg
pip install -e .

# Or run directly:
python -m engare
```

FFmpeg is required:
```bash
# macOS
brew install ffmpeg

# Ubuntu/Debian
sudo apt install ffmpeg

# Windows
# Download from https://ffmpeg.org/download.html
```

## Quick Start

### 1. Generate Your Identity

```bash
engare keygen reza
# Creates key pair in ~/.engare/
# Share the public key with anyone you want to communicate with

# Or with passphrase protection:
engare keygen reza --encrypt
# Private key is encrypted at rest (scrypt + AES-256-GCM)
```

### 2. Import a Friend's Public Key

```bash
engare import ali "their-base64-public-key"
```

### 3. Hide a Video

```bash
# Using key pair (most secure):
engare encode --cover beach.mp4 --secret evidence.mp4 \
  --identity reza --recipient ali --output vacation.mkv

# Using password (simpler):
engare encode --cover beach.mp4 --secret evidence.mp4 \
  --password "shared-secret" --output vacation.mkv

# Using video-as-key (offline, physical handoff):
engare encode --cover beach.mp4 --secret evidence.mp4 \
  --video-key /usb/our-key-video.mp4 --output vacation.mkv

# H.264 lossless codec (2-5x smaller files):
engare encode --cover beach.mp4 --secret evidence.mp4 \
  --password "shared-secret" --codec h264 --output vacation.mp4

# Preview capacity without encoding:
engare encode --cover beach.mp4 --message "test" \
  --password "x" --output x --dry-run
```

### 4. Extract the Secret

```bash
# Key pair:
engare decode --input vacation.mkv \
  --identity ali --sender reza --output revealed.mkv

# Password:
engare decode --input vacation.mkv \
  --password "shared-secret" --output revealed.mkv

# Video-as-key:
engare decode --input vacation.mkv \
  --video-key /usb/our-key-video.mp4 --output revealed.mkv
```

### 5. Hide a Text Message

```bash
engare encode --cover beach.mp4 --message "meet at 8pm tomorrow" \
  --password "secret" --output vacation.mkv

engare decode --input vacation.mkv --password "secret"
# Output: Message: meet at 8pm tomorrow
```

### 6. Verify Hidden Data

```bash
engare verify --input vacation.mkv
# Checks if a video contains hidden data (without decrypting)
```

## Three Key Modes

| Mode | How It Works | Best For |
|------|-------------|----------|
| **Key Pair** | X25519 ECDH — each person generates keys locally, shares public key | Ongoing secure communication |
| **Password** | Shared passphrase, key derived via scrypt | Quick one-off messages |
| **Video-as-Key** | A video file IS the key — share on USB drive | Air-gapped security, no internet needed |

## Check Capacity

```bash
engare info --cover beach.mp4
```

Shows how much secret data fits inside your cover video.

## Security

- **Open source does NOT weaken security.** The algorithm (AES-256) is public knowledge — every government knows how it works. It's still unbreakable. Security is in the key, not the code ([Kerckhoffs's Principle](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle)).
- **AES-256-GCM** — authenticated encryption. Any tampering is detected.
- **Per-frame unique keys** — derived via HKDF. No two frames share a key.
- **X25519** — modern elliptic-curve key exchange (same as Signal, WireGuard).
- **Wrong key = normal video.** No error message, no hint, no evidence.

## Output Format

Engare supports two lossless codecs:

- **FFV1** (default, `--codec ffv1`) — MKV container. Largest files but universally lossless.
- **H.264 lossless** (`--codec h264`) — MP4 container. Uses libx264rgb at CRF 0 for mathematically lossless RGB encoding. 2-5x smaller than FFV1.

Both preserve every pixel exactly. Lossy compression (standard H.264, VP9) destroys hidden data.

## Library API

For programmatic use (GUIs, scripts, other frontends), import `engare.core`:

```python
from engare.core import KeyConfig, encode_text, encode_video, decode

key = KeyConfig(mode="password", password="secret")
encode_text("cover.mp4", "hidden message", key, "output.mkv")
result = decode("output.mkv", key)
print(result.message)  # "hidden message"
```

## Documentation

- [Architecture](docs/architecture.md) — System design, data flow, payload format, module dependencies
- [Security Model](docs/security.md) — Threat model, cryptographic choices, limitations, recommendations
- [Contributing](docs/contributing.md) — Setup, testing, code rules, areas where help is needed

## Origin

Built on research from the StegoChat project. Named after the ancient Persian *Angareion* — the royal dispatch system of the Achaemenid Empire (550-330 BC), where elite mounted couriers carried sealed messages across the empire. Only the intended recipient could open the seal.

## License

GPL-3.0 — Free as in freedom.
