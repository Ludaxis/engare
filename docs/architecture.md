# Engare Architecture

## System Overview

Engare is a video steganography system that hides encrypted content inside normal-looking videos. It operates in three layers:

```
┌─────────────────────────────────────────────┐
│  CLI Layer (cli.py)                         │
│  User commands, argument parsing, workflow  │
│  ASCII progress bar, --dry-run, verify      │
├─────────────────────────────────────────────┤
│  Core API (core.py)                         │
│  KeyConfig, encode_text, encode_video,      │
│  decode — clean library API for any frontend│
├─────────────────────────────────────────────┤
│  Crypto Layer          │  Stego Layer       │
│  (crypto.py)           │  (stego.py)        │
│  Key exchange          │  Vectorized LSB    │
│  Encryption            │  embed/extract     │
│  Key derivation        │  (numpy, 10-50x)   │
├────────────────────────┼────────────────────┤
│  Key Management        │  Video I/O         │
│  (keys.py)             │  (video.py)        │
│  Identity generation   │  Pipe-based I/O    │
│  Key storage/loading   │  read_frames()     │
│  Import/export         │  write_frames()    │
│  Encrypted keys        │  FFV1 + H.264      │
│                        │  Video-to-key      │
└────────────────────────┴────────────────────┘
```

## Data Flow

### Encoding (Hiding a Secret)

```
Input:
  cover.mp4 (what everyone sees)
  secret.mp4 (what only the recipient sees)
  key (password, video-as-key, or X25519 identity)

Process:
  1. Resolve key → 256-bit master_key
  2. Read cover frames via pipe (read_frames → numpy arrays, no temp files)
  3. Read secret frames via pipe (read_frames → numpy arrays)
  4. Extract cover audio as AAC (FFmpeg)
  5. For each cover frame:
     a. Derive frame_key = HKDF(master_key, frame_index)
     b. Resize matching secret frame to fit capacity
     c. Encrypt secret frame bytes with AES-256-GCM(frame_key)
     d. Build payload = MAGIC + header + encrypted_data
     e. Embed payload in cover frame LSBs (vectorized numpy)
  6. Write stego frames + audio via pipe (write_frames, FFV1 or H.264 lossless)

Output:
  stego.mkv or stego.mp4 (looks identical to cover, contains hidden secret)
```

### Decoding (Extracting a Secret)

```
Input:
  stego.mkv (received video)
  key (password, video-as-key, or X25519 identity)

Process:
  1. Read all frames via pipe (read_frames → numpy arrays)
  2. Probe first frame for magic bytes:
     a. "ENP1" → password mode: extract salt from bytes 4-20, derive key via scrypt(password, salt)
     b. "ENG1" → standard mode: resolve key via keypair or video-key
  3. For each frame:
     a. Extract LSB payload (full frame capacity)
     b. Derive frame_key = HKDF(master_key, frame_index)
     c. Parse header fields at correct offset (4 for ENG1, 20 for ENP1)
     d. Decrypt payload with frame_key
     e. If text: print message
     f. If video: save decoded frame
  4. If video frames found: assemble into MKV (FFmpeg)
  5. If nothing found: output the video as-is (no hint)

Output:
  Either: extracted secret video/message
  Or: the original video unchanged (wrong key / no hidden content)
```

## Cryptographic Pipeline

### Key Derivation

```
Password Mode:
  password + salt(16 bytes) → scrypt(n=16384, r=8, p=1) → 256-bit key
  Salt is generated randomly during encoding and embedded in the ENP1 payload header.
  During decoding, salt is extracted from the payload before key derivation.

Video-as-Key Mode:
  video file → extract 5 frames → resize to 64x64 → SHA-256(pixel_data + first_1MB) → 256-bit key

Key Pair Mode:
  my_private_key + their_public_key → X25519 ECDH → shared_secret → HKDF(SHA-256) → 256-bit key
```

### Per-Frame Encryption

```
master_key + frame_index → HKDF(SHA-256, info="engare-frame-{index}") → frame_key
plaintext + frame_key → AES-256-GCM(random_nonce) → nonce(12) + ciphertext + tag(16)
```

Each frame has a unique encryption key derived from the master key. This prevents:
- Pattern analysis across frames
- Known-plaintext attacks on repeated data
- Correlation between frame positions

### AES-256-GCM Properties

- **Confidentiality:** Data is encrypted with 256-bit key
- **Integrity:** 16-byte authentication tag detects any tampering
- **Non-malleability:** Cannot modify ciphertext without detection
- **Random nonce:** 12 bytes of cryptographically random nonce per encryption

## Steganography Engine

### LSB Embedding

Each pixel has 3 color channels (R, G, B), each 8 bits wide. We replace the lowest 2 bits of each channel with data:

```
Original pixel:   R=11010110  G=10101001  B=01110011
                        ^^          ^^          ^^  ← these 2 bits replaced
Stego pixel:      R=11010101  G=10101010  B=01110010
                        ^^          ^^          ^^  ← now contain hidden data

Max change per channel: 3 out of 255 = 1.2%
Human perception: invisible
```

### Capacity Formula

```
bits_per_pixel = 3 channels * 2 bits_per_channel = 6
bytes_per_frame = (width * height * bits_per_pixel) / 8
total_bytes = bytes_per_frame * frame_count

Example (720p, 30fps, 60 seconds):
  1280 * 720 * 6 / 8 = 691,200 bytes/frame (675 KB)
  691,200 * 1800 = 1,244,160,000 bytes total (~1.16 GB capacity)
```

### Payload Format

Two payload formats exist, distinguished by magic bytes:

**Keypair/Video-key mode — MAGIC "ENG1":**

```
Byte offset  Size     Field
──────────────────────────────────
0            4        Magic ("ENG1")
4            1        Type ('T' = text, 'V' = video)

For text (Type = 'T'):
5            2        Text length (uint16 BE)
7            4        Encrypted data length (uint32 BE)
11           N        Encrypted data (AES-256-GCM: 12 nonce + ciphertext + 16 tag)

For video (Type = 'V'):
5            2        Secret width (uint16 BE)
7            2        Secret height (uint16 BE)
9            4        Total secret frames (uint32 BE)
13           4        Current frame index (uint32 BE)
17           4        Encrypted data length (uint32 BE)
21           N        Encrypted data
```

**Password mode — MAGIC "ENP1":**

```
Byte offset  Size     Field
──────────────────────────────────
0            4        Magic ("ENP1")
4            16       Scrypt salt (random, generated at encode time)
20           1        Type ('T' = text, 'V' = video)

For text (Type = 'T'):
21           2        Text length (uint16 BE)
23           4        Encrypted data length (uint32 BE)
27           N        Encrypted data

For video (Type = 'V'):
21           2        Secret width (uint16 BE)
23           2        Secret height (uint16 BE)
25           4        Total secret frames (uint32 BE)
29           4        Current frame index (uint32 BE)
33           4        Encrypted data length (uint32 BE)
37           N        Encrypted data
```

The decoder checks bytes 0-3 to determine the format. Data field offsets are 4 (ENG1) or 20 (ENP1).

## Key Storage

```
~/.engare/
├── reza.key          # Private key (chmod 0600, optionally encrypted)
├── reza.pub          # Public key (shareable)
├── ali.pub           # Imported contact public key
└── sara.pub          # Imported contact public key
```

### Key File Format

Unencrypted private key:
```json
{
  "type": "engare-private-key-v1",
  "name": "reza",
  "private": "base64-encoded-32-bytes",
  "public": "base64-encoded-32-bytes"
}
```

Encrypted private key (generated with `engare keygen <name> --encrypt`):
```json
{
  "type": "engare-private-key-v1-encrypted",
  "name": "reza",
  "encrypted_private": "base64-encoded-AES-GCM-ciphertext",
  "salt": "base64-encoded-16-byte-scrypt-salt",
  "public": "base64-encoded-32-bytes"
}
```

Encryption uses scrypt to derive a key from the passphrase, then AES-256-GCM to encrypt the raw private key bytes. The passphrase is prompted interactively on load.

```json
{
  "type": "engare-public-key-v1",
  "name": "ali",
  "public": "base64-encoded-32-bytes"
}
```

## Dependencies

| Package | Purpose | Why This One |
|---------|---------|-------------|
| `cryptography` | X25519, AES-GCM, HKDF, scrypt | Python's gold standard crypto library, audited, maintained by PyCA |
| `Pillow` | Load/save PNG frames | Standard Python imaging library |
| `numpy` | Pixel array manipulation for LSB operations | Fast array operations essential for per-pixel bit manipulation |
| FFmpeg (system) | Video frame extraction and assembly | Industry standard, handles all codecs, lossless FFV1 support |

## Module Dependency Graph

```
cli.py ──→ core.py  (library API: KeyConfig, encode_text, encode_video, decode)
  │   ──→ crypto.py (pure crypto, no I/O)
  │   ──→ stego.py  (pure vectorized numpy, no crypto, no I/O)
  │   ──→ video.py  (FFmpeg pipe I/O: read_frames, write_frames, video-to-key)
  │   ──→ keys.py   (filesystem + crypto.py, encrypted key support)
  │
  └──→ PIL, numpy, struct, os, tempfile (stdlib)

core.py ──→ crypto.py, stego.py, video.py (orchestrates pipeline without CLI)
```

`crypto.py` and `stego.py` have zero cross-dependencies — they can be tested independently without FFmpeg or filesystem access.
