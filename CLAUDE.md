# Engare - Agent Instructions

## Project Identity

**Engare** (انگاره) — Named after the ancient Persian royal dispatch riders (Angareion) of the Achaemenid Empire. Elite couriers whose sealed messages could only be opened by the intended recipient.

**Tagline:** "Only the intended eyes shall see."

**What it does:** Hides encrypted videos inside normal-looking videos using steganography. Anyone watching sees a regular video. Only the person with the right key can extract the real hidden content. Wrong key = just a normal video, no error, no hint.

## Architecture Overview

```
engare/
├── engare/
│   ├── __init__.py      # Version only (0.3.0)
│   ├── __main__.py      # python -m engare entry
│   ├── cli.py           # CLI commands (keygen, keys, export, import, encode, decode, verify, info)
│   ├── core.py          # Library API (v2 format, KeyConfig, encode_text, encode_video, decode) for any frontend
│   ├── crypto.py        # X25519 + AES-256-GCM(+AAD) + HKDF + scrypt n=2^17 (NO custom crypto)
│   ├── stego.py         # Vectorized LSB steganography engine (numpy, 10-50x faster than v0.1)
│   ├── video.py         # FFmpeg video I/O (pipe-based read_frames/write_frames) + error propagation
│   └── keys.py          # Key management (~/.engare/, JSON key files, optional passphrase encryption)
├── tests/
│   ├── test_core.py         # 26 tests: v2 format, AAD, deniability, backward compat, encode/decode
│   ├── test_crypto.py       # 9 tests: keypair, encryption, key derivation, encrypted key storage
│   ├── test_stego.py        # 5 tests: embed, extract, capacity, visual similarity
│   └── test_integration.py  # 6 tests: password roundtrip, deniability, keypair, salt, H.264 lossless, stego performance
├── docs/
│   ├── architecture.md  # Full technical architecture
│   ├── security.md      # Security model, threat analysis, limitations
│   └── contributing.md  # Contribution guidelines
├── CLAUDE.md            # This file
├── README.md            # User-facing docs (English)
├── README.fa.md         # User-facing docs (Persian/RTL)
├── pyproject.toml       # Package config
├── .github/workflows/ci.yml  # GitHub Actions CI
└── LICENSE              # GPL-3.0
```

## Critical Rules

### Security — Never Break These

1. **NEVER implement custom cryptographic primitives.** Always use the `cryptography` library. No hand-rolled AES, no custom key derivation, no DIY random number generation.
2. **NEVER weaken encryption defaults.** AES-256-GCM is the minimum. Never downgrade to CBC, ECB, or unauthenticated modes.
3. **NEVER log, print, or store keys/passwords** in plaintext outside of ~/.engare/ key files. Private keys are chmod 0o600.
4. **NEVER send keys over the network.** Key exchange happens out-of-band (USB, QR, in person) or via X25519 ECDH where only public keys are shared.
5. **Wrong key must produce NO error signal.** The decode command must output a normal-looking video when the key is wrong — no error messages, no exceptions visible to the user, no hint that hidden content exists. This is a core security property (deniability).
6. **Per-frame key derivation is mandatory.** Each frame uses `derive_frame_key(master_key, frame_index)` via HKDF. Never reuse the master key directly for frame encryption.

### Code Conventions

- **Python 3.9+ compatible** — use `from __future__ import annotations` if needed, but current code uses `type | None` syntax (3.10+). Targeting 3.9 is aspirational; 3.10+ is the practical minimum.
- **Dependencies:** `cryptography`, `Pillow`, `numpy` only. FFmpeg is a system dependency.
- **No emojis in code or output** — the original StegoChat used emojis; Engare uses clean ASCII output.
- **Module boundaries are strict:**
  - `crypto.py` — pure crypto, no I/O, no video, no PIL
  - `stego.py` — pure numpy pixel operations, no crypto, no I/O
  - `video.py` — FFmpeg subprocess calls (pipe-based I/O via `read_frames`/`write_frames`), video-to-key
  - `keys.py` — filesystem key management, uses crypto module, supports passphrase-encrypted keys
  - `core.py` — clean library API (`KeyConfig`, `encode_text`, `encode_video`, `decode`) for any frontend
  - `cli.py` — ties everything together, handles args, user-facing output, ASCII progress bar

### Binary Format (Stego Payload)

**v2 format (v0.3.0+, default):** Encrypted headers, no cleartext magic.

The header is INSIDE the AES-GCM ciphertext. Without the key, extracted LSBs are indistinguishable from random noise.

Outer layout (keypair/video-key):
```
random(4) + enc_len(4 BE) + AES-GCM(inner, frame_key, aad=frame_index)
```

Outer layout (password):
```
random(4) + salt(16) + enc_len(4 BE) + AES-GCM(inner, frame_key, aad=frame_index)
```

Inner (text):
```
"ENG2"(4) + version(1, 0x02) + scrypt_n_log2(1) + type(1, 'T') + text_len(2 BE) + text_data
```

Inner (video):
```
"ENG2"(4) + version(1, 0x02) + scrypt_n_log2(1) + type(1, 'V') + width(2 BE) + height(2 BE) + total_frames(4 BE) + frame_index(4 BE) + pixel_data
```

AAD = frame_index as 4 bytes big-endian. Prevents frame reordering attacks.

**v1 format (legacy, decode-only):** Cleartext magic bytes at offset 0.

Keypair/Video-key (MAGIC = "ENG1"):
```
"ENG1"(4) + type(1) + text_len(2 BE) + enc_len(4 BE) + encrypted_data
```

Password (MAGIC = "ENP1"):
```
"ENP1"(4) + salt(16) + type(1) + text_len(2 BE) + enc_len(4 BE) + encrypted_data
```

v1 uses scrypt n=2^14. v2 uses n=2^17 (OWASP minimum). Decoder tries v2 first, falls back to v1.

Payload is zero-padded to fill the full frame capacity for consistency.

### Key Modes

Three encryption key modes:

1. **Password** (`--password`): scrypt key derivation (n=2^17). `--password` (no value) prompts securely via getpass. `ENGARE_PASSWORD` env var for scripting. `--password VALUE` emits deprecation warning (visible in ps aux).
2. **Video-as-key** (`--video-key`): SHA-256 hash of 5 sampled frames + first 1MB. Physical USB handoff. Resolved via `_resolve_key()`.
3. **Key pair** (`--identity` + `--recipient`/`--sender`): X25519 ECDH shared secret via HKDF. Most secure. Resolved via `_resolve_key()`.

### Key Storage

Keys are stored in `~/.engare/`:
- `<name>.key` — Private key (JSON, chmod 0o600). Optionally encrypted with passphrase.
- `<name>.pub` — Public key (JSON, shareable)

Unencrypted format: `{"type": "engare-private-key-v1", "name": "...", "private": "base64...", "public": "base64..."}`

Encrypted format: `{"type": "engare-private-key-v1-encrypted", "name": "...", "encrypted_private": "base64...", "salt": "base64...", "public": "base64..."}`

Encrypted keys use scrypt + AES-256-GCM. The passphrase is required to load the key (prompted interactively if not provided). Generate with `engare keygen <name> --encrypt`.

### Testing

```bash
source .venv/bin/activate
python -m pytest tests/ -v
```

All tests must pass before any merge. Tests do NOT require FFmpeg (crypto and stego tests are self-contained). Video integration tests that need FFmpeg should be marked with `@pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="FFmpeg required")`.

### Output Format

- Two lossless codec options, both rgb24 pixel format:
  - **FFV1** (default, `--codec ffv1`) — MKV container, largest files
  - **H.264 lossless** (`--codec h264`) — MP4 container, libx264rgb at CRF 0, 2-5x smaller than FFV1
- Both preserve every bit exactly — required for LSB steganography to survive
- Standard (lossy) H.264, VP9, or any lossy codec will **destroy** the hidden data
- Audio is re-encoded as AAC 128kbps from the cover video

## Roadmap (Planned Features)

### Phase 2 — Multi-Recipient
- Different people see different hidden content from the same video
- Partition LSB bit layers: bits 0-1 for recipient A, bits 2-3 for recipient B
- Each layer encrypted with different shared key
- Header includes recipient fingerprint so decoder knows which layer to read

### Phase 3 — Desktop App
- Tauri (Rust + web frontend) for Windows/Mac/Linux
- Bundle Python core or rewrite stego engine in Rust/WASM
- Simple UI: pick cover, pick secret, pick recipient, encode

### Phase 4 — Mobile
- React Native or Flutter
- Native FFmpeg libs (ffmpeg-kit)
- Camera integration for cover video capture

### Phase 5 — Detection Resistance
- Move beyond basic LSB to DCT-domain steganography (survives H.264)
- Adaptive embedding (hide data only in noisy/complex regions)
- Statistical steganalysis resistance testing

## Known Limitations

1. **LSB is detectable** by statistical analysis (StegDetect, RS Analysis). The data is encrypted, but an adversary can detect that *something* is hidden.
2. **Lossy compression destroys data.** Sharing via social media (which re-encodes with lossy H.264) will destroy the hidden content. Files must be shared directly (email attachment, file transfer, USB).
3. **No forward secrecy.** If a long-term key is compromised, all past messages are compromised. Planned fix: ephemeral keys per message.
4. **Large file sizes.** FFV1 lossless MKV files are significantly larger than lossy MP4. The `--codec h264` option (lossless H.264) reduces output size 2-5x while preserving steganographic data.

## Agent Organization

Engare uses a hierarchical multi-agent system modeled after a real company. Agent definitions are stored in `~/.claude/agents/engare-*.md`.

### Org Chart (1→1→2→2→8 tree)

```
Level 0: Reza (God/User — CEO)
│
Level 1: Claude Main Agent (Communication God — Orchestrator)
│
├── Level 2: Kaveh Rostami — CTO God (engare-cto-god)
│   ├── Level 3: Arash Kiani — Tech Lead (engare-tech-lead)
│   │   ├── Level 4: Parisa Ahmadi — Senior iOS Dev (engare-ios-dev)
│   │   ├── Level 4: Babak Sharifi — Senior macOS Dev (engare-macos-dev)
│   │   ├── Level 4: Sahar Karimi — Senior Android Dev (engare-android-dev)
│   │   └── Level 4: Kian Nazari — Senior Next.js Dev (engare-nextjs-dev)
│   └── Level 3: Shirin Fazeli — Platform Lead (engare-platform-lead)
│
└── Level 2: Darya Mohammadi — Product God (engare-product-god)
    ├── Level 3: Neda Bahrami — Design & UX Lead (engare-design-lead)
    └── Level 3: Omid Taheri — QA & DevOps Lead (engare-qa-lead)
```

### Organization Rules

1. **Max 8 direct reports** per agent
2. **Max 144 agents** per unit
3. **Escalation paths:** security → CTO God, product/UX → Product God, blocked → parent
4. **Hiring:** Lead requests → God approves → Communication God creates agent file
5. **Cross-tree communication:** route through nearest common ancestor
6. **Model assignment:** Gods/Leads = opus, ICs = sonnet
7. **Task dispatch format:** From, To, Priority, Context, Scope, Constraints, Acceptance Criteria
