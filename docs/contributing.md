# Contributing to Engare

## Setup

```bash
git clone https://github.com/Ludaxis/engare.git
cd engare
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install pytest
```

System requirement:
```bash
# macOS
brew install ffmpeg

# Ubuntu/Debian
sudo apt install ffmpeg
```

## Running Tests

```bash
python -m pytest tests/ -v
```

All tests must pass before submitting a PR. The crypto and stego tests do not require FFmpeg.

## Project Structure

| File | Responsibility | Dependencies |
|------|---------------|-------------|
| `engare/crypto.py` | Pure cryptography (X25519, AES-GCM, HKDF, scrypt) | `cryptography` only |
| `engare/stego.py` | Pure steganography (LSB embed/extract) | `numpy` only |
| `engare/video.py` | Video I/O via FFmpeg, video-to-key | `PIL`, `numpy`, FFmpeg |
| `engare/keys.py` | Key file management | `engare/crypto.py` |
| `engare/cli.py` | CLI commands, ties everything together | All modules |

## Rules

### Security Rules (Non-Negotiable)

1. **No custom crypto.** Use the `cryptography` library for all cryptographic operations.
2. **No key logging.** Never print, log, or store keys outside of `~/.engare/` key files.
3. **Deniability is sacred.** Wrong key must NEVER produce an error message or any detectable difference from "no hidden content."
4. **No unauthenticated encryption.** AES-256-GCM minimum. Never use CBC, ECB, or CTR without authentication.

### Code Rules

1. Keep module boundaries clean — `crypto.py` must not import PIL, `stego.py` must not import crypto.
2. All new features need tests.
3. No unnecessary dependencies. Every new dependency must be justified.
4. Binary format changes require a new MAGIC byte version (e.g., "ENG2").

### Commit Messages

```
feat: add multi-recipient support
fix: handle cover videos shorter than secret
docs: add Persian translation of README
test: add integration test for video-as-key mode
```

## Areas Where Help Is Needed

- **DCT-domain steganography** — hiding data that survives H.264 compression
- **Steganalysis testing** — running detection tools against Engare output
- **Desktop app** — Tauri (Rust + web) cross-platform GUI
- **Mobile app** — React Native or Flutter with FFmpeg integration
- **Persian/Arabic documentation** — translations for target users
- **Multi-recipient encoding** — different hidden content for different keys
- **Forward secrecy** — ephemeral keys per message session
