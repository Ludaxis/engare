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

16 tests must pass before submitting a PR. The crypto and stego tests do not require FFmpeg. Integration tests that require FFmpeg are skipped automatically if FFmpeg is not installed.

Test coverage includes:
- **Crypto** (9 tests): keypair generation, shared key derivation, encrypt/decrypt, wrong key rejection, tamper detection, password-to-key, per-frame key derivation, end-to-end keypair flow, encrypted key storage
- **Stego** (5 tests): capacity calculation, embed/extract roundtrip, shape preservation, visual similarity, overflow handling
- **Integration** (6 tests): password text roundtrip, wrong-password deniability, keypair text roundtrip, salt embedding, H.264 lossless roundtrip, stego performance benchmarks

## Project Structure

| File | Responsibility | Dependencies |
|------|---------------|-------------|
| `engare/crypto.py` | Pure cryptography (X25519, AES-GCM, HKDF, scrypt) | `cryptography` only |
| `engare/stego.py` | Vectorized LSB steganography (embed/extract, 10-50x faster) | `numpy` only |
| `engare/video.py` | Pipe-based video I/O (`read_frames`/`write_frames`), video-to-key | `PIL`, `numpy`, FFmpeg |
| `engare/keys.py` | Key file management, encrypted key storage | `engare/crypto.py` |
| `engare/core.py` | Library API (`KeyConfig`, `encode_text`, `encode_video`, `decode`) | `crypto`, `stego`, `video` |
| `engare/cli.py` | CLI commands (encode, decode, verify, keygen, info), progress bar | All modules |

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

### Test Patterns

When adding new features, follow these test patterns:
- **Crypto tests** (`test_crypto.py`): Pure unit tests, no I/O or FFmpeg. See `test_encrypted_key_storage` for testing key management with monkey-patched key directories.
- **Stego tests** (`test_stego.py`): Random numpy arrays as frames, test roundtrip and edge cases. See `TestStegoPerformance` for performance benchmarks.
- **Integration tests** (`test_integration.py`): Use `@needs_ffmpeg` decorator for tests requiring FFmpeg. Use `make_test_video()` helper for synthetic test videos. See `TestH264LosslessRoundtrip` for codec-specific testing.

## Areas Where Help Is Needed

- **DCT-domain steganography** — hiding data that survives lossy H.264 compression
- **Steganalysis testing** — running detection tools against Engare output
- **Desktop app** — Tauri (Rust + web) cross-platform GUI (can use `engare.core` API)
- **Mobile app** — React Native or Flutter with FFmpeg integration
- **Persian/Arabic documentation** — translations for target users
- **Multi-recipient encoding** — different hidden content for different keys
- **Forward secrecy** — ephemeral keys per message session
