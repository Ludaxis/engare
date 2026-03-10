# Engare Security Model

## Threat Model

Engare is designed for people who need to share video content in environments where:
- Encrypted communication is monitored or criminalized
- The act of using encryption itself draws suspicion
- Plausible deniability is essential

### What Engare Protects Against

| Threat | Protection | Strength |
|--------|-----------|----------|
| Content interception | AES-256-GCM encryption | Very strong |
| Suspicion of encryption | Steganography (hidden in normal video) | Moderate |
| Key compromise (brute force) | 256-bit keys, scrypt for passwords | Very strong |
| Data tampering | GCM authentication tag | Very strong |
| Pattern analysis across frames | Per-frame key derivation via HKDF | Strong |
| Deniability | Wrong key = normal video, no error | Strong |

### What Engare Does NOT Protect Against

| Threat | Why | Mitigation |
|--------|-----|-----------|
| Statistical steganalysis | LSB modifies pixel distribution detectably | Planned: DCT-domain steganography |
| Traffic analysis | MKV files are unusual; large file sizes | Use common cover formats, keep sizes reasonable |
| Compromised endpoints | Malware on sender/receiver device | Out of scope — use a secure device |
| Rubber-hose cryptanalysis | Physical coercion to reveal key | Deniability helps — "there is no hidden content" |
| Metadata analysis | File timestamps, transfer logs | Use Tor/VPN for transfer, strip metadata |

## Cryptographic Choices

### Why AES-256-GCM (not CBC)

The original StegoChat used AES-CBC. Engare upgrades to GCM because:

- **CBC is malleable:** An attacker can flip bits in the ciphertext and predictably alter the plaintext without detection. GCM's authentication tag prevents this.
- **CBC requires separate HMAC:** To detect tampering with CBC, you need to add HMAC. GCM has built-in authentication.
- **CBC padding oracle attacks:** CBC is vulnerable to padding oracle attacks if error messages differ between bad padding and bad data. GCM eliminates this entire class of attacks.

### Why X25519 (not RSA)

- **32-byte keys** vs RSA's 2048+ bit keys — easier to share, display, embed
- **Constant-time operations** — resistant to timing side-channel attacks
- **Modern standard** — used by Signal, WireGuard, TLS 1.3
- **No padding vulnerabilities** — RSA PKCS#1 has had multiple padding attacks

### Why HKDF for Per-Frame Keys

Each frame gets a unique key: `HKDF(master_key, info="engare-frame-{index}")`.

Without this:
- Same key encrypts different data at known offsets → potential for known-plaintext attacks
- Identical secret frames (e.g., black frames) would produce identical ciphertext → pattern leakage

With HKDF:
- Each frame has an independent 256-bit key
- No mathematical relationship between frame keys is recoverable
- Compromising one frame key does not reveal others

### Why Scrypt for Passwords

- **Memory-hard:** Resistant to GPU/ASIC brute force
- **Configurable cost:** n=16384, r=8, p=1 provides reasonable security for interactive use
- **Better than SHA-256:** The original StegoChat used `SHA-256(password)` which is trivially brute-forceable

### Random Nonce (not MD5-derived IV)

The original StegoChat used `MD5(key + frame_number)` as IV. Engare uses `os.urandom(12)` because:
- MD5 is broken — collisions are practical
- Deterministic IVs leak information if the same key encrypts different messages
- `os.urandom` uses the OS CSPRNG (cryptographically secure pseudorandom number generator)

## Steganography Security

### LSB Detection Risk

LSB steganography is the simplest form of image steganography. It is:

- **Invisible to humans:** Max pixel change is 1.2% per channel
- **Detectable by algorithms:** Chi-square analysis, RS analysis, and StegDetect can identify LSB manipulation with high accuracy on uncompressed images

**Risk assessment:**
- If an adversary does not suspect steganography → **safe**
- If an adversary actively scans for steganography → **detectable** (but content remains encrypted and unreadable)
- If an adversary both detects AND has the key → **compromised**

### Deniability Properties

1. **No error on wrong key:** The decode command outputs the cover video silently. There is no "wrong password" error, no exception, no different behavior.
2. **No metadata markers:** The MAGIC bytes "ENG1" are embedded inside LSBs, not visible in file metadata, headers, or format structures.
3. **Normal file format:** Output is standard MKV. No custom file extensions, no unusual headers.

### Known Weakness: File Format

MKV with FFV1 codec is unusual for casual video sharing. Most consumer video is H.264 in MP4. An adversary aware of steganography tools might flag MKV/FFV1 files as suspicious.

**Mitigation (v0.2.0):** The `--codec h264` option produces standard MP4 files using libx264rgb at CRF 0 (mathematically lossless in RGB colorspace). These files are less suspicious than MKV/FFV1 and 2-5x smaller, while still preserving steganographic data exactly. Future work: DCT-domain steganography that survives lossy compression.

## Key Management Security

### Private Key Storage

- Stored in `~/.engare/<name>.key`
- File permissions: `chmod 0o600` (owner read/write only)
- Format: JSON with base64-encoded key data
- **Optional passphrase encryption:** `engare keygen <name> --encrypt` protects the private key at rest using scrypt + AES-256-GCM. The passphrase is prompted interactively when the key is loaded.
- Unencrypted keys use type `engare-private-key-v1`; encrypted keys use type `engare-private-key-v1-encrypted` and store the ciphertext + scrypt salt instead of raw private bytes

### Public Key Verification

Public keys have a fingerprint: `SHA-256(public_key_bytes)` displayed as `xxxx:xxxx:xxxx:xxxx:xxxx`.

Users should verify fingerprints out-of-band (phone call, in person) to prevent MITM attacks during key exchange.

## What Open Source Means for Security

**Open source makes Engare MORE secure, not less.** This is Kerckhoffs's Principle (1883):

> "A cryptographic system should be secure even if everything about the system, except the key, is public knowledge."

- AES-256 is fully public — every government knows how it works. Still unbreakable without the key.
- X25519 is fully public — used by billions of devices. Still secure.
- The `cryptography` library is open source and audited by security professionals.
- Closed-source crypto cannot be verified — it could contain backdoors (see: NSA's Dual_EC_DRBG).
- Open-source invites review — bugs are found and fixed by the community.

## Recommendations for Users

1. **Use key pair mode** for ongoing communication — it's the most secure
2. **Verify fingerprints** in person or over a trusted channel
3. **Use strong passwords** if using password mode (16+ characters)
4. **Transfer files directly** — do not upload to social media (compression destroys hidden data)
5. **Keep private keys backed up** — losing your private key means losing access to all messages encrypted to you
6. **Use on a clean device** — steganography cannot protect against malware on your machine
