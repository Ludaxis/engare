"""
Engare steganography engine.

Hides encrypted data in the Least Significant Bits (LSB) of video frames.
Changes < 2.5% of pixel values — invisible to the human eye.

The same frame looks identical to anyone watching.
Only someone who knows what to look for — and has the key — can extract anything.
"""

import numpy as np

# Default: 2 bits per color channel (RGB = 6 bits per pixel)
DEFAULT_BITS = 2


def capacity(width: int, height: int, bits: int = DEFAULT_BITS) -> int:
    """How many bytes can be hidden in a single frame."""
    return (width * height * 3 * bits) // 8


def embed(cover: np.ndarray, data: bytes, bits: int = DEFAULT_BITS) -> np.ndarray:
    """
    Hide data in the LSBs of a cover frame.

    cover: RGB image as numpy array (H, W, 3)
    data:  bytes to hide (must fit within capacity)
    bits:  bits per channel to use (1-4)
    """
    flat = cover.copy().flatten().astype(np.uint8)
    max_bytes = (len(flat) * bits) // 8

    if len(data) > max_bytes:
        raise ValueError(f"Data ({len(data)} bytes) exceeds capacity ({max_bytes} bytes)")

    # Convert bytes to individual bits
    data_bits = []
    for byte in data:
        for i in range(8):
            data_bits.append((byte >> (7 - i)) & 1)

    # Pad to align with bits-per-channel
    while len(data_bits) % bits:
        data_bits.append(0)

    # Clear LSBs and embed data
    mask = (0xFF << bits) & 0xFF
    bi = 0
    for i in range(len(flat)):
        if bi >= len(data_bits):
            break
        v = int(flat[i]) & mask
        for b in range(bits):
            if bi < len(data_bits):
                v |= data_bits[bi] << (bits - 1 - b)
                bi += 1
        flat[i] = v

    return flat.reshape(cover.shape)


def extract(stego: np.ndarray, length: int, bits: int = DEFAULT_BITS) -> bytes:
    """
    Extract hidden data from the LSBs of a stego frame.

    stego:  RGB image as numpy array (H, W, 3)
    length: number of bytes to extract
    bits:   bits per channel used during embedding
    """
    flat = stego.flatten()
    needed_bits = length * 8

    data_bits = []
    for i in range(len(flat)):
        if len(data_bits) >= needed_bits:
            break
        for b in range(bits):
            data_bits.append((int(flat[i]) >> (bits - 1 - b)) & 1)

    # Convert bits back to bytes
    result = bytearray()
    for i in range(0, len(data_bits) - 7, 8):
        byte = 0
        for b in range(8):
            byte = (byte << 1) | data_bits[i + b]
        result.append(byte)

    return bytes(result[:length])
