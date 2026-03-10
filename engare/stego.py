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

    # Convert bytes to bit array (MSB first)
    data_arr = np.frombuffer(data, dtype=np.uint8)
    data_bits = np.unpackbits(data_arr)

    # Pad to align with bits-per-channel
    pad = (-len(data_bits)) % bits
    if pad:
        data_bits = np.concatenate([data_bits, np.zeros(pad, dtype=np.uint8)])

    # Group bits and compute the value to embed per channel
    num_channels = len(data_bits) // bits
    bit_groups = data_bits.reshape(-1, bits)
    multipliers = (1 << np.arange(bits - 1, -1, -1)).astype(np.uint8)
    data_values = (bit_groups * multipliers).sum(axis=1).astype(np.uint8)

    # Clear LSBs and embed
    mask = np.uint8((0xFF << bits) & 0xFF)
    flat[:num_channels] = (flat[:num_channels] & mask) | data_values

    return flat.reshape(cover.shape)


def extract(stego: np.ndarray, length: int, bits: int = DEFAULT_BITS) -> bytes:
    """
    Extract hidden data from the LSBs of a stego frame.

    stego:  RGB image as numpy array (H, W, 3)
    length: number of bytes to extract
    bits:   bits per channel used during embedding
    """
    flat = stego.flatten().astype(np.uint8)
    needed_bits = length * 8
    needed_channels = (needed_bits + bits - 1) // bits
    pixel_values = flat[:needed_channels]

    # Extract bit planes from LSBs
    bit_planes = []
    for b in range(bits):
        shift = bits - 1 - b
        bit_planes.append((pixel_values >> shift) & 1)

    # Interleave bits from each channel and flatten
    data_bits = np.column_stack(bit_planes).flatten()[:needed_bits]

    # Pad to byte boundary and pack
    pad = (-len(data_bits)) % 8
    if pad:
        data_bits = np.concatenate([data_bits, np.zeros(pad, dtype=np.uint8)])

    return bytes(np.packbits(data_bits.astype(np.uint8))[:length])
