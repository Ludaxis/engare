"""Tests for the Engare steganography module."""

import numpy as np
from engare import stego


def test_capacity():
    assert stego.capacity(1920, 1080) == (1920 * 1080 * 3 * 2) // 8
    assert stego.capacity(100, 100) == (100 * 100 * 3 * 2) // 8


def test_embed_extract_roundtrip():
    """Data hidden in a frame can be extracted back."""
    cover = np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)
    data = b"Engare test message"

    stego_frame = stego.embed(cover, data)
    extracted = stego.extract(stego_frame, len(data))

    assert extracted == data


def test_embed_preserves_shape():
    cover = np.random.randint(0, 256, (64, 64, 3), dtype=np.uint8)
    data = b"test"

    result = stego.embed(cover, data)
    assert result.shape == cover.shape


def test_visual_similarity():
    """Stego frame should be visually similar to cover (< 2.5% difference)."""
    cover = np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)
    cap = stego.capacity(100, 100)
    data = bytes(range(256)) * (cap // 256)
    data = data[:cap]

    stego_frame = stego.embed(cover, data)

    # Max pixel change with 2 bits is 3 (out of 255) = 1.2%
    max_diff = np.max(np.abs(cover.astype(int) - stego_frame.astype(int)))
    assert max_diff <= 3


def test_overflow_raises():
    """Embedding more data than capacity should raise."""
    cover = np.random.randint(0, 256, (10, 10, 3), dtype=np.uint8)
    cap = stego.capacity(10, 10)
    data = b"\xff" * (cap + 1)

    try:
        stego.embed(cover, data)
        assert False, "Should have raised"
    except ValueError:
        pass
