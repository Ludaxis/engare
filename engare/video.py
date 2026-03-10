"""
Engare video I/O engine.

Uses FFmpeg for frame extraction and video reconstruction.
All frame processing is done losslessly (FFV1/PNG) to preserve steganographic data.
"""

import json
import os
import shutil
import subprocess
import tempfile

import numpy as np
from PIL import Image


def check_ffmpeg():
    """Verify FFmpeg is available."""
    if shutil.which("ffmpeg") is None or shutil.which("ffprobe") is None:
        raise RuntimeError(
            "FFmpeg not found. Install it:\n"
            "  macOS:   brew install ffmpeg\n"
            "  Ubuntu:  sudo apt install ffmpeg\n"
            "  Windows: https://ffmpeg.org/download.html"
        )


def get_info(path: str) -> dict:
    """Get video metadata."""
    check_ffmpeg()
    cmd = [
        "ffprobe", "-v", "quiet", "-print_format", "json",
        "-show_streams", "-show_format", str(path),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise ValueError(f"Cannot read video: {path}")

    info = json.loads(result.stdout)
    vs = next(
        (s for s in info.get("streams", []) if s["codec_type"] == "video"),
        None,
    )
    if not vs:
        raise ValueError(f"No video stream in {path}")

    fps_str = vs.get("r_frame_rate", "30/1")
    if "/" in fps_str:
        num, den = fps_str.split("/")
        fps = float(num) / float(den)
    else:
        fps = float(fps_str)

    return {
        "width": int(vs["width"]),
        "height": int(vs["height"]),
        "fps": fps,
        "duration": float(info.get("format", {}).get("duration", 0)),
        "has_audio": any(
            s["codec_type"] == "audio" for s in info.get("streams", [])
        ),
    }


def extract_frames(path: str, outdir: str, max_frames: int | None = None) -> int:
    """Extract video frames as PNG files. Returns frame count."""
    os.makedirs(outdir, exist_ok=True)
    cmd = ["ffmpeg", "-y", "-i", str(path)]
    if max_frames:
        cmd += ["-frames:v", str(max_frames)]
    cmd += ["-start_number", "0", os.path.join(outdir, "frame_%06d.png")]
    subprocess.run(cmd, capture_output=True)
    return len([f for f in os.listdir(outdir) if f.startswith("frame_")])


def extract_audio(path: str, output: str) -> bool:
    """Extract audio track from video."""
    r = subprocess.run(
        ["ffmpeg", "-y", "-i", str(path), "-vn", "-acodec", "aac", "-b:a", "128k", output],
        capture_output=True,
    )
    return r.returncode == 0 and os.path.exists(output)


def build_video(frames_dir: str, output: str, fps: float,
                audio: str | None = None, codec: str = "ffv1"):
    """Reconstruct video from frames using a lossless codec.

    codec: "ffv1" (default, MKV) or "h264" (H.264 lossless RGB, smaller files).
    Both are bit-exact in RGB — steganographic data survives the roundtrip.
    """
    cmd = [
        "ffmpeg", "-y",
        "-framerate", str(fps),
        "-i", os.path.join(frames_dir, "frame_%06d.png"),
    ]
    if audio and os.path.exists(audio):
        cmd += ["-i", audio, "-c:a", "aac", "-b:a", "128k"]

    if codec == "h264":
        cmd += [
            "-c:v", "libx264rgb",  # H.264 in RGB colorspace — no YUV conversion loss
            "-crf", "0",           # Mathematically lossless
            "-preset", "ultrafast",
            "-pix_fmt", "rgb24",
        ]
    else:  # ffv1
        cmd += [
            "-c:v", "ffv1",
            "-level", "3",
            "-pix_fmt", "rgb24",
        ]

    cmd += ["-shortest", str(output)]
    subprocess.run(cmd, capture_output=True)


def read_frames(path: str) -> tuple[list[np.ndarray], dict]:
    """Read all frames from video via FFmpeg pipe (no disk I/O).

    Returns (list of RGB numpy arrays, video info dict).
    """
    check_ffmpeg()
    info = get_info(path)
    w, h = info["width"], info["height"]
    frame_size = w * h * 3

    proc = subprocess.Popen(
        ["ffmpeg", "-i", str(path), "-f", "rawvideo", "-pix_fmt", "rgb24",
         "-v", "quiet", "pipe:1"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )

    frames = []
    while True:
        raw = proc.stdout.read(frame_size)
        if len(raw) < frame_size:
            break
        frames.append(np.frombuffer(raw, dtype=np.uint8).reshape((h, w, 3)).copy())

    proc.wait()
    return frames, info


def write_frames(frames: list[np.ndarray], output: str, fps: float,
                 codec: str = "ffv1", audio: str | None = None):
    """Write frames to video via FFmpeg pipe (no disk I/O).

    frames: list of RGB numpy arrays (all same shape)
    """
    check_ffmpeg()
    if not frames:
        return

    h, w = frames[0].shape[:2]

    cmd = [
        "ffmpeg", "-y",
        "-f", "rawvideo", "-pix_fmt", "rgb24",
        "-s", f"{w}x{h}", "-r", str(fps),
        "-i", "pipe:0",
    ]
    if audio and os.path.exists(audio):
        cmd += ["-i", audio, "-c:a", "aac", "-b:a", "128k"]

    if codec == "h264":
        cmd += ["-c:v", "libx264rgb", "-crf", "0", "-preset", "ultrafast",
                "-pix_fmt", "rgb24"]
    else:
        cmd += ["-c:v", "ffv1", "-level", "3", "-pix_fmt", "rgb24"]

    cmd += ["-shortest", str(output)]

    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    for frame in frames:
        proc.stdin.write(frame.astype(np.uint8).tobytes())
    proc.stdin.close()
    proc.wait()


def load_frame(path: str) -> np.ndarray:
    """Load a frame as RGB numpy array."""
    return np.array(Image.open(path).convert("RGB"))


def save_frame(frame: np.ndarray, path: str):
    """Save a numpy array as PNG frame."""
    Image.fromarray(frame.astype(np.uint8)).save(path)


def video_to_key(video_path: str) -> bytes:
    """
    Derive a 256-bit key from a video file.
    The same video always produces the same key.

    Uses 5 evenly-spaced frames (resized to 64x64) + first 1MB of file data.
    Share the video on USB — it IS the key.
    """
    import hashlib

    check_ffmpeg()
    tmpdir = tempfile.mkdtemp()
    try:
        # Get duration
        cmd = ["ffprobe", "-v", "quiet", "-print_format", "json", "-show_format", video_path]
        info = json.loads(subprocess.run(cmd, capture_output=True, text=True).stdout)
        duration = float(info.get("format", {}).get("duration", 1))

        hasher = hashlib.sha256()

        for i in range(5):
            t = duration * (i + 1) / 6
            frame_path = os.path.join(tmpdir, f"key_{i}.png")
            subprocess.run(
                ["ffmpeg", "-y", "-ss", str(t), "-i", video_path,
                 "-frames:v", "1", "-f", "image2", frame_path],
                capture_output=True,
            )
            if os.path.exists(frame_path):
                img = np.array(
                    Image.open(frame_path).convert("RGB").resize((64, 64), Image.LANCZOS)
                )
                hasher.update(img.tobytes())

        # Also hash raw file bytes for uniqueness
        with open(video_path, "rb") as f:
            hasher.update(f.read(1024 * 1024))

        return hasher.digest()  # 32 bytes = 256 bits

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
