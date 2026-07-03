#!/usr/bin/env python3
"""
nsfw_scan.py — content scanner for VideoTub's CONTENT_SCAN_CMD hook.

Samples frames from a video with ffmpeg and runs the open-source NudeNet
detector on each frame. Exit code 0 = allow, non-zero = reject (matching the
CONTENT_SCAN_CMD contract). This is a decoupled CLI so VideoTub itself stays
dependency-light — it only shells out to this scanner when configured.

Usage (set in VideoTub's environment):
    CONTENT_SCAN_CMD="python /path/to/tools/nsfw_scan.py"
VideoTub appends the uploaded file path as the final argument.

Requirements on the host running VideoTub:
    pip install nudenet
    ffmpeg + ffprobe on PATH
If either is missing the scanner FAILS CLOSED (exit 1) so nothing slips through
unscanned when scanning was explicitly enabled.
"""
import sys
import os
import subprocess
import tempfile
import shutil

# NudeNet detection classes treated as disallowed, at a 0.85 confidence floor.
NSFW_ALERT_CLASSES = {
    "FEMALE_BREAST_EXPOSED", "FEMALE_GENITALIA_EXPOSED",
    "MALE_GENITALIA_EXPOSED", "ANUS_EXPOSED", "BUTTOCKS_EXPOSED",
}
THRESHOLD = 0.85
FRAMES = int(os.environ.get("NSFW_FRAMES", "8"))   # frames sampled across the clip


def fail_closed(msg):
    sys.stderr.write(f"[nsfw_scan] {msg}\n")
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        fail_closed("no video path provided")
    video = sys.argv[-1]
    if not os.path.isfile(video):
        fail_closed(f"file not found: {video}")
    if not shutil.which("ffmpeg"):
        fail_closed("ffmpeg not found (required to sample frames)")

    try:
        from nudenet import NudeDetector
    except Exception as e:
        fail_closed(f"nudenet not installed ({e}); run: pip install nudenet")

    tmpdir = tempfile.mkdtemp(prefix="nsfw_")
    try:
        # Sample FRAMES evenly-spaced frames as JPEGs.
        pattern = os.path.join(tmpdir, "f_%03d.jpg")
        cmd = [
            "ffmpeg", "-v", "error", "-i", video,
            "-vf", f"fps={max(1, FRAMES)}/60,scale=640:-1",
            "-frames:v", str(FRAMES), pattern,
        ]
        subprocess.run(cmd, check=False, timeout=120)
        frames = [os.path.join(tmpdir, f) for f in os.listdir(tmpdir) if f.endswith(".jpg")]
        if not frames:
            # Could not extract frames — treat as un-scannable → reject.
            fail_closed("could not extract frames for scanning")

        detector = NudeDetector()
        for frame in frames:
            try:
                for det in detector.detect(frame):
                    if det.get("class") in NSFW_ALERT_CLASSES and det.get("score", 0) >= THRESHOLD:
                        sys.stderr.write(
                            f"[nsfw_scan] REJECT: {det.get('class')} "
                            f"score={det.get('score'):.2f} in {os.path.basename(frame)}\n"
                        )
                        sys.exit(2)  # non-zero → VideoTub rejects the upload
            except Exception as e:
                sys.stderr.write(f"[nsfw_scan] frame error ({e})\n")
        # No alert-class detections above threshold on any sampled frame.
        sys.exit(0)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
