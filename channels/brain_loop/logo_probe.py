#!/usr/bin/env python3
"""Logo-presence probe for a single channel frame.

Reads a JPEG/PNG frame, crops the top-right corner (where channel
branding lives), and reports whether a logo appears to be present
based on variance and edge density.

This is a pre-stage signal for the brain wake. It does NOT answer
"is this the correct logo?" — that semantic check stays with the
brain's visual sub-agents. It answers only "is there something
logo-shaped in the top-right corner, or is the region smooth?"

Rule 10 (channels/brain/lessons.db) requires 5 rounds of
logo-absence spaced ~3 min apart before any mismatch flag. This
probe produces one round's signal. The bash wrapper accumulates
rounds into each channel's state file as `logo_history`.

Output: one JSON object on stdout. Non-zero exit on error.
"""

from __future__ import annotations
import json
import os
import sys
from typing import Any

try:
    from PIL import Image, ImageFilter
except ImportError:  # pragma: no cover
    print(json.dumps({"error": "PIL (Pillow) not installed"}), file=sys.stderr)
    sys.exit(3)

try:
    import numpy as np
except ImportError:  # pragma: no cover
    print(json.dumps({"error": "numpy not installed"}), file=sys.stderr)
    sys.exit(3)


# Region of interest. Channel logos across all 22 baselines fall within
# the rightmost 22% of width and the top 22% of height. Slightly wider
# than strictly needed to tolerate aspect-ratio drift.
ROI_RIGHT_FRAC = 0.22
ROI_TOP_FRAC = 0.22

# Thresholds calibrated against the 22 baseline thumbnails in
# channels/baselines/ (all have logos present). See README note in
# lessons_schema.sql for how these were derived. Tuned to detect
# present-logo with high recall; occasional false-positives (logo
# reported present when it's actually program graphics) are absorbed
# by rule 10's 5-round requirement.
VARIANCE_THRESHOLD = 350.0
EDGE_THRESHOLD = 12.0


def analyze(image_path: str) -> dict[str, Any]:
    img = Image.open(image_path).convert("RGB")
    w, h = img.size
    if w < 100 or h < 60:
        return {"error": f"frame too small: {w}x{h}"}
    # Crop the top-right corner.
    left = int(w * (1.0 - ROI_RIGHT_FRAC))
    bottom = int(h * ROI_TOP_FRAC)
    region = img.crop((left, 0, w, bottom))
    arr = np.asarray(region, dtype=np.float32)
    # Per-channel variance averaged across R/G/B.
    variance = float(arr.var(axis=(0, 1)).mean())
    # Edge density via a simple high-pass filter. PIL's FIND_EDGES is a
    # 3x3 Laplacian-like kernel — cheap and adequate for "is there
    # structure here vs smooth gradient?" signal.
    edges = region.filter(ImageFilter.FIND_EDGES)
    edge_density = float(np.asarray(edges, dtype=np.float32).mean())

    logo_present = (
        variance >= VARIANCE_THRESHOLD or edge_density >= EDGE_THRESHOLD
    )
    # Confidence: how far above/below the nearer threshold (0 = at
    # threshold, 1 = well above/below). Clipped to [0, 1].
    v_margin = variance / VARIANCE_THRESHOLD
    e_margin = edge_density / EDGE_THRESHOLD
    signal = max(v_margin, e_margin) if logo_present else min(v_margin, e_margin)
    confidence = float(min(max(abs(signal - 1.0), 0.0), 1.0))

    return {
        "logo_present": bool(logo_present),
        "variance": round(variance, 2),
        "edge_density": round(edge_density, 2),
        "confidence": round(confidence, 3),
        "roi_size": [w - left, bottom],
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(json.dumps({"error": "usage: logo_probe.py <image-path>"}),
              file=sys.stderr)
        return 2
    path = argv[1]
    if not os.path.isfile(path):
        print(json.dumps({"error": f"file not found: {path}"}), file=sys.stderr)
        return 2
    try:
        result = analyze(path)
    except Exception as e:  # pragma: no cover
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}), file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
