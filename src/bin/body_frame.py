#!/usr/bin/env python3
"""Thin frame-grab shim for the `body` faculty.

Grabs ONE camera frame from the configured Reachy Mini daemon and writes it as
a PNG to the path given as argv[1]; argv[2] is the daemon base URL. Prints
"WIDTHxHEIGHT" to stdout.

This is the single Python island in `body`: frame pixels only flow over the
daemon's WebRTC/GStreamer pipeline, with no plain HTTP snapshot endpoint, so
pulling them natively would mean a gstreamer-rs/webrtc-rs build. Everything
else in the faculty — proprioception, motion, the pile write — is pure Rust
over the daemon's REST API. This shim is the obvious target for a native
Rust frame path once the VLA loop needs the continuous stream.

The faculty embeds this file (include_str!) and writes it to a temp path at
runtime, so there is no loose script to lose.
"""
import sys
import time
from urllib.parse import urlsplit

import numpy as np
from PIL import Image
from reachy_mini import ReachyMini


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: body_frame.py <out.png> <daemon-url>", file=sys.stderr)
        return 64
    out = sys.argv[1]
    daemon = urlsplit(sys.argv[2])
    if (
        daemon.scheme != "http"
        or daemon.hostname is None
        or daemon.username is not None
        or daemon.password is not None
        or daemon.path not in ("", "/")
        or daemon.query
        or daemon.fragment
    ):
        print("daemon URL must be an HTTP origin without credentials or a path", file=sys.stderr)
        return 64
    try:
        port = daemon.port or 80
    except ValueError as error:
        print(f"invalid daemon port: {error}", file=sys.stderr)
        return 64
    host = daemon.hostname
    connection_mode = (
        "localhost_only"
        if host.lower() in ("localhost", "127.0.0.1", "::1")
        else "network"
    )

    # Context manager handles teardown (media_manager.close + client.disconnect).
    with ReachyMini(
        host=host,
        port=port,
        connection_mode=connection_mode,
        spawn_daemon=False,
    ) as mini:
        # WebRTC frames can be None for the first moment while the pipeline
        # ramps up — give it a brief window rather than failing on a cold pull.
        frame = None
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            frame = mini.media.get_frame()
            if frame is not None:
                break
            time.sleep(0.1)
        if frame is None:
            print("no frame available from daemon", file=sys.stderr)
            return 2

        # get_frame returns BGR uint8 (H, W, 3); store true-colour RGB.
        rgb = np.ascontiguousarray(frame[:, :, ::-1])
        Image.fromarray(rgb).save(out)
        h, w = frame.shape[:2]
        print(f"{w}x{h}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
