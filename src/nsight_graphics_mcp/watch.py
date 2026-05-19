"""Capture-directory watcher.

For hotkey-driven workflows the user launches the app in the background,
plays to a known spot, hits F11, and *then* wants the MCP to find the
capture that just landed. This is exactly the case where polling a
directory is the right call — Nsight writes the file atomically when the
capture completes (so a size-stable check is sufficient).
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from .captures import CAPTURE_EXTS, GPUTRACE_EXTS, list_captures_in_dir


def _snapshot(dirs: list[Path], kinds: tuple[str, ...]) -> dict[Path, float]:
    """{path -> mtime} for every matching file currently on disk."""
    snap: dict[Path, float] = {}
    for d in dirs:
        for c in list_captures_in_dir(d, kinds=kinds):
            snap[c.path] = c.mtime
    return snap


async def wait_for_new_capture(
    dirs: list[Path],
    *,
    kinds: tuple[str, ...] = ("graphics_capture", "gpu_trace"),
    timeout_sec: float = 300.0,
    poll_interval_sec: float = 1.5,
    stable_for_sec: float = 2.5,
) -> dict[str, Any]:
    """Poll one or more directories until a new capture (or gputrace) appears
    and its size stops changing, or ``timeout_sec`` elapses.

    Returns the new file's path + size + mtime, or ``{"timed_out": True}``.
    """
    dirs = [d for d in dirs if d.is_dir()]
    if not dirs:
        return {"timed_out": False, "error": "no valid watch dirs supplied"}

    baseline = _snapshot(dirs, kinds)
    deadline = asyncio.get_event_loop().time() + timeout_sec
    while asyncio.get_event_loop().time() < deadline:
        current = _snapshot(dirs, kinds)
        new_paths = [
            p for p, m in current.items() if p not in baseline or baseline[p] != m
        ]
        if new_paths:
            # Pick the newest, then wait for its size to stabilise.
            target = max(new_paths, key=lambda p: current[p])
            stable_since = None
            last_size = -1
            stable_deadline = asyncio.get_event_loop().time() + 30.0  # cap stability wait
            while asyncio.get_event_loop().time() < stable_deadline:
                try:
                    size = target.stat().st_size
                except OSError:
                    size = -1
                now = asyncio.get_event_loop().time()
                if size != last_size:
                    last_size = size
                    stable_since = now
                elif stable_since is not None and (now - stable_since) >= stable_for_sec:
                    return {
                        "timed_out": False,
                        "path": str(target),
                        "size_bytes": size,
                        "mtime": target.stat().st_mtime,
                    }
                await asyncio.sleep(poll_interval_sec)
            # Didn't stabilise — still return what we have
            return {
                "timed_out": False,
                "path": str(target),
                "size_bytes": last_size,
                "note": "size never stabilised within the stability window",
            }
        await asyncio.sleep(poll_interval_sec)
    return {"timed_out": True, "watched_dirs": [str(d) for d in dirs]}
