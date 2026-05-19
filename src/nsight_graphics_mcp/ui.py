"""UI hand-off helpers.

Sometimes the right move is to open a capture in the Nsight Graphics UI for
human inspection — the GUI's interactive views (PSO browser, shader source
profiler scroll, etc.) cannot be fully replicated headless. We expose a
small ``open_in_ui`` wrapper for that, and a tool to spawn the ``ngfx-ui``
process as a launch session so it can be cleanly stopped from the MCP later.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .cli import start_background
from .config import Settings, get_settings
from .session import get_sessions


def open_in_ui(
    path: str | None = None,
    *,
    extra_args: list[str] | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Launch ``ngfx-ui.exe`` (optionally passing a path) and register the
    process as a launch session."""
    s = settings or get_settings()
    exe = s.require_tool("ngfx_ui")
    argv: list[str] = [str(exe)]
    if path:
        argv.append(path)
    if extra_args:
        argv.extend(extra_args)
    bg = start_background("__tmp__", argv, tool="ngfx-ui")
    sess = get_sessions().register_launch(
        bg, tool="ngfx-ui", notes=f"opened {path!r} in Nsight Graphics UI" if path else "ngfx-ui"
    )
    return sess.summary()
