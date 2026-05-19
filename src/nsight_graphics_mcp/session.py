"""Session registry for nsight-graphics-mcp.

Three kinds of sessions:

* **CaptureSession** — a known capture file on disk. We cache parsed metadata
  (from ``ngfx-replay --metadata``) keyed by mtime, so subsequent queries
  return instantly.

* **GpuTraceSession** — a known ``.nsight-gputrace`` file on disk, with cached
  zip-based contents enumeration.

* **LaunchSession** — a long-running background process (e.g. ``ngfx
  --activity 'Graphics Capture' --hotkey-capture …`` or
  ``nv-nsight-remote-monitor``) the user drives interactively.
"""

from __future__ import annotations

import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .cli import BackgroundProcess


def _slug(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_-]+", "_", s)
    return s[:48] or "session"


@dataclass
class CaptureSession:
    handle: str
    path: Path
    # last cached metadata + the mtime at the time of caching
    metadata: dict[str, Any] | None = None
    metadata_mtime: float | None = None
    notes: str = ""

    def summary(self) -> dict[str, Any]:
        return {
            "handle": self.handle,
            "path": str(self.path),
            "size_bytes": self.path.stat().st_size if self.path.is_file() else None,
            "has_metadata": self.metadata is not None,
            "notes": self.notes,
        }


@dataclass
class GpuTraceSession:
    handle: str
    path: Path
    summary_cache: dict[str, Any] | None = None
    summary_mtime: float | None = None
    notes: str = ""

    def summary(self) -> dict[str, Any]:
        return {
            "handle": self.handle,
            "path": str(self.path),
            "size_bytes": self.path.stat().st_size if self.path.is_file() else None,
            "has_summary": self.summary_cache is not None,
            "notes": self.notes,
        }


@dataclass
class LaunchSession:
    handle: str
    tool: str
    bg: BackgroundProcess
    activity: str | None = None
    exe: str | None = None
    notes: str = ""

    def summary(self) -> dict[str, Any]:
        return {
            "handle": self.handle,
            "tool": self.tool,
            "activity": self.activity,
            "exe": self.exe,
            "pid": self.bg.proc.pid,
            "running": self.bg.is_running(),
            "returncode": self.bg.returncode(),
            "uptime_sec": round(time.monotonic() - self.bg.started_at, 2),
            "cmdline": self.bg.cmdline,
            "notes": self.notes,
        }


class SessionManager:
    """Thread-safe registry of capture / GPU-trace / launch sessions."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._captures: dict[str, CaptureSession] = {}
        self._gputraces: dict[str, GpuTraceSession] = {}
        self._launches: dict[str, LaunchSession] = {}

    # ---- capture sessions ---------------------------------------------------

    def open_capture(self, path: Path, *, handle: str | None = None) -> CaptureSession:
        path = path.resolve()
        if not path.is_file():
            raise FileNotFoundError(f"capture not found: {path}")
        with self._lock:
            for sess in self._captures.values():
                if sess.path == path:
                    return sess
            h = handle or f"cap_{_slug(path.stem)}_{secrets.token_hex(3)}"
            sess = CaptureSession(handle=h, path=path)
            self._captures[h] = sess
            return sess

    def get_capture(self, handle: str) -> CaptureSession:
        with self._lock:
            sess = self._captures.get(handle)
            if sess is not None:
                return sess
        # Allow resolution by exact path
        p = Path(handle)
        if p.is_file():
            return self.open_capture(p)
        raise KeyError(f"capture session not found: {handle}")

    def list_captures(self) -> list[CaptureSession]:
        with self._lock:
            return list(self._captures.values())

    def close_capture(self, handle: str) -> bool:
        with self._lock:
            return self._captures.pop(handle, None) is not None

    # ---- gpu trace sessions -------------------------------------------------

    def open_gputrace(self, path: Path, *, handle: str | None = None) -> GpuTraceSession:
        path = path.resolve()
        if not path.is_file():
            raise FileNotFoundError(f"gputrace not found: {path}")
        with self._lock:
            for sess in self._gputraces.values():
                if sess.path == path:
                    return sess
            h = handle or f"gpt_{_slug(path.stem)}_{secrets.token_hex(3)}"
            sess = GpuTraceSession(handle=h, path=path)
            self._gputraces[h] = sess
            return sess

    def get_gputrace(self, handle: str) -> GpuTraceSession:
        with self._lock:
            sess = self._gputraces.get(handle)
            if sess is not None:
                return sess
        p = Path(handle)
        if p.is_file():
            return self.open_gputrace(p)
        raise KeyError(f"gputrace session not found: {handle}")

    def list_gputraces(self) -> list[GpuTraceSession]:
        with self._lock:
            return list(self._gputraces.values())

    def close_gputrace(self, handle: str) -> bool:
        with self._lock:
            return self._gputraces.pop(handle, None) is not None

    # ---- launch sessions ----------------------------------------------------

    def register_launch(
        self,
        bg: BackgroundProcess,
        *,
        tool: str,
        activity: str | None = None,
        exe: str | None = None,
        notes: str = "",
        handle: str | None = None,
    ) -> LaunchSession:
        with self._lock:
            base = _slug(Path(exe).stem) if exe else tool
            h = handle or f"run_{base}_{secrets.token_hex(3)}"
            sess = LaunchSession(
                handle=h, tool=tool, bg=bg, activity=activity, exe=exe, notes=notes
            )
            self._launches[h] = sess
            return sess

    def get_launch(self, handle: str) -> LaunchSession:
        with self._lock:
            sess = self._launches.get(handle)
            if sess is None:
                raise KeyError(f"launch session not found: {handle}")
            return sess

    def list_launches(self) -> list[LaunchSession]:
        with self._lock:
            return list(self._launches.values())

    def stop_launch(self, handle: str, *, timeout: float = 5.0) -> int:
        with self._lock:
            sess = self._launches.pop(handle, None)
        if sess is None:
            raise KeyError(f"launch session not found: {handle}")
        return sess.bg.terminate(timeout=timeout)

    def reap(self) -> list[str]:
        reaped: list[str] = []
        with self._lock:
            for h, sess in list(self._launches.items()):
                if not sess.bg.is_running():
                    del self._launches[h]
                    reaped.append(h)
        return reaped


_sessions: SessionManager | None = None


def get_sessions() -> SessionManager:
    global _sessions
    if _sessions is None:
        _sessions = SessionManager()
    return _sessions
