"""Capture-file discovery, listing, and diffing.

The Nsight Graphics UI has a 'Recent Captures' panel that watches the user's
captures directory. We replicate that here as plain filesystem operations so
the MCP can answer 'find the capture I just took' without re-implementing
the UI's state.

Capture extensions in the wild:
  * ``.ngfx-gfxcap``  — current Graphics Capture format
  * ``.gfxcap``       — legacy alias
  * ``.nsightgfx``    — extremely old; we still recognise it
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Settings, default_captures_dir, default_gputrace_dir, get_settings


CAPTURE_EXTS = (".ngfx-gfxcap", ".gfxcap", ".nsightgfx", ".nsight-gfxcapture")
GPUTRACE_EXTS = (".nsight-gputrace", ".gputrace")


@dataclass
class CaptureFile:
    path: Path
    size_bytes: int
    mtime: float
    kind: str  # "graphics_capture" | "gpu_trace"

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "size_bytes": self.size_bytes,
            "mtime": self.mtime,
            "kind": self.kind,
            "name": self.path.name,
        }


def _classify(p: Path) -> str | None:
    suffix = p.suffix.lower()
    full = p.name.lower()
    if any(full.endswith(ext) for ext in CAPTURE_EXTS):
        return "graphics_capture"
    if any(full.endswith(ext) for ext in GPUTRACE_EXTS):
        return "gpu_trace"
    if suffix in CAPTURE_EXTS:
        return "graphics_capture"
    if suffix in GPUTRACE_EXTS:
        return "gpu_trace"
    return None


def list_captures_in_dir(
    directory: Path,
    *,
    include_subdirs: bool = True,
    kinds: tuple[str, ...] = ("graphics_capture", "gpu_trace"),
) -> list[CaptureFile]:
    """Enumerate capture files under ``directory`` (recursively by default).

    Returns newest-first.
    """
    if not directory.is_dir():
        return []
    out: list[CaptureFile] = []
    walker = os.walk(directory) if include_subdirs else [(str(directory), [], os.listdir(directory))]
    for root, _dirs, files in walker:
        for fname in files:
            p = Path(root) / fname
            try:
                kind = _classify(p)
                if not kind or kind not in kinds:
                    continue
                st = p.stat()
                out.append(CaptureFile(path=p, size_bytes=st.st_size, mtime=st.st_mtime, kind=kind))
            except OSError:
                continue
    out.sort(key=lambda c: c.mtime, reverse=True)
    return out


def find_recent_captures(
    *,
    settings: Settings | None = None,
    limit: int = 20,
    kinds: tuple[str, ...] = ("graphics_capture", "gpu_trace"),
    extra_dirs: list[Path] | None = None,
) -> dict[str, Any]:
    """Look in the standard Nsight Graphics output directories for recent
    captures and gputrace files.
    """
    s = settings or get_settings()
    dirs: list[Path] = []
    if s.captures_dir.is_dir():
        dirs.append(s.captures_dir)
    if s.gputrace_dir.is_dir():
        dirs.append(s.gputrace_dir)
    default_caps = default_captures_dir()
    if default_caps != s.captures_dir and default_caps.is_dir():
        dirs.append(default_caps)
    default_trace = default_gputrace_dir()
    if default_trace != s.gputrace_dir and default_trace.is_dir():
        dirs.append(default_trace)
    if extra_dirs:
        for d in extra_dirs:
            if d.is_dir():
                dirs.append(d)
    # Dedup
    seen: set[Path] = set()
    uniq_dirs: list[Path] = []
    for d in dirs:
        r = d.resolve()
        if r not in seen:
            seen.add(r)
            uniq_dirs.append(r)

    combined: list[CaptureFile] = []
    for d in uniq_dirs:
        combined.extend(list_captures_in_dir(d, kinds=kinds))
    combined.sort(key=lambda c: c.mtime, reverse=True)
    return {
        "searched_dirs": [str(d) for d in uniq_dirs],
        "captures": [c.to_dict() for c in combined[:limit]],
        "total_found": len(combined),
    }


def diff_metadata(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Shallow diff of two parsed metadata dicts (from ``ngfx_capture_summary``).

    Returns ``{only_in_a, only_in_b, changed: {key: [a, b]}}``.
    """
    a_flat = _flatten(a)
    b_flat = _flatten(b)
    keys = set(a_flat) | set(b_flat)
    only_a: list[str] = []
    only_b: list[str] = []
    changed: dict[str, list[Any]] = {}
    same_count = 0
    for k in sorted(keys):
        if k in a_flat and k not in b_flat:
            only_a.append(k)
        elif k in b_flat and k not in a_flat:
            only_b.append(k)
        elif a_flat[k] != b_flat[k]:
            changed[k] = [a_flat[k], b_flat[k]]
        else:
            same_count += 1
    return {
        "only_in_a": only_a,
        "only_in_b": only_b,
        "changed": changed,
        "same_count": same_count,
    }


def _flatten(d: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        if k.startswith("_"):
            continue
        key = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, prefix=key))
        elif isinstance(v, list):
            out[key] = tuple(v) if all(isinstance(x, (str, int, float, bool)) for x in v) else len(v)
        else:
            out[key] = v
    return out
