"""Configuration: Nsight Graphics install discovery, environment, default paths.

Resolution order for every binary:

  1. ``NSIGHT_GRAPHICS_MCP_<TOOL>`` env var (absolute path to that exe).
  2. ``NSIGHT_GRAPHICS_MCP_INSTALL_ROOT`` env var (folder that contains a
     ``host/windows-desktop-nomad-x64`` subdir).
  3. Newest installed version under ``C:/Program Files/NVIDIA Corporation``.
  4. The exe on PATH.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

NVIDIA_DEFAULT_ROOT = Path(r"C:\Program Files\NVIDIA Corporation")
NGFX_INSTALL_DIR_RE = re.compile(r"^Nsight Graphics (\d+)\.(\d+)\.(\d+)$")

HOST_SUBDIR = Path("host") / "windows-desktop-nomad-x64"

NGFX_INSTALL_ROOT_ENV = "NSIGHT_GRAPHICS_MCP_INSTALL_ROOT"
CACHE_DIR_ENV = "NSIGHT_GRAPHICS_MCP_CACHE_DIR"

# Tool name -> env var override -> default exe filename
TOOL_DEFINITIONS: dict[str, tuple[str, str]] = {
    "ngfx": ("NSIGHT_GRAPHICS_MCP_NGFX", "ngfx.exe"),
    "ngfx_capture": ("NSIGHT_GRAPHICS_MCP_NGFX_CAPTURE", "ngfx-capture.exe"),
    "ngfx_replay": ("NSIGHT_GRAPHICS_MCP_NGFX_REPLAY", "ngfx-replay.exe"),
    "ngfx_rpc": ("NSIGHT_GRAPHICS_MCP_NGFX_RPC", "ngfx-rpc.exe"),
    "ngfx_ui": ("NSIGHT_GRAPHICS_MCP_NGFX_UI", "ngfx-ui.exe"),
    "aftermath_control": ("NSIGHT_GRAPHICS_MCP_AFTERMATH_CONTROL", "nv-aftermath-control.exe"),
    "aftermath_monitor": ("NSIGHT_GRAPHICS_MCP_AFTERMATH_MONITOR", "nv-aftermath-monitor.exe"),
    "aftermath_format": ("NSIGHT_GRAPHICS_MCP_AFTERMATH_FORMAT", "nv-aftermath-format.exe"),
    "remote_monitor": (
        "NSIGHT_GRAPHICS_MCP_REMOTE_MONITOR",
        "nv-nsight-remote-monitor.exe",
    ),
    "shaderdebugger_configurator": (
        "NSIGHT_GRAPHICS_MCP_SHADERDEBUGGER_CONFIGURATOR",
        "nv-shaderdebugger-configurator.exe",
    ),
    "glslang": ("NSIGHT_GRAPHICS_MCP_GLSLANG", "glslang.exe"),
}


def _version_key_from_dir(name: str) -> tuple[int, ...]:
    """Sort 'Nsight Graphics 2026.1.0' / '... 2025.4.2' numerically."""
    m = NGFX_INSTALL_DIR_RE.match(name)
    if m:
        return tuple(int(p) for p in m.groups())
    parts = re.findall(r"\d+", name)
    return tuple(int(p) for p in parts) if parts else (0,)


def discover_install_roots() -> list[Path]:
    """All Nsight Graphics install roots found on this machine, newest first.

    An install root is a directory like ``C:/Program Files/NVIDIA Corporation/Nsight Graphics 2026.1.0``
    — it directly contains ``host/windows-desktop-nomad-x64/``.
    """
    candidates: list[Path] = []
    override = os.environ.get(NGFX_INSTALL_ROOT_ENV)
    if override:
        p = Path(override)
        if (p / HOST_SUBDIR).is_dir():
            candidates.append(p.resolve())

    if NVIDIA_DEFAULT_ROOT.is_dir():
        for entry in NVIDIA_DEFAULT_ROOT.iterdir():
            if entry.is_dir() and NGFX_INSTALL_DIR_RE.match(entry.name):
                if (entry / HOST_SUBDIR).is_dir():
                    candidates.append(entry.resolve())

    # newest-first by version tuple
    seen: set[Path] = set()
    out: list[Path] = []
    for c in sorted(candidates, key=lambda p: _version_key_from_dir(p.name), reverse=True):
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def host_bin_dir(install_root: Path | None = None) -> Path | None:
    """Resolve the ``host/windows-desktop-nomad-x64`` directory for an install."""
    if install_root is None:
        roots = discover_install_roots()
        if not roots:
            return None
        install_root = roots[0]
    candidate = install_root / HOST_SUBDIR
    return candidate if candidate.is_dir() else None


def discover_sdk_versions(install_root: Path | None = None) -> list[Path]:
    """List ``NsightGraphicsSDK/<version>/`` directories. Newest first."""
    if install_root is None:
        roots = discover_install_roots()
        if not roots:
            return []
        install_root = roots[0]
    sdk_dir = install_root / "SDKs" / "NsightGraphicsSDK"
    if not sdk_dir.is_dir():
        return []
    return sorted(
        (p for p in sdk_dir.iterdir() if p.is_dir() and (p / "include").is_dir()),
        key=lambda p: _version_key_from_dir(p.name),
        reverse=True,
    )


def find_tool(tool: str, install_root: Path | None = None) -> Path | None:
    """Resolve a tool path. ``tool`` is a key in ``TOOL_DEFINITIONS``."""
    if tool not in TOOL_DEFINITIONS:
        raise KeyError(f"Unknown tool '{tool}'. Known: {sorted(TOOL_DEFINITIONS)}")
    env_var, exe_name = TOOL_DEFINITIONS[tool]

    override = os.environ.get(env_var)
    if override:
        p = Path(override)
        if p.is_file():
            return p.resolve()

    bin_dir = host_bin_dir(install_root)
    if bin_dir is not None:
        candidate = bin_dir / exe_name
        if candidate.is_file():
            return candidate.resolve()

    from shutil import which

    found = which(exe_name.removesuffix(".exe"))
    if found:
        return Path(found).resolve()
    return None


def default_cache_dir() -> Path:
    """Where to store per-capture indexes, parsed metadata, replay outputs, etc."""
    override = os.environ.get(CACHE_DIR_ENV)
    if override:
        return Path(override)
    base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    return base / "nsight-graphics-mcp" / "cache"


def default_captures_dir() -> Path:
    """Where Nsight Graphics typically drops captures from the UI."""
    return Path.home() / "Documents" / "NVIDIA Nsight Graphics" / "Captures"


def default_gputrace_dir() -> Path:
    """Where GPU Trace reports are typically written."""
    return Path.home() / "Documents" / "NVIDIA Nsight Graphics" / "GPUTrace"


@dataclass
class Settings:
    install_root: Path | None = field(default_factory=lambda: (discover_install_roots() or [None])[0])
    cache_dir: Path = field(default_factory=default_cache_dir)
    captures_dir: Path = field(default_factory=default_captures_dir)
    gputrace_dir: Path = field(default_factory=default_gputrace_dir)
    cli_timeout_sec: int = 1200  # captures of slow apps can take a while
    sdk_root: Path | None = None

    def __post_init__(self) -> None:
        if self.sdk_root is None:
            sdks = discover_sdk_versions(self.install_root) if self.install_root else []
            self.sdk_root = sdks[0] if sdks else None

    def require_install_root(self) -> Path:
        if self.install_root is None or not (self.install_root / HOST_SUBDIR).is_dir():
            raise FileNotFoundError(
                "Nsight Graphics installation not found. Set "
                f"{NGFX_INSTALL_ROOT_ENV} or install Nsight Graphics under {NVIDIA_DEFAULT_ROOT}."
            )
        return self.install_root

    def require_tool(self, tool: str) -> Path:
        p = find_tool(tool, install_root=self.install_root)
        if p is None:
            env_var, exe_name = TOOL_DEFINITIONS[tool]
            raise FileNotFoundError(
                f"{exe_name} not found. Set {env_var}=<full path> or install Nsight Graphics."
            )
        return p

    def ensure_cache_dir(self) -> Path:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        return self.cache_dir

    def installation_info(self) -> dict[str, object]:
        roots = discover_install_roots()
        tools: dict[str, str | None] = {}
        for tool in TOOL_DEFINITIONS:
            p = find_tool(tool, install_root=self.install_root)
            tools[tool] = str(p) if p else None
        sdks = discover_sdk_versions(self.install_root) if self.install_root else []
        return {
            "install_root": str(self.install_root) if self.install_root else None,
            "all_install_roots": [str(p) for p in roots],
            "host_bin_dir": str(host_bin_dir(self.install_root)) if self.install_root else None,
            "sdk_root": str(self.sdk_root) if self.sdk_root else None,
            "all_sdk_versions": [str(p) for p in sdks],
            "tools": tools,
            "cache_dir": str(self.cache_dir),
            "captures_dir": str(self.captures_dir),
            "gputrace_dir": str(self.gputrace_dir),
        }


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reload_settings() -> Settings:
    global _settings
    _settings = Settings()
    return _settings
